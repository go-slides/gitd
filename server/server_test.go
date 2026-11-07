package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-browserhttp/browsergit/remote"
	"github.com/go-browserhttp/browsergit/secret"
	"github.com/go-slides/gitd/internal/audit"
	"github.com/go-slides/gitd/internal/vault"
)

const (
	origin = "https://slides.example"
	tokA   = "ALICE-TOKEN-PLACEHOLDER-0001"
	tokB   = "BOB-TOKEN-PLACEHOLDER-0002"
)

// fakeRemote answers as the forge would, and says whose token it was built with.
type fakeRemote struct {
	owner  string
	prefix string
	block  chan struct{} // Propose waits on it (or on the context)
	got    *[]remote.Proposal
	mu     *sync.Mutex
}

func (f fakeRemote) Load(ctx context.Context, repo, ref, dir string) (remote.Files, remote.Base, error) {
	return remote.Files{"deck.md": []byte("# deck of " + repo + "\n"), "owner.txt": []byte(f.owner)},
		remote.Base{Forge: "gitlab", Repo: repo, Ref: "main", Commit: strings.Repeat("a", 40)}, nil
}

func (f fakeRemote) Propose(ctx context.Context, base remote.Base, files remote.Files, p remote.Proposal) (remote.Result, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return remote.Result{}, ctx.Err()
		}
	}
	if err := remote.RequirePrefix(p.Branch, f.prefix); err != nil {
		return remote.Result{}, err
	}
	f.mu.Lock()
	*f.got = append(*f.got, p)
	f.mu.Unlock()
	return remote.Result{Branch: p.Branch, Commit: strings.Repeat("b", 40), URL: "https://gitlab.example/g/p/-/merge_requests/1"}, nil
}

func (f fakeRemote) Refresh(ctx context.Context, base remote.Base) (remote.Files, remote.Base, error) {
	return nil, base, nil
}

type harness struct {
	t        *testing.T
	srv      *Server
	h        http.Handler
	log      *bytes.Buffer
	logMu    *sync.Mutex
	proposed []remote.Proposal
	mu       sync.Mutex
	block    chan struct{}
}

type lockedBuf struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (l lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	cfg, err := ParseConfig([]byte(`{
		"origin": "` + origin + `",
		"master_key_file": "unused", "data_dir": "unused", "audit_file": "unused",
		"rate_per_minute": 600, "burst": 50,
		"forges": {
			"gitlab": {"kind": "gitlab", "api": "https://gitlab.example/api/v4", "auth": "user-token"},
			"github": {"kind": "github", "api": "https://api.github.example", "auth": "github-app", "app_client_id": "Iv1.x", "installation_id": 1, "app_key_file": "unused"}
		},
		"users": {
			"alice": {"repos": ["gitlab:g/p"]},
			"bob":   {"slug": "bob", "repos": ["gitlab:g/p", "gitlab:g/q"]}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	v, _ := vault.Open(t.TempDir(), bytes.Repeat([]byte{3}, 32))
	hh := &harness{t: t, log: &bytes.Buffer{}, logMu: &sync.Mutex{}}
	hh.srv = New(cfg, v, audit.To(lockedBuf{hh.logMu, hh.log}), nil, secret.Token{})
	owners := map[string]string{tokA: "alice", tokB: "bob"}
	hh.srv.NewRemote = func(fc ForgeConfig, tok secret.Token, prefix string) (remote.Remote, error) {
		return fakeRemote{owner: owners[tok.Reveal()], prefix: prefix, block: hh.block, got: &hh.proposed, mu: &hh.mu}, nil
	}
	hh.h = hh.srv.Handler()
	_ = v.Put("alice", "gitlab", secret.New(tokA))
	_ = v.Put("bob", "gitlab", secret.New(tokB))
	return hh
}

type client struct {
	subject, cookie, csrf string
}

func (hh *harness) do(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	hh.h.ServeHTTP(w, r)
	return w
}

// login is the page fetching its session through Caddy and oauth2-proxy.
func (hh *harness) login(subject string) client {
	r := httptest.NewRequest("GET", "/api/git/session", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Auth-Request-User", subject)
	w := hh.do(r)
	if w.Code != 200 {
		hh.t.Fatalf("session for %s: %d %s", subject, w.Code, w.Body)
	}
	var out struct{ CSRF string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	var cookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName {
			cookie = c.Value
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
				hh.t.Fatalf("cookie flags: %+v", c)
			}
		}
	}
	return client{subject: subject, cookie: cookie, csrf: out.CSRF}
}

func (hh *harness) post(c client, path string, body any) *httptest.ResponseRecorder {
	return hh.postCtx(context.Background(), c, path, body)
}

func (hh *harness) postCtx(ctx context.Context, c client, path string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", path, bytes.NewReader(b)).WithContext(ctx)
	r.RemoteAddr = "127.0.0.1:40000"
	if c.subject != "" {
		r.Header.Set("X-Auth-Request-User", c.subject)
	}
	r.Header.Set("Origin", origin)
	r.Header.Set("X-Requested-With", "slides-gitd")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", c.csrf)
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: CookieName, Value: c.cookie})
	}
	return hh.do(r)
}

func owner(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var out loadRsp
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("load response: %d %s", w.Code, w.Body)
	}
	return string(out.Files["owner.txt"])
}

var loadP = loadReq{Forge: "gitlab", Repo: "g/p"}

func TestEachUserGetsTheirOwnCredential(t *testing.T) {
	hh := newHarness(t)
	a, b := hh.login("alice"), hh.login("bob")
	if got := owner(t, hh.post(a, "/api/git/load", loadP)); got != "alice" {
		t.Fatalf("alice's load used %q's token", got)
	}
	if got := owner(t, hh.post(b, "/api/git/load", loadP)); got != "bob" {
		t.Fatalf("bob's load used %q's token", got)
	}
}

func TestUserACanNeverUseUserBsSession(t *testing.T) {
	hh := newHarness(t)
	a, b := hh.login("alice"), hh.login("bob")
	cases := map[string]client{
		"cookie swap: alice with bob's cookie and csrf": {subject: "alice", cookie: b.cookie, csrf: b.csrf},
		"alice's cookie, bob's csrf":                    {subject: "alice", cookie: a.cookie, csrf: b.csrf},
		"guessed id":                                    {subject: "alice", cookie: strings.Repeat("A", 43), csrf: a.csrf},
		"no cookie":                                     {subject: "alice", csrf: a.csrf},
		"no csrf":                                       {subject: "alice", cookie: a.cookie},
	}
	for name, c := range cases {
		if w := hh.post(c, "/api/git/load", loadP); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	// The cookie presented by the wrong person is dead for its owner too.
	if w := hh.post(b, "/api/git/load", loadP); w.Code != http.StatusForbidden {
		t.Fatalf("bob's session must have been destroyed when alice presented it: %d", w.Code)
	}
	// Session fixation: a cookie the server never issued is replaced, not adopted.
	r := httptest.NewRequest("GET", "/api/git/session", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Auth-Request-User", "alice")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "attacker-chosen"})
	w := hh.do(r)
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName && c.Value == "attacker-chosen" {
			t.Fatal("a client-chosen session id was adopted")
		}
	}
	// And the IdP changing who is behind the browser (bob signs in where
	// alice was): alice's cookie does not carry over.
	b2 := hh.login("bob")
	if w := hh.post(client{subject: "bob", cookie: a.cookie, csrf: a.csrf}, "/api/git/load", loadP); w.Code != http.StatusForbidden {
		t.Fatalf("a new identity with the old cookie: %d", w.Code)
	}
	if got := owner(t, hh.post(b2, "/api/git/load", loadP)); got != "bob" {
		t.Fatal(got)
	}
}

func TestConcurrentUsersNeverCross(t *testing.T) {
	hh := newHarness(t)
	hh.srv.lim = newLimiter(100000, 1000) // this test is about isolation, not the limit
	users := []client{hh.login("alice"), hh.login("bob")}
	var wg sync.WaitGroup
	var bad sync.Map
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := users[i%2]
			w := hh.post(c, "/api/git/load", loadP)
			var out loadRsp
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			if string(out.Files["owner.txt"]) != c.subject {
				bad.Store(i, fmt.Sprintf("%s got %q (%d)", c.subject, out.Files["owner.txt"], w.Code))
			}
		}(i)
	}
	wg.Wait()
	bad.Range(func(k, v any) bool { t.Error(v); return true })
}

func TestDenyByDefault(t *testing.T) {
	hh := newHarness(t)
	a, carol := hh.login("alice"), hh.login("carol")
	for name, q := range map[string]struct {
		c client
		r loadReq
	}{
		"unknown user":       {carol, loadP},
		"repo not granted":   {a, loadReq{Forge: "gitlab", Repo: "g/q"}},
		"unknown forge":      {a, loadReq{Forge: "gitea", Repo: "g/p"}},
		"granted on another": {a, loadReq{Forge: "github", Repo: "g/p"}},
	} {
		if w := hh.post(q.c, "/api/git/load", q.r); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
}

func TestIdentityMustComeFromTheProxy(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	b, _ := json.Marshal(loadP)
	mk := func() *http.Request {
		r := httptest.NewRequest("POST", "/api/git/load", bytes.NewReader(b))
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set("X-Auth-Request-User", "alice")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Requested-With", "slides-gitd")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", a.csrf)
		r.AddCookie(&http.Cookie{Name: CookieName, Value: a.cookie})
		return r
	}
	checks := map[string]func(*http.Request){
		"not from the proxy":            func(r *http.Request) { r.RemoteAddr = "203.0.113.9:1" },
		"expired IdP session (no user)": func(r *http.Request) { r.Header.Del("X-Auth-Request-User") },
		"control character in subject":  func(r *http.Request) { r.Header.Set("X-Auth-Request-User", "alice\x00") },
	}
	for name, mod := range checks {
		r := mk()
		mod(r)
		if w := hh.do(r); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	csrf := map[string]func(*http.Request){
		"another origin":      func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"no origin":           func(r *http.Request) { r.Header.Del("Origin") },
		"no X-Requested-With": func(r *http.Request) { r.Header.Del("X-Requested-With") },
		"a form post":         func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
	}
	for name, mod := range csrf {
		r := mk()
		mod(r)
		if w := hh.do(r); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if w := hh.do(mk()); w.Code != 200 {
		t.Fatalf("control: the unmodified request must pass: %d %s", w.Code, w.Body)
	}
	// With a proxy secret configured, a request without it is not from Caddy.
	hh.srv.proxySecret = secret.New("PROXY-SECRET-PLACEHOLDER")
	if w := hh.do(mk()); w.Code != http.StatusUnauthorized {
		t.Fatal("the proxy secret must be required")
	}
	r := mk()
	r.Header.Set("X-Gitd-Proxy-Secret", "PROXY-SECRET-PLACEHOLDER")
	if w := hh.do(r); w.Code != 200 {
		t.Fatal("with the proxy secret")
	}
	// A GET on a mutating path is not routed.
	g := httptest.NewRequest("GET", "/api/git/load", nil)
	g.RemoteAddr = "127.0.0.1:1"
	if w := hh.do(g); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on load: %d", w.Code)
	}
}

func TestWritesOnlyToTheUsersOwnBranches(t *testing.T) {
	hh := newHarness(t)
	b := hh.login("bob")
	base := remote.Base{Forge: "gitlab", Repo: "g/p", Ref: "main", Commit: strings.Repeat("a", 40)}
	w := hh.post(b, "/api/git/propose", proposeReq{Forge: "gitlab", Base: base, Files: remote.Files{"deck.md": []byte("x")}, Title: "Fix the intro"})
	if w.Code != 200 || len(hh.proposed) != 1 || !strings.HasPrefix(hh.proposed[0].Branch, "slides/bob/fix-the-intro-") {
		t.Fatalf("propose: %d %s %+v", w.Code, w.Body, hh.proposed)
	}
	if !strings.Contains(hh.proposed[0].Body, "Proposed by bob") {
		t.Fatal("the proposal names its author")
	}
	// The client cannot name a branch: the field does not exist.
	raw := map[string]any{"forge": "gitlab", "base": base, "files": map[string]string{}, "title": "t", "branch": "main"}
	if w := hh.post(b, "/api/git/propose", raw); w.Code != http.StatusBadRequest {
		t.Fatalf("a client-chosen branch: %d", w.Code)
	}
	// Alice's slug is derived; it cannot be bob's.
	a := hh.login("alice")
	_ = hh.post(a, "/api/git/propose", proposeReq{Forge: "gitlab", Base: base, Files: remote.Files{"deck.md": []byte("y")}, Title: "x"})
	if !strings.HasPrefix(hh.proposed[1].Branch, "slides/alice/") {
		t.Fatalf("alice's branch %q", hh.proposed[1].Branch)
	}
	if hh.srv.slug("../Évil User!") != "evil-user" && hh.srv.slug("../Évil User!") == "" {
		t.Fatal("slug")
	}
}

func TestCredentialsAndAudit(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	w := hh.post(a, "/api/git/credential", credentialReq{Forge: "gitlab", Token: "NEW-ALICE-TOKEN-PLACEHOLDER"})
	if w.Code != 200 || strings.Contains(w.Body.String(), "NEW-ALICE") {
		t.Fatalf("credential: %d %s", w.Code, w.Body)
	}
	if w := hh.post(a, "/api/git/credential", credentialReq{Forge: "github", Token: "x"}); w.Code != http.StatusBadRequest {
		t.Fatal("a github-app forge takes no user token")
	}
	if w := hh.post(a, "/api/git/credential/delete", map[string]string{"forge": "gitlab"}); w.Code != 200 {
		t.Fatal("delete")
	}
	if w := hh.post(a, "/api/git/load", loadP); w.Code != http.StatusPreconditionRequired {
		t.Fatalf("no credential: %d", w.Code)
	}
	hh.logMu.Lock()
	log := hh.log.String()
	hh.logMu.Unlock()
	for _, leak := range []string{tokA, tokB, "NEW-ALICE", "deck of", a.csrf, a.cookie} {
		if strings.Contains(log, leak) {
			t.Fatalf("the audit log carries %q", leak)
		}
	}
	if !strings.Contains(log, `"action":"credential"`) || !strings.Contains(log, `"subject":"alice"`) || !strings.Contains(log, `"outcome":"no-credential"`) {
		t.Fatalf("control: the audit must record the actions:\n%s", log)
	}
}

func TestRateLimitAndBodyBound(t *testing.T) {
	hh := newHarness(t)
	hh.srv.lim = newLimiter(1, 2)
	a := hh.login("alice")
	codes := []int{}
	for i := 0; i < 4; i++ {
		codes = append(codes, hh.post(a, "/api/git/load", loadP).Code)
	}
	if codes[0] != 200 || codes[3] != http.StatusTooManyRequests {
		t.Fatalf("codes %v", codes)
	}
	hh.srv.lim = newLimiter(600, 50)
	hh.srv.cfg.MaxBodyBytes = 64
	if w := hh.post(a, "/api/git/load", map[string]string{"forge": strings.Repeat("x", 200)}); w.Code != http.StatusBadRequest {
		t.Fatalf("an oversized body: %d", w.Code)
	}
}

// Chaos: the client goes away in the middle of a push.
func TestAKilledProposalLeavesNothingBehind(t *testing.T) {
	hh := newHarness(t)
	hh.block = make(chan struct{})
	b := hh.login("bob")
	base := remote.Base{Forge: "gitlab", Repo: "g/p", Ref: "main", Commit: strings.Repeat("a", 40)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *httptest.ResponseRecorder)
	go func() {
		done <- hh.postCtx(ctx, b, "/api/git/propose", proposeReq{Forge: "gitlab", Base: base, Files: remote.Files{"deck.md": []byte("x")}, Title: "t"})
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case w := <-done:
		if w.Code != 499 || len(hh.proposed) != 0 {
			t.Fatalf("a canceled proposal: %d, %d proposals", w.Code, len(hh.proposed))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not stop when its client went away")
	}
	hh.logMu.Lock()
	if !strings.Contains(hh.log.String(), `"outcome":"canceled"`) {
		t.Fatal("the audit must record the cancellation")
	}
	hh.logMu.Unlock()
	close(hh.block)
	if w := hh.post(b, "/api/git/propose", proposeReq{Forge: "gitlab", Base: base, Files: remote.Files{"deck.md": []byte("x")}, Title: "t"}); w.Code != 200 {
		t.Fatalf("after the kill, the next proposal works: %d", w.Code)
	}
}

func TestResponsesAreNotCacheableOrFramable(t *testing.T) {
	hh := newHarness(t)
	r := httptest.NewRequest("GET", "/healthz", nil)
	w := hh.do(r)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal(w.Header())
	}
	_ = hh.srv.String()
}

func FuzzMutatingBodies(f *testing.F) {
	f.Add("/api/git/load", `{"forge":"gitlab","repo":"g/p"}`)
	f.Add("/api/git/propose", `{"forge":"gitlab","base":{"repo":"g/p","ref":"main","commit":"`+strings.Repeat("a", 40)+`"},"files":{"deck.md":"eA=="},"title":"t"}`)
	f.Add("/api/git/refresh", `{"forge":"gitlab","base":{"repo":"g/p"}}`)
	f.Add("/api/git/credential", `{"forge":"gitlab","token":"x"}`)
	hh := newHarness(&testing.T{})
	a := hh.login("alice")
	f.Fuzz(func(t *testing.T, path, body string) {
		switch path {
		case "/api/git/load", "/api/git/propose", "/api/git/refresh", "/api/git/credential", "/api/git/credential/delete":
		default:
			return
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set("X-Auth-Request-User", "alice")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Requested-With", "slides-gitd")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", a.csrf)
		r.AddCookie(&http.Cookie{Name: CookieName, Value: a.cookie})
		w := httptest.NewRecorder()
		hh.h.ServeHTTP(w, r)
		if w.Code == 500 {
			t.Fatalf("500 for %s %q: %s", path, body, w.Body)
		}
		_, _ = io.Copy(io.Discard, w.Body)
	})
}
