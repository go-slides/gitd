package gitdtest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

const alice, bob = "sub-alice", "sub-bob"

// asUser is a browser behind oauth2-proxy: the proxy sets the identity.
type asUser struct {
	t       *testing.T
	base    string
	subject string
	hc      *http.Client
	csrf    string
}

type identity struct {
	subject string
	next    http.RoundTripper
}

func (i identity) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Auth-Request-User", i.subject)
	return i.next.RoundTrip(r)
}

func newEnv(t *testing.T) (*Env, string) {
	t.Helper()
	var srvURL string
	var env *Env
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { env.Handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	srvURL = srv.URL
	env, err := New(Options{
		Origin: srvURL, Dir: t.TempDir(),
		Users: []User{
			{Subject: alice, Slug: "alice", Repos: []string{"lab/alpha", "lab/beta"}, Token: "ALICE-TOKEN-PLACEHOLDER"},
			{Subject: bob, Repos: []string{"lab/beta"}, Token: "BOB-TOKEN-PLACEHOLDER"},
		},
		Repos: []Repo{
			{Name: "lab/alpha", Token: "ALICE-TOKEN-PLACEHOLDER", Files: map[string]string{"talk/deck.md": "# Alpha\n", "talk/a.txt": "a"}},
			{Name: "lab/beta", Token: "BOB-TOKEN-PLACEHOLDER", Files: map[string]string{"deck.md": "# Beta\n"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return env, srvURL
}

func (e *Env) user(t *testing.T, base, subject string) *asUser {
	jar, _ := cookiejar.New(nil)
	u := &asUser{t: t, base: base, subject: subject, hc: &http.Client{Jar: jar, Transport: identity{subject, http.DefaultTransport}}}
	rsp, err := u.hc.Get(base + "/api/git/session")
	if err != nil {
		t.Fatal(err)
	}
	defer rsp.Body.Close()
	var s struct {
		CSRF  string   `json:"csrf"`
		Repos []string `json:"repos"`
	}
	_ = json.NewDecoder(rsp.Body).Decode(&s)
	u.csrf = s.CSRF
	return u
}

func (u *asUser) post(path string, body any) (int, map[string]any) {
	b, _ := json.Marshal(body)
	r, _ := http.NewRequest("POST", u.base+path, bytes.NewReader(b))
	r.Header.Set("Origin", u.base)
	r.Header.Set("X-Requested-With", "slides-gitd")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", u.csrf)
	rsp, err := u.hc.Do(r)
	if err != nil {
		u.t.Fatal(err)
	}
	defer rsp.Body.Close()
	data, _ := io.ReadAll(rsp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return rsp.StatusCode, out
}

func TestEachUserSeesOnlyTheirRepositoriesAndUsesOnlyTheirToken(t *testing.T) {
	env, base := newEnv(t)
	a, b := env.user(t, base, alice), env.user(t, base, bob)

	if code, out := a.post("/api/git/load", map[string]string{"forge": Forge, "repo": "lab/alpha", "dir": "talk"}); code != 200 || out["files"] == nil {
		t.Fatalf("alice loads her repository: %d %v", code, out)
	}
	// bob is not granted alpha: denied before any forge is asked
	if code, out := b.post("/api/git/load", map[string]string{"forge": Forge, "repo": "lab/alpha"}); code != 403 || out["error"] != "denied" {
		t.Fatalf("bob on alpha: %d %v", code, out)
	}
	// alice is granted beta but her vault token is not beta's: the forge says not found
	if code, out := a.post("/api/git/load", map[string]string{"forge": Forge, "repo": "lab/beta"}); code != 404 || out["error"] != "not-found" {
		t.Fatalf("alice on beta with her own token: %d %v", code, out)
	}
	if code, _ := b.post("/api/git/load", map[string]string{"forge": Forge, "repo": "lab/beta"}); code != 200 {
		t.Fatalf("bob loads beta: %d", code)
	}
}

func TestProposeAndRefresh(t *testing.T) {
	env, base := newEnv(t)
	a := env.user(t, base, alice)
	_, ld := a.post("/api/git/load", map[string]string{"forge": Forge, "repo": "lab/alpha", "dir": "talk"})
	baseObj := ld["base"]
	code, out := a.post("/api/git/propose", map[string]any{"forge": Forge, "base": baseObj, "files": map[string]string{"deck.md": "IyBOZXcK"}, "title": "New"})
	if code != 200 || !strings.HasPrefix(out["branch"].(string), "slides/alice-") {
		t.Fatalf("propose: %d %v", code, out)
	}
	ps := env.Proposals()
	if len(ps) != 1 || ps[0].Token != "ALICE-TOKEN-PLACEHOLDER" || ps[0].Repo != "lab/alpha" || len(ps[0].Files) != 1 {
		t.Fatalf("proposals %+v", ps)
	}
	if code, out := a.post("/api/git/refresh", map[string]any{"forge": Forge, "base": baseObj}); code != 200 || out["files"] != nil {
		t.Fatalf("refresh with nothing new: %d %v", code, out)
	}
	if !env.Advance("lab/alpha", map[string]string{"talk/deck.md": "# Alpha 2\n"}) || env.Advance("nope", nil) {
		t.Fatal("Advance")
	}
	if code, out := a.post("/api/git/refresh", map[string]any{"forge": Forge, "base": baseObj}); code != 200 || out["files"] == nil {
		t.Fatalf("refresh after a colleague's push: %d %v", code, out)
	}
	if !strings.Contains(env.Audit(), `"action":"propose"`) {
		t.Fatalf("audit: %s", env.Audit())
	}
}

func TestBadOptions(t *testing.T) {
	if _, err := New(Options{Origin: "http://x", Dir: "/does/not/exist", Users: []User{{Subject: "u", Repos: []string{"a/b"}}}}); err == nil {
		t.Fatal("a missing vault directory")
	}
	if _, err := New(Options{Origin: "", Dir: t.TempDir()}); err == nil {
		t.Fatal("no origin")
	}
}
