package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

const pageTok = "ALICE-PAGE-TOKEN-PLACEHOLDER-0003"

var hiddenRe = regexp.MustCompile(`name="action" value="(store|forget)"><input type="hidden" name="csrf" value="([^"]+)"`)

// getPage is a tab navigating to the credential page.
func (hh *harness) getPage(c client, subject, forgeN string, extra map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/api/git/credential/page?forge="+url.QueryEscape(forgeN), nil)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Auth-Request-User", subject)
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: CookieName, Value: c.cookie})
	}
	for k, v := range extra {
		r.Header.Set(k, v)
	}
	return hh.do(r)
}

// formTokens reads the page's two form tokens.
func formTokens(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range hiddenRe.FindAllStringSubmatch(w.Body.String(), -1) {
		out[m[1]] = m[2]
	}
	if len(out) != 2 {
		t.Fatalf("the page carries %d form tokens: %d %s", len(out), w.Code, w.Body)
	}
	return out
}

// submit is the browser posting the form.
func (hh *harness) submit(c client, subject string, form url.Values, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/git/credential/page", strings.NewReader(form.Encode()))
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Auth-Request-User", subject)
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: CookieName, Value: c.cookie})
	}
	if mod != nil {
		mod(r)
	}
	return hh.do(r)
}

func storeForm(forgeN, csrf, token string) url.Values {
	return url.Values{"forge": {forgeN}, "action": {"store"}, "csrf": {csrf}, "token": {token}}
}

func (hh *harness) loadStatus(c client) int { return hh.post(c, "/api/git/load", loadP).Code }

func TestPageHeaders(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	w := hh.getPage(a, "alice", "gitlab", nil)
	if w.Code != 200 {
		t.Fatalf("page: %d", w.Code)
	}
	check := func(what string, w *httptest.ResponseRecorder) {
		t.Helper()
		h := w.Header()
		if h.Get("Cross-Origin-Opener-Policy") != "same-origin" {
			t.Errorf("%s: COOP %q", what, h.Get("Cross-Origin-Opener-Policy"))
		}
		csp := h.Get("Content-Security-Policy")
		m := regexp.MustCompile(`^default-src 'none'; style-src 'nonce-([A-Za-z0-9_-]{40,})'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'$`).FindStringSubmatch(csp)
		if m == nil {
			t.Fatalf("%s: CSP %q", what, csp)
		}
		if strings.Contains(csp, "script-src") || strings.Contains(csp, "unsafe") {
			t.Errorf("%s: the page allows script or unsafe: %q", what, csp)
		}
		if !strings.Contains(w.Body.String(), `<style nonce="`+m[1]+`">`) {
			t.Errorf("%s: the style does not carry the policy's nonce", what)
		}
		if strings.Contains(strings.ToLower(w.Body.String()), "<script") {
			t.Errorf("%s: the page has a script", what)
		}
		for k, v := range map[string]string{"X-Frame-Options": "DENY", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"} {
			if h.Get(k) != v {
				t.Errorf("%s: %s is %q, want %q", what, k, h.Get(k), v)
			}
		}
		if !strings.HasPrefix(h.Get("Content-Type"), "text/html") {
			t.Errorf("%s: content type %q", what, h.Get("Content-Type"))
		}
	}
	check("the form", w)
	// the nonce is fresh for every response
	if w2 := hh.getPage(a, "alice", "gitlab", nil); w2.Header().Get("Content-Security-Policy") == w.Header().Get("Content-Security-Policy") {
		t.Error("the nonce is reused")
	}
	// the field is a masked one and is not prefilled
	body := w.Body.String()
	if !strings.Contains(body, `type="password" name="token" value=""`) {
		t.Errorf("the token field is not an empty password field: %s", body)
	}
	tk := formTokens(t, w)
	check("the result", hh.submit(a, "alice", storeForm("gitlab", tk["store"], pageTok), nil))
	check("a refusal", hh.submit(a, "alice", storeForm("gitlab", "wrong", pageTok), nil))
	// even a 404 carries the isolating headers
	nf := hh.getPage(a, "alice", "nope", nil)
	if nf.Header().Get("Cross-Origin-Opener-Policy") != "same-origin" || nf.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("the 404 lacks the page's headers")
	}
}

func TestPageUngrantedIs404WithNoDetail(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	m := hh.login("mallory") // known to oauth2-proxy, granted nothing
	for i, tc := range []struct {
		c       client
		subject string
		forge   string
	}{{m, "mallory", "gitlab"}, {a, "alice", "nope"}, {a, "alice", "github"}, {a, "alice", ""}, {a, "alice", "../x"}} {
		w := hh.getPage(tc.c, tc.subject, tc.forge, nil)
		if w.Code != 404 || w.Body.Len() != 0 {
			t.Errorf("case %d: %d %q", i, w.Code, w.Body)
		}
	}
	if w := hh.getPage(client{}, "", "gitlab", nil); w.Code != 401 {
		t.Errorf("no identity: %d", w.Code)
	}
	// a script's fetch is not served the form
	if w := hh.getPage(a, "alice", "gitlab", map[string]string{"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}); w.Code != 404 || w.Body.Len() != 0 {
		t.Errorf("a fetch got the form: %d", w.Code)
	}
	if w := hh.getPage(a, "alice", "gitlab", map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}); w.Code != 200 {
		t.Errorf("a navigation was refused: %d", w.Code)
	}
	// nobody ungranted can store through the form either
	tk := formTokens(t, hh.getPage(a, "alice", "gitlab", nil))
	mc := hh.login("mallory")
	if w := hh.submit(mc, "mallory", storeForm("gitlab", tk["store"], "MALLORY"), nil); w.Code != 403 {
		t.Errorf("another subject used alice's form: %d", w.Code)
	}
	if _, err := hh.srv.vault.Get("mallory", "gitlab"); err == nil {
		t.Error("an ungranted subject stored a credential")
	}
}

func TestPageStoreThenUse(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	if err := hh.srv.vault.Delete("alice", "gitlab"); err != nil {
		t.Fatal(err)
	}
	if got := hh.loadStatus(a); got != http.StatusPreconditionRequired {
		t.Fatalf("before: %d, want 428", got)
	}
	tk := formTokens(t, hh.getPage(a, "alice", "gitlab", nil))
	w := hh.submit(a, "alice", storeForm("gitlab", tk["store"], tokA), nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "stored") {
		t.Fatalf("store: %d %s", w.Code, w.Body)
	}
	if got := hh.loadStatus(a); got != 200 {
		t.Fatalf("after storing: %d", got)
	}
	// the stored token is alice's: the fake forge says whose it was
	r := hh.post(a, "/api/git/load", loadP)
	if !strings.Contains(r.Body.String(), "owner.txt") {
		t.Fatalf("load: %s", r.Body)
	}

	// Forget goes the same way
	tk = formTokens(t, hh.getPage(a, "alice", "gitlab", nil))
	w = hh.submit(a, "alice", url.Values{"forge": {"gitlab"}, "action": {"forget"}, "csrf": {tk["forget"]}}, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "forgot") {
		t.Fatalf("forget: %d %s", w.Code, w.Body)
	}
	if got := hh.loadStatus(a); got != http.StatusPreconditionRequired {
		t.Fatalf("after forgetting: %d, want 428", got)
	}
}

func TestPageFormTokenRules(t *testing.T) {
	hh := newHarness(t)
	hh.srv.lim = newLimiter(6000, 6000)
	a := hh.login("alice")
	fresh := func() map[string]string { return formTokens(t, hh.getPage(a, "alice", "gitlab", nil)) }
	deny := func(what string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != 403 {
			t.Errorf("%s: %d %s", what, w.Code, w.Body)
		}
	}
	// missing
	deny("missing", hh.submit(a, "alice", url.Values{"forge": {"gitlab"}, "action": {"store"}, "token": {pageTok}}, nil))
	deny("empty", hh.submit(a, "alice", storeForm("gitlab", "", pageTok), nil))
	deny("invented", hh.submit(a, "alice", storeForm("gitlab", "AAAA", pageTok), nil))
	// the JSON API's CSRF token is not the form's
	deny("the API's token", hh.submit(a, "alice", storeForm("gitlab", a.csrf, pageTok), nil))
	// reused
	tk := fresh()
	if w := hh.submit(a, "alice", storeForm("gitlab", tk["store"], tokA), nil); w.Code != 200 {
		t.Fatalf("first use: %d %s", w.Code, w.Body)
	}
	deny("reused", hh.submit(a, "alice", storeForm("gitlab", tk["store"], tokA), nil))
	// consumed even when it was refused for something else
	tk = fresh()
	deny("wrong origin", hh.submit(a, "alice", storeForm("gitlab", tk["store"], tokA), func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }))
	if w := hh.submit(a, "alice", storeForm("gitlab", tk["store"], tokA), nil); w.Code != 200 {
		t.Errorf("a refused origin must not burn the token: %d", w.Code) // the origin is checked before the token is looked at
	}
	// bound to its action
	tk = fresh()
	deny("store token used to forget", hh.submit(a, "alice", url.Values{"forge": {"gitlab"}, "action": {"forget"}, "csrf": {tk["store"]}}, nil))
	// bound to its session
	tk = fresh()
	a2 := hh.login("alice") // another session of alice's
	deny("another session", hh.submit(a2, "alice", storeForm("gitlab", tk["store"], tokA), nil))
	// bound to its subject
	tk = formTokens(t, hh.getPage(a, "alice", "gitlab", nil))
	b := hh.login("bob")
	deny("another subject", hh.submit(b, "bob", storeForm("gitlab", tk["store"], tokB), nil))
	// bound to its forge
	tk = fresh()
	deny("another forge", hh.submit(a, "alice", storeForm("github", tk["store"], tokA), nil))
	// expired
	tk = fresh()
	now := time.Now()
	hh.srv.Now = func() time.Time { return now.Add(formTTL + time.Second) }
	deny("expired", hh.submit(a, "alice", storeForm("gitlab", tk["store"], tokA), nil))
	hh.srv.Now = nil
	hh.srv.lim = newLimiter(6000, 6000) // its clock went back
	// the same value twice in the body is not one value
	tk = fresh()
	deny("two csrf fields", hh.submit(a, "alice", url.Values{"forge": {"gitlab"}, "action": {"store"}, "csrf": {"x", tk["store"]}, "token": {tokA}}, nil))
	// the token in the query string is ignored
	tk = fresh()
	deny("csrf in the URL", hh.submit(a, "alice", url.Values{"forge": {"gitlab"}, "action": {"store"}, "token": {tokA}}, func(r *http.Request) { r.URL.RawQuery = "csrf=" + tk["store"] }))
}

func TestPageOriginAndContentType(t *testing.T) {
	hh := newHarness(t)
	hh.srv.lim = newLimiter(6000, 6000)
	a := hh.login("alice")
	cases := map[string]func(*http.Request){
		"no Origin":        func(r *http.Request) { r.Header.Del("Origin") },
		"cross-origin":     func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"a prefix of ours": func(r *http.Request) { r.Header.Set("Origin", origin+".evil.example") },
		"null Origin":      func(r *http.Request) { r.Header.Set("Origin", "null") },
		"JSON":             func(r *http.Request) { r.Header.Set("Content-Type", "application/json") },
		"multipart":        func(r *http.Request) { r.Header.Set("Content-Type", "multipart/form-data; boundary=x") },
		"text/plain":       func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		"no cookie":        func(r *http.Request) { r.Header.Del("Cookie") },
		"no identity":      func(r *http.Request) { r.Header.Del("X-Auth-Request-User") },
		"untrusted proxy":  func(r *http.Request) { r.RemoteAddr = "203.0.113.9:1" },
		"another's cookie": func(r *http.Request) { r.Header.Set("Cookie", CookieName+"="+hh.login("bob").cookie) },
		"not a session":    func(r *http.Request) { r.Header.Set("Cookie", CookieName+"=nope") },
	}
	for name, mod := range cases {
		tk := formTokens(t, hh.getPage(a, "alice", "gitlab", nil))
		w := hh.submit(a, "alice", storeForm("gitlab", tk["store"], pageTok), mod)
		if w.Code != 403 && w.Code != 401 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		if v, err := hh.srv.vault.Get("alice", "gitlab"); err == nil && v.Reveal() == pageTok {
			t.Errorf("%s: the credential was stored", name)
		}
	}
	// an oversized body is refused before anything is stored
	tk := formTokens(t, hh.getPage(a, "alice", "gitlab", nil))
	if w := hh.submit(a, "alice", storeForm("gitlab", tk["store"], strings.Repeat("x", 1<<20)), nil); w.Code == 200 {
		t.Errorf("a 1 MiB token was accepted")
	}
	// a token over the vault's bound
	tk = formTokens(t, hh.getPage(a, "alice", "gitlab", nil))
	if w := hh.submit(a, "alice", storeForm("gitlab", tk["store"], strings.Repeat("x", 4097)), nil); w.Code != 400 {
		t.Errorf("a token over the bound: %d", w.Code)
	}
	// an empty one
	tk = formTokens(t, hh.getPage(a, "alice", "gitlab", nil))
	if w := hh.submit(a, "alice", storeForm("gitlab", tk["store"], ""), nil); w.Code != 400 {
		t.Errorf("an empty token: %d", w.Code)
	}
}

func TestPageGrantIsCheckedAgainAtSubmission(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	tk := formTokens(t, hh.getPage(a, "alice", "gitlab", nil))
	if err := hh.srv.vault.Delete("alice", "gitlab"); err != nil {
		t.Fatal(err)
	}
	hh.srv.cfg.Users["alice"] = User{} // the administrator revoked the grant
	w := hh.submit(a, "alice", storeForm("gitlab", tk["store"], pageTok), nil)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "is stored") {
		t.Fatalf("a revoked grant stored a credential: %d %s", w.Code, w.Body)
	}
	if _, err := hh.srv.vault.Get("alice", "gitlab"); err == nil {
		t.Fatal("the credential is in the vault")
	}
	hh.logMu.Lock()
	log := hh.log.String()
	hh.logMu.Unlock()
	if !strings.Contains(log, `"outcome":"denied"`) {
		t.Fatalf("the audit must say denied:\n%s", log)
	}
}

func TestPageNeverEchoesTheTokenNorLogsIt(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	var bodies, heads []string
	keep := func(w *httptest.ResponseRecorder) {
		bodies = append(bodies, w.Body.String())
		for k, v := range w.Result().Header {
			heads = append(heads, k+": "+strings.Join(v, ","))
		}
	}
	tk := formTokens(t, hh.getPage(a, "alice", "gitlab", nil))
	for _, w := range []*httptest.ResponseRecorder{
		hh.submit(a, "alice", storeForm("gitlab", tk["store"], pageTok), nil),
		hh.submit(a, "alice", storeForm("gitlab", "wrong", pageTok), nil), // refused
		hh.submit(a, "alice", storeForm("gitlab", "wrong", pageTok), func(r *http.Request) { r.Header.Set("Origin", "x") }),
		hh.submit(a, "alice", storeForm("gitlab", tk["store"], pageTok), nil), // reused
		hh.getPage(a, "alice", "gitlab", nil),
	} {
		keep(w)
	}
	all := strings.Join(bodies, "\n") + strings.Join(heads, "\n")
	if strings.Contains(all, pageTok) || strings.Contains(all, "PAGE-TOKEN") {
		t.Fatalf("a response carries the token")
	}
	if v, err := hh.srv.vault.Get("alice", "gitlab"); err != nil || v.Reveal() != pageTok {
		t.Fatalf("control: the token was not stored")
	}
	hh.logMu.Lock()
	log := hh.log.String()
	hh.logMu.Unlock()
	for _, leak := range []string{pageTok, "PAGE-TOKEN", tk["store"], tk["forget"], a.csrf, a.cookie} {
		if strings.Contains(log, leak) {
			t.Fatalf("the audit log carries %q:\n%s", leak, log)
		}
	}
	// control: the audit records the store, as the API's own action
	if !strings.Contains(log, `"action":"credential"`) || !strings.Contains(log, `"outcome":"ok"`) || !strings.Contains(log, `"outcome":"csrf"`) {
		t.Fatalf("control: the audit must record the actions:\n%s", log)
	}
}

func TestPageFormStoreIsBounded(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	for i := 0; i < 3*formsPerSubject; i++ {
		hh.srv.lim = newLimiter(6000, 6000)
		hh.getPage(a, "alice", "gitlab", nil)
	}
	hh.srv.forms.mu.Lock()
	n := len(hh.srv.forms.m)
	hh.srv.forms.mu.Unlock()
	if n > formsPerSubject {
		t.Fatalf("%d form tokens kept for one subject, bound %d", n, formsPerSubject)
	}
}
