package server

// The credential page (go-slides/go-slides.github.io#102): a user who must store
// their own token for a "user-token" forge types it into a page of THIS server,
// not into the playground page, so that no script of the playground page ever
// holds it.
//
//	GET  /api/git/credential/page?forge=<name>   the form (Store, Forget)
//	POST /api/git/credential/page                its submission
//
// The playground opens it with window.open(url, "_blank", "noopener"): the two
// documents share an origin, so isolation comes from what the page itself says:
//
//   - Cross-Origin-Opener-Policy: same-origin, and the opener gets no reference;
//   - a CSP with no script at all (default-src 'none', one nonce'd style),
//     form-action 'self', frame-ancestors 'none', base-uri 'none'; X-Frame-Options
//     DENY, no-store, no-referrer (same-origin on the form itself: see writePage):
//     the page cannot be framed, and runs nothing;
//   - it refuses to be fetched (Sec-Fetch-Mode other than navigate), so a script
//     cannot read its form token out of the HTML;
//   - the form carries its own token (formStore): random, bound to the subject,
//     the session, the forge and the action, single-use, five minutes, apart from
//     the JSON API's X-CSRF-Token, which the page never shows;
//   - the POST takes only application/x-www-form-urlencoded, the exact
//     configured Origin, the session cookie (SameSite=Strict) and that token.
//
// The token typed is stored by storeCredential, the JSON API's own path: same
// grant check, bounds and audit action. It is never in a response, never in a
// URL and never in the audit.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/go-browserhttp/browsergit/secret"
	"github.com/go-slides/gitd/internal/audit"
	"github.com/go-slides/gitd/internal/session"
	"github.com/go-slides/gitd/internal/vault"
)

const (
	// formTTL is how long a form token lives.
	formTTL = 5 * time.Minute
	// formsPerSubject and formsMax bound the tokens kept: a subject over its
	// bound loses its oldest.
	formsPerSubject = 16
	formsMax        = 20000
	// formBodyBytes bounds the submission: a token percent-encoded (3 bytes per
	// byte at worst) plus the fixed fields.
	formBodyBytes = 3*vault.MaxToken + 2048
)

type formToken struct {
	subject, session, forge, action string
	exp                             time.Time
}

type formStore struct {
	mu   sync.Mutex
	m    map[string]formToken
	mine map[string]int
}

func newFormStore() *formStore {
	return &formStore{m: map[string]formToken{}, mine: map[string]int{}}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("server: no randomness: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (f *formStore) dropLocked(k string) {
	if t, ok := f.m[k]; ok {
		delete(f.m, k)
		if f.mine[t.subject]--; f.mine[t.subject] <= 0 {
			delete(f.mine, t.subject)
		}
	}
}

// issue makes a token for one use.
func (f *formStore) issue(now time.Time, subject, sess, forgeN, action string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var oldest string
	for k, t := range f.m {
		switch {
		case now.After(t.exp):
			f.dropLocked(k)
		case t.subject == subject && (oldest == "" || t.exp.Before(f.m[oldest].exp)):
			oldest = k
		}
	}
	if f.mine[subject] >= formsPerSubject && oldest != "" {
		f.dropLocked(oldest)
	}
	for len(f.m) >= formsMax { // pathological: every subject at its bound
		for k := range f.m {
			f.dropLocked(k)
			break
		}
	}
	k := randomToken()
	f.m[k] = formToken{subject, sess, forgeN, action, now.Add(formTTL)}
	f.mine[subject]++
	return k
}

// take consumes a token, whatever it is then compared with: a token is good for
// one submission, right or wrong.
func (f *formStore) take(now time.Time, presented, subject, sess, forgeN, action string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.m[presented]
	if !ok || presented == "" {
		return false
	}
	f.dropLocked(presented)
	eq := func(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
	return !now.After(t.exp) && eq(t.subject, subject) && eq(t.session, sess) && eq(t.forge, forgeN) && eq(t.action, action)
}

// pageHeaders sets the page's own policy over headers() defaults and returns
// the nonce its one style carries.
func pageHeaders(w http.ResponseWriter) string {
	nonce := randomToken()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	return nonce
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style nonce="{{.Nonce}}">
body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem}
form{margin:1.5rem 0}input[type=password]{width:100%;box-sizing:border-box;padding:.4rem}
button{margin-top:.6rem;padding:.4rem 1rem}
</style></head><body>
<h1>{{.Title}}</h1>
{{if .Forms}}
<p>Your own token for <b>{{.Forge}}</b> is kept on the server, sealed, and is never shown again. This page is not the playground: nothing the playground runs can read what you type here.</p>
<form method="post" action="/api/git/credential/page" autocomplete="off">
<label>Token <input type="password" name="token" value="" autocomplete="new-password" required maxlength="4096"></label>
<input type="hidden" name="forge" value="{{.Forge}}"><input type="hidden" name="action" value="store"><input type="hidden" name="csrf" value="{{.Store}}">
<button type="submit">Store on the server</button></form>
<form method="post" action="/api/git/credential/page">
<input type="hidden" name="forge" value="{{.Forge}}"><input type="hidden" name="action" value="forget"><input type="hidden" name="csrf" value="{{.Forget}}">
<button type="submit">Forget my token on the server</button></form>
{{else}}<p>{{.Message}}</p>{{end}}
</body></html>
`))

type pageData struct {
	Title, Nonce, Forge, Store, Forget, Message string
	Forms                                       bool
}

func writePage(w http.ResponseWriter, code int, d pageData) {
	d.Nonce = pageHeaders(w)
	if d.Forms {
		// A form POST sent under "no-referrer" carries "Origin: null" in browsers
		// (Fetch: serializing a request origin), so the exact-Origin check below
		// could never pass. The form page links to nothing and loads nothing but
		// itself: "same-origin" gives nothing away and keeps the Origin.
		w.Header().Set("Referrer-Policy", "same-origin")
	}
	w.WriteHeader(code)
	_ = pageTmpl.Execute(w, d)
}

// notFound is the page's refusal for a forge that is unknown, not a user-token
// forge, or not granted to the subject: no body, so nothing tells them apart.
func notFound(w http.ResponseWriter) {
	pageHeaders(w)
	w.WriteHeader(http.StatusNotFound)
}

func (s *Server) userTokenForge(subject, forgeN string) bool {
	fc, ok := s.cfg.Forges[forgeN]
	return forgeName.MatchString(forgeN) && ok && fc.Auth == "user-token" && s.grantedOn(subject, forgeN)
}

// pageSession is the caller's session, made when there is none (a tab opened
// from a window whose cookie was lost).
func (s *Server) pageSession(w http.ResponseWriter, r *http.Request, subject string) *session.Session {
	if c, err := r.Cookie(CookieName); err == nil {
		if x, err := s.sessions.Get(c.Value, subject); err == nil {
			return x
		}
	}
	x := s.sessions.Create(subject)
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: x.ID, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return x
}

func (s *Server) handleCredentialPage(w http.ResponseWriter, r *http.Request) {
	subject, _, err := s.identity(r)
	if err != nil {
		pageHeaders(w)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// a document is navigated to; a script's fetch is not served the form
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" && m != "navigate" {
		notFound(w)
		return
	}
	forgeN := r.URL.Query().Get("forge")
	if !s.userTokenForge(subject, forgeN) {
		notFound(w)
		return
	}
	if !s.lim.allow(subject, s.now()) {
		w.Header().Set("Retry-After", "10")
		pageHeaders(w)
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	x := s.pageSession(w, r, subject)
	now := s.now()
	writePage(w, http.StatusOK, pageData{
		Title: "Your token for " + forgeN, Forms: true, Forge: forgeN,
		Store:  s.forms.issue(now, subject, x.ID, forgeN, "store"),
		Forget: s.forms.issue(now, subject, x.ID, forgeN, "forget"),
	})
}

func (s *Server) handleCredentialPageSubmit(w http.ResponseWriter, r *http.Request) {
	e := audit.Entry{Action: "credential-page", Remote: r.Header.Get("X-Forwarded-For")}
	defer func() {
		e.Time = s.now().UTC()
		s.audit.Write(e)
	}()
	refuse := func(code int, class, msg string) {
		e.Outcome = class
		writePage(w, code, pageData{Title: "Not done", Message: msg})
	}
	subject, _, err := s.identity(r)
	if err != nil {
		e.Outcome = "unauthenticated"
		pageHeaders(w)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	e.Subject = subject
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Header.Get("Origin") != s.cfg.Origin || mt != "application/x-www-form-urlencoded" {
		refuse(http.StatusForbidden, "csrf", "This form was not sent from the page. Open it again from the playground.")
		return
	}
	c, err := r.Cookie(CookieName)
	if err != nil {
		refuse(http.StatusForbidden, "no-session", "Your session ended. Open the page again from the playground.")
		return
	}
	x, err := s.sessions.Get(c.Value, subject)
	if err != nil {
		refuse(http.StatusForbidden, "session", "Your session ended. Open the page again from the playground.")
		return
	}
	if !s.lim.allow(subject, s.now()) {
		w.Header().Set("Retry-After", "10")
		e.Outcome = "rate-limited"
		pageHeaders(w)
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, formBodyBytes)
	if err := r.ParseForm(); err != nil {
		refuse(http.StatusBadRequest, "bad-request", "The form was not understood.")
		return
	}
	one := func(k string) string { // exactly one value, from the body alone
		if v := r.PostForm[k]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	forgeN, action := one("forge"), one("action")
	tok := secret.New(one("token"))
	delete(r.PostForm, "token")
	delete(r.Form, "token")
	defer tok.Forget()
	// the token is consumed here, right or wrong: one submission per form. It
	// was issued for one forge and one of two actions, so any other is refused.
	if !s.forms.take(s.now(), one("csrf"), subject, x.ID, forgeN, action) {
		refuse(http.StatusForbidden, "csrf", "This form expired or was already used. Open it again from the playground.")
		return
	}
	// the forge and the grant are checked again by storeCredential, as for the API
	var code int
	var class, msg string
	if action == "store" {
		e.Action = "credential"
		code, class = s.storeCredential(subject, forgeN, tok, &e)
		msg = fmt.Sprintf("Your token for %s is stored on the server. You can close this tab and go back to the playground.", forgeN)
	} else {
		e.Action = "credential-delete"
		code, class = s.forgetCredential(subject, forgeN, &e)
		msg = fmt.Sprintf("The server forgot your token for %s. You can close this tab.", forgeN)
	}
	if class != "" {
		refuse(code, class, "The server did not take it: the token is empty, or too long.")
		return
	}
	e.Outcome = "ok"
	writePage(w, http.StatusOK, pageData{Title: "Done", Message: msg})
}
