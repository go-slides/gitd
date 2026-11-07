// Package server is slides-gitd's HTTP API: the playground's git operations,
// run on the server with credentials the browser never sees.
//
// Every request is checked in this order, and the first failure ends it:
//
//  1. Identity. The request must come from a trusted proxy address (Caddy),
//     carry the proxy secret when one is configured, and carry the subject
//     oauth2-proxy vouches for (X-Auth-Request-User: the OIDC "sub" by
//     default). No identity, 401: an expired IdP session reaches nothing.
//  2. For a call that changes anything: POST, the exact configured Origin,
//     X-Requested-With: slides-gitd, a JSON body; the gitd session cookie
//     (__Host-, Secure, HttpOnly, SameSite=Strict) must belong to THIS subject
//     (another subject's cookie is refused and its session destroyed) and the
//     X-CSRF-Token header must equal the session's token.
//  3. A per-subject rate limit and a body size bound.
//  4. Authorization, deny by default: the repository must be one the
//     configuration grants to this subject on this forge.
//  5. The credential is this subject's own (sealed in the vault, per-user key)
//     or a GitHub App installation token minted for that one repository.
//     Proposals go to a NEW branch under slides/<user>/, named by the server.
//  6. One audit line: who, what, where, the outcome; never content or token.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-browserhttp/browsergit/forge"
	"github.com/go-browserhttp/browsergit/remote"
	"github.com/go-browserhttp/browsergit/secret"
	"github.com/go-slides/gitd/internal/audit"
	"github.com/go-slides/gitd/internal/ghapp"
	"github.com/go-slides/gitd/internal/session"
	"github.com/go-slides/gitd/internal/vault"
)

// CookieName is the session cookie (the __Host- prefix forbids Domain and
// requires Secure and Path=/).
const CookieName = "__Host-gitd"

var (
	forgeName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	slugRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
)

// Server is the API.
type Server struct {
	cfg         *Config
	vault       *vault.Vault
	sessions    *session.Store
	audit       *audit.Log
	apps        map[string]*ghapp.App
	proxySecret secret.Token
	trusted     []netip.Prefix
	lim         *limiter
	// NewRemote builds a forge remote; tests replace it.
	NewRemote func(fc ForgeConfig, tok secret.Token, branchPrefix string) (remote.Remote, error)
	Now       func() time.Time
}

// New assembles a server.
func New(cfg *Config, v *vault.Vault, a *audit.Log, apps map[string]*ghapp.App, proxySecret secret.Token) *Server {
	s := &Server{cfg: cfg, vault: v, sessions: session.New(), audit: a, apps: apps, proxySecret: proxySecret,
		lim: newLimiter(cfg.RatePerMinute, cfg.Burst)}
	for _, p := range cfg.TrustedProxies {
		s.trusted = append(s.trusted, netip.MustParsePrefix(p))
	}
	s.NewRemote = func(fc ForgeConfig, tok secret.Token, prefix string) (remote.Remote, error) {
		return forge.New(forge.Config{Kind: forge.Kind(fc.Kind), API: fc.API, Web: fc.Web, Token: tok, BranchPrefix: prefix})
	}
	return s
}

// Sessions exposes the store (tests, metrics).
func (s *Server) Sessions() *session.Store { return s.sessions }

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler is the API's router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /api/git/session", s.handleSession)
	mux.HandleFunc("POST /api/git/credential", s.mutating("credential", s.handleCredential))
	mux.HandleFunc("POST /api/git/credential/delete", s.mutating("credential-delete", s.handleCredentialDelete))
	mux.HandleFunc("POST /api/git/load", s.mutating("load", s.handleLoad))
	mux.HandleFunc("POST /api/git/propose", s.mutating("propose", s.handlePropose))
	mux.HandleFunc("POST /api/git/refresh", s.mutating("refresh", s.handleRefresh))
	return headers(mux)
}

// headers sets what every response carries: no caching of per-user answers,
// no sniffing, no framing.
func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

// identity returns the subject oauth2-proxy vouched for, or an error.
func (s *Server) identity(r *http.Request) (subject, email string, err error) {
	host, _, splitErr := net.SplitHostPort(r.RemoteAddr)
	addr, parseErr := netip.ParseAddr(host)
	if splitErr != nil || parseErr != nil {
		return "", "", errors.New("no peer address")
	}
	trusted := false
	for _, p := range s.trusted {
		if p.Contains(addr.Unmap()) {
			trusted = true
		}
	}
	if !trusted {
		return "", "", errors.New("not from a trusted proxy")
	}
	if !s.proxySecret.IsZero() && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Gitd-Proxy-Secret")), []byte(s.proxySecret.Reveal())) != 1 {
		return "", "", errors.New("proxy secret missing or wrong")
	}
	subject = r.Header.Get("X-Auth-Request-User")
	if subject == "" || len(subject) > 256 || strings.IndexFunc(subject, unicode.IsControl) >= 0 {
		return "", "", errors.New("no identity")
	}
	email = r.Header.Get("X-Auth-Request-Email")
	if len(email) > 254 || strings.IndexFunc(email, func(c rune) bool { return unicode.IsControl(c) || c == '<' || c == '>' }) >= 0 {
		email = ""
	}
	return subject, email, nil
}

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, class string) {
	writeJSON(w, code, apiError{Error: class})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	subject, _, err := s.identity(r)
	if err != nil {
		fail(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var x *session.Session
	if c, err := r.Cookie(CookieName); err == nil {
		x, _ = s.sessions.Get(c.Value, subject) // another subject's: destroyed by Get
	}
	if x == nil {
		x = s.sessions.Create(subject)
		http.SetCookie(w, &http.Cookie{Name: CookieName, Value: x.ID, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": subject, "csrf": x.CSRF, "repos": s.cfg.Users[subject].Repos})
}

// call is what a mutating handler receives once every check has passed.
type call struct {
	subject, email string
	entry          *audit.Entry
}

func (s *Server) mutating(action string, h func(context.Context, *call, *json.Decoder) (int, any)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e := audit.Entry{Action: action, Remote: r.Header.Get("X-Forwarded-For")}
		defer func() {
			e.Time = s.now().UTC()
			s.audit.Write(e)
		}()
		subject, email, err := s.identity(r)
		if err != nil {
			e.Outcome = "unauthenticated"
			fail(w, http.StatusUnauthorized, e.Outcome)
			return
		}
		e.Subject = subject
		if r.Header.Get("Origin") != s.cfg.Origin || r.Header.Get("X-Requested-With") != "slides-gitd" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			e.Outcome = "csrf"
			fail(w, http.StatusForbidden, e.Outcome)
			return
		}
		c, err := r.Cookie(CookieName)
		if err != nil {
			e.Outcome = "no-session"
			fail(w, http.StatusForbidden, e.Outcome)
			return
		}
		x, err := s.sessions.Get(c.Value, subject)
		if err != nil {
			e.Outcome = "session"
			fail(w, http.StatusForbidden, e.Outcome)
			return
		}
		if session.CheckCSRF(x, r.Header.Get("X-CSRF-Token")) != nil {
			e.Outcome = "csrf"
			fail(w, http.StatusForbidden, e.Outcome)
			return
		}
		if !s.lim.allow(subject, s.now()) {
			e.Outcome = "rate-limited"
			w.Header().Set("Retry-After", "10")
			fail(w, http.StatusTooManyRequests, e.Outcome)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		code, out := h(r.Context(), &call{subject: subject, email: email, entry: &e}, dec)
		if e.Outcome == "" {
			e.Outcome = "ok"
		}
		writeJSON(w, code, out)
	}
}

// grant reports whether subject may reach forge:repo.
func (s *Server) grant(subject, forgeName, repo string) bool {
	u, ok := s.cfg.Users[subject]
	if !ok {
		return false
	}
	want := forgeName + ":" + repo
	for _, r := range u.Repos {
		if r == want {
			return true
		}
	}
	return false
}

// grantedOn reports whether subject has any repository on forge.
func (s *Server) grantedOn(subject, forgeName string) bool {
	for _, r := range s.cfg.Users[subject].Repos {
		if strings.HasPrefix(r, forgeName+":") {
			return true
		}
	}
	return false
}

// slug is the user's branch directory (see branchDir).
func (s *Server) slug(subject string) string { return branchDir(subject, s.cfg.Users[subject].Slug) }

// remoteFor is subject's remote for forge and repo, after the grant check.
func (s *Server) remoteFor(ctx context.Context, c *call, forgeName, repo string) (remote.Remote, int, string) {
	fc, ok := s.cfg.Forges[forgeName]
	if !ok || !s.grant(c.subject, forgeName, repo) {
		// nothing the client sent reaches the audit before it is granted
		// (go-slides/gitd#2): only a configured forge's name
		if ok {
			c.entry.Forge = forgeName
		}
		return nil, http.StatusForbidden, "denied"
	}
	c.entry.Forge, c.entry.Repo = forgeName, repo // both from the configuration now
	var tok secret.Token
	switch fc.Auth {
	case "github-app":
		app := s.apps[forgeName]
		if app == nil {
			return nil, http.StatusInternalServerError, "misconfigured"
		}
		_, name, _ := strings.Cut(repo, "/")
		t, err := app.Token(ctx, name)
		if err != nil {
			return nil, http.StatusBadGateway, "app-token"
		}
		tok = t
	default:
		t, err := s.vault.Get(c.subject, forgeName)
		if errors.Is(err, vault.ErrNotFound) {
			return nil, http.StatusPreconditionRequired, "no-credential"
		}
		if err != nil {
			return nil, http.StatusInternalServerError, "vault"
		}
		tok = t
	}
	rem, err := s.NewRemote(fc, tok, "slides/"+s.slug(c.subject)+"/")
	if err != nil {
		return nil, http.StatusInternalServerError, "misconfigured"
	}
	return rem, 0, ""
}

// classify maps a remote error to a status and a class (never its text).
func classify(ctx context.Context, err error) (int, string) {
	switch {
	case ctx.Err() != nil:
		return 499, "canceled"
	case errors.Is(err, remote.ErrBadPath), errors.Is(err, remote.ErrBadRepo), errors.Is(err, remote.ErrBadBranch), errors.Is(err, remote.ErrTooLarge), errors.Is(err, remote.ErrNoChanges):
		return http.StatusBadRequest, "refused"
	case errors.Is(err, remote.ErrBranchExists), errors.Is(err, remote.ErrStale), errors.Is(err, remote.ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, remote.ErrNotFound):
		return http.StatusNotFound, "not-found"
	case errors.Is(err, remote.ErrAuth), errors.Is(err, remote.ErrForbidden):
		return http.StatusBadGateway, "forge-auth"
	case errors.Is(err, remote.ErrRateLimited):
		return http.StatusBadGateway, "forge-rate-limited"
	}
	return http.StatusBadGateway, "forge"
}

func (c *call) failed(ctx context.Context, err error) (int, any) {
	code, class := classify(ctx, err)
	c.entry.Outcome = class
	return code, apiError{Error: class}
}

func (c *call) deny(code int, class string) (int, any) {
	c.entry.Outcome = class
	return code, apiError{Error: class}
}

type credentialReq struct {
	Forge string `json:"forge"`
	Token string `json:"token"`
}

func (s *Server) handleCredential(_ context.Context, c *call, dec *json.Decoder) (int, any) {
	var q credentialReq
	if err := dec.Decode(&q); err != nil {
		return c.deny(http.StatusBadRequest, "bad-request")
	}
	tok := secret.New(q.Token)
	q.Token = ""
	defer tok.Forget()
	fc, ok := s.cfg.Forges[q.Forge]
	if !ok || fc.Auth != "user-token" {
		return c.deny(http.StatusBadRequest, "no-such-forge")
	}
	c.entry.Forge = q.Forge // a configured name, so bounded
	// a user with no repository on this forge has nothing to store a token for
	// (go-slides/gitd#2): the vault takes writes from granted users only
	if !s.grantedOn(c.subject, q.Forge) {
		return c.deny(http.StatusForbidden, "denied")
	}
	if err := s.vault.Put(c.subject, q.Forge, tok); err != nil {
		return c.deny(http.StatusBadRequest, "refused")
	}
	return http.StatusOK, map[string]any{"stored": true}
}

func (s *Server) handleCredentialDelete(_ context.Context, c *call, dec *json.Decoder) (int, any) {
	var q struct {
		Forge string `json:"forge"`
	}
	if err := dec.Decode(&q); err != nil {
		return c.deny(http.StatusBadRequest, "bad-request")
	}
	if _, ok := s.cfg.Forges[q.Forge]; ok {
		c.entry.Forge = q.Forge
	}
	if err := s.vault.Delete(c.subject, q.Forge); err != nil {
		return c.deny(http.StatusBadRequest, "refused")
	}
	return http.StatusOK, map[string]any{"deleted": true}
}

type loadReq struct {
	Forge string `json:"forge"`
	Repo  string `json:"repo"`
	Ref   string `json:"ref"`
	Dir   string `json:"dir"`
}

type loadRsp struct {
	Files remote.Files `json:"files"`
	Base  remote.Base  `json:"base"`
}

func (s *Server) handleLoad(ctx context.Context, c *call, dec *json.Decoder) (int, any) {
	var q loadReq
	if err := dec.Decode(&q); err != nil {
		return c.deny(http.StatusBadRequest, "bad-request")
	}
	rem, code, class := s.remoteFor(ctx, c, q.Forge, q.Repo)
	if rem == nil {
		return c.deny(code, class)
	}
	files, base, err := rem.Load(ctx, q.Repo, q.Ref, q.Dir)
	if err != nil {
		return c.failed(ctx, err)
	}
	c.entry.Files = len(files)
	return http.StatusOK, loadRsp{Files: files, Base: base}
}

type proposeReq struct {
	Forge string       `json:"forge"`
	Base  remote.Base  `json:"base"`
	Files remote.Files `json:"files"`
	Title string       `json:"title"`
	Body  string       `json:"body"`
}

func oneLine(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if len([]rune(s)) > n {
		s = string([]rune(s)[:n])
	}
	return strings.TrimSpace(s)
}

func (s *Server) handlePropose(ctx context.Context, c *call, dec *json.Decoder) (int, any) {
	var q proposeReq
	if err := dec.Decode(&q); err != nil {
		return c.deny(http.StatusBadRequest, "bad-request")
	}
	rem, code, class := s.remoteFor(ctx, c, q.Forge, q.Base.Repo)
	if rem == nil {
		return c.deny(code, class)
	}
	title := oneLine(q.Title, 120)
	if title == "" {
		title = "Update the slides"
	}
	// The branch is the server's choice, under this user's prefix: a client
	// cannot name one.
	branch := remote.BranchName("slides/"+s.slug(c.subject)+"/", title, s.now())
	body := oneLine(q.Body, 2000) + "\n\nProposed by " + oneLine(c.subject, 256) + " through slides-gitd."
	if c.email != "" {
		body += "\n\nCo-authored-by: " + oneLine(c.subject, 256) + " <" + c.email + ">"
	}
	c.entry.Branch, c.entry.Files = branch, len(q.Files)
	res, err := rem.Propose(ctx, q.Base, q.Files, remote.Proposal{Branch: branch, Title: title, Body: body})
	if err != nil {
		return c.failed(ctx, err)
	}
	return http.StatusOK, map[string]any{"branch": res.Branch, "commit": res.Commit, "url": res.URL}
}

type refreshReq struct {
	Forge string      `json:"forge"`
	Base  remote.Base `json:"base"`
}

func (s *Server) handleRefresh(ctx context.Context, c *call, dec *json.Decoder) (int, any) {
	var q refreshReq
	if err := dec.Decode(&q); err != nil {
		return c.deny(http.StatusBadRequest, "bad-request")
	}
	rem, code, class := s.remoteFor(ctx, c, q.Forge, q.Base.Repo)
	if rem == nil {
		return c.deny(code, class)
	}
	files, head, err := rem.Refresh(ctx, q.Base)
	if err != nil {
		return c.failed(ctx, err)
	}
	return http.StatusOK, loadRsp{Files: files, Base: head}
}

// limiter is a token bucket per subject.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute, burst int) *limiter {
	return &limiter{rate: float64(perMinute) / 60, burst: float64(burst), buckets: map[string]*bucket{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) > 100000 {
			l.buckets = map[string]*bucket{} // bounded memory
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// String keeps a Server out of logs.
func (s *Server) String() string { return fmt.Sprintf("slides-gitd(%d forges)", len(s.cfg.Forges)) }
