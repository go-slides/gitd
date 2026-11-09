// Package gitdtest is a slides-gitd for tests of what sits in front of it (the
// playground, a proxy): the real server package, its real session, CSRF, grant,
// vault and audit code, with the forge replaced by an in-memory one.
//
// What is real: everything a browser or a proxy can observe, that is the
// identity header, the cookie, the CSRF handshake, the grants, the branch
// prefix the server imposes, and the per-user credential from the sealed vault.
// What is not: the forge. A repository here has an owner token, and the fake
// forge answers a request only when the vault handed it THAT token, so a server
// that mixed two users' credentials fails a test instead of passing it.
//
// It is for tests: its tokens are fixed strings the caller names, and nothing
// here is safe to run on a network.
package gitdtest

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/go-browserhttp/browsergit/remote"
	"github.com/go-browserhttp/browsergit/secret"
	"github.com/go-slides/gitd/internal/audit"
	"github.com/go-slides/gitd/internal/vault"
	"github.com/go-slides/gitd/server"
)

// Forge is the one forge's name in the configuration.
const Forge = "github"

// Repo is a repository of the fake forge.
type Repo struct {
	// Name is "owner/name".
	Name string
	// Token is the credential that may read and write it.
	Token string
	// Files are the repository's files (path to content) on its main branch.
	Files map[string]string
}

// User is one identity the proxy may vouch for.
type User struct {
	// Subject is what X-Auth-Request-User carries (the OIDC sub).
	Subject string
	// Slug names the user's branches (empty: derived from the subject).
	Slug string
	// Repos are the "owner/name" the user is granted.
	Repos []string
	// Token is the user's own credential, sealed in the vault.
	Token string
}

// Options configure New.
type Options struct {
	// Origin is the page's origin, the only one allowed to write
	// ("http://127.0.0.1:PORT").
	Origin string
	// Dir holds the vault; it must exist.
	Dir   string
	Users []User
	Repos []Repo
}

// Proposal is a pull request the fake forge received.
type Proposal struct {
	Repo   string
	Branch string
	Title  string
	Body   string
	// Token is the credential the forge saw: whose it was is the point.
	Token string
	Files []string
}

// Env is a running (in-process) slides-gitd and its fake forge.
type Env struct {
	// Server is the real server.
	Server *server.Server
	// Handler is Server's router: mount it behind whatever sets the identity.
	Handler http.Handler

	mu        sync.Mutex
	repos     map[string]*repoState
	proposals []Proposal
	audit     bytes.Buffer
}

type repoState struct {
	Repo
	rev   int
	files map[string]string
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

// New builds the environment.
func New(o Options) (*Env, error) {
	users := map[string]any{}
	for _, u := range o.Users {
		repos := make([]string, len(u.Repos))
		for i, r := range u.Repos {
			repos[i] = Forge + ":" + r
		}
		e := map[string]any{"repos": repos}
		if u.Slug != "" {
			e["slug"] = u.Slug
		}
		users[u.Subject] = e
	}
	if o.Origin == "" {
		return nil, errors.New("gitdtest: Options.Origin is required")
	}
	// the configuration insists on https; a test page is served from
	// http://127.0.0.1 (a secure context for browsers), so the origin is set
	// after parsing
	raw, err := json.Marshal(map[string]any{
		"origin": "https://slides.example", "master_key_file": "unused", "data_dir": "unused", "audit_file": "unused",
		"rate_per_minute": 6000, "burst": 500,
		"forges": map[string]any{Forge: map[string]any{"kind": "github", "api": "https://api.github.example", "auth": "user-token"}},
		"users":  users,
	})
	if err != nil {
		return nil, err
	}
	cfg, err := server.ParseConfig(raw)
	if err != nil {
		return nil, err
	}
	cfg.Origin = strings.TrimRight(o.Origin, "/")
	v, err := vault.Open(o.Dir, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		return nil, err
	}
	e := &Env{repos: map[string]*repoState{}}
	for _, r := range o.Repos {
		e.repos[r.Name] = &repoState{Repo: r, rev: 1, files: cloneFiles(r.Files)}
	}
	for _, u := range o.Users {
		if err := v.Put(u.Subject, Forge, secret.New(u.Token)); err != nil {
			return nil, err
		}
	}
	e.Server = server.New(cfg, v, audit.To(lockedWriter{&e.mu, &e.audit}), nil, secret.Token{})
	e.Server.NewRemote = func(_ server.ForgeConfig, tok secret.Token, prefix string) (remote.Remote, error) {
		return &fakeForge{env: e, token: tok.Reveal(), prefix: prefix}, nil
	}
	e.Handler = e.Server.Handler()
	return e, nil
}

func cloneFiles(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Proposals are the pull requests received so far.
func (e *Env) Proposals() []Proposal {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Proposal(nil), e.proposals...)
}

// Advance moves a repository's main branch to a new commit with files (a
// colleague pushed), so that a Check for changes finds it.
func (e *Env) Advance(repo string, files map[string]string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.repos[repo]
	if !ok {
		return false
	}
	r.rev++
	r.files = cloneFiles(files)
	return true
}

// Audit is the audit log so far (one JSON object per line).
func (e *Env) Audit() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.audit.String()
}

// commit is a repository's current commit id.
func (r *repoState) commit() string {
	h := sha1.New()
	fmt.Fprintf(h, "%s/%d", r.Name, r.rev)
	return hex.EncodeToString(h.Sum(nil))
}

func blobID(s string) string { return remote.BlobID([]byte(s)) }

type fakeForge struct {
	env    *Env
	token  string
	prefix string
}

// repo is the repository when this forge's credential may use it.
func (f *fakeForge) repo(name string) (*repoState, error) {
	r, ok := f.env.repos[name]
	if !ok {
		return nil, remote.ErrNotFound
	}
	if r.Token != f.token {
		// a private repository answers a stranger's token as GitHub does
		return nil, remote.ErrNotFound
	}
	return r, nil
}

func (f *fakeForge) Load(_ context.Context, repo, ref, dir string) (remote.Files, remote.Base, error) {
	f.env.mu.Lock()
	defer f.env.mu.Unlock()
	r, err := f.repo(repo)
	if err != nil {
		return nil, remote.Base{}, err
	}
	if ref == "" {
		ref = "main"
	}
	return r.snapshot(ref, dir)
}

func (r *repoState) snapshot(ref, dir string) (remote.Files, remote.Base, error) {
	files, blobs := remote.Files{}, map[string]string{}
	for p, c := range r.files {
		rel, ok := remote.Rel(dir, p)
		if !ok {
			continue
		}
		files[rel] = []byte(c)
		blobs[rel] = blobID(c)
	}
	return files, remote.Base{Forge: Forge, Repo: r.Name, Ref: ref, Dir: dir, Commit: r.commit(), Blobs: blobs}, nil
}

func (f *fakeForge) Propose(_ context.Context, base remote.Base, files remote.Files, p remote.Proposal) (remote.Result, error) {
	f.env.mu.Lock()
	defer f.env.mu.Unlock()
	r, err := f.repo(base.Repo)
	if err != nil {
		return remote.Result{}, err
	}
	if base.Commit != r.commit() {
		return remote.Result{}, remote.ErrStale
	}
	if err := remote.RequirePrefix(p.Branch, f.prefix); err != nil {
		return remote.Result{}, err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	f.env.proposals = append(f.env.proposals, Proposal{Repo: base.Repo, Branch: p.Branch, Title: p.Title, Body: p.Body, Token: f.token, Files: names})
	return remote.Result{
		Branch: p.Branch, Commit: strings.Repeat("c", 40),
		URL: fmt.Sprintf("https://github.example/%s/pull/%d", base.Repo, len(f.env.proposals)),
	}, nil
}

func (f *fakeForge) Refresh(_ context.Context, base remote.Base) (remote.Files, remote.Base, error) {
	f.env.mu.Lock()
	defer f.env.mu.Unlock()
	r, err := f.repo(base.Repo)
	if err != nil {
		return nil, base, err
	}
	if base.Commit == r.commit() {
		return nil, base, nil
	}
	ref := base.Ref
	if ref == "" {
		ref = "main"
	}
	return r.snapshot(ref, base.Dir)
}
