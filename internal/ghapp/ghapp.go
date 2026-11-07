// Package ghapp mints GitHub App installation tokens, narrowed to ONE
// repository and the three permissions a proposal needs, cached until shortly
// before they expire (they live an hour).
//
// References: docs.github.com, "Generating a JSON Web Token (JWT) for a GitHub
// App" (RS256; iat 60 s in the past; exp at most 10 minutes; iss the client
// or app ID) and "Create an installation access token for an app" (POST
// /app/installations/{id}/access_tokens; body repositories, permissions;
// response token, expires_at).
package ghapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-browserhttp/browsergit/forge"
	"github.com/go-browserhttp/browsergit/secret"
)

// Permissions are what a proposal needs, and all a minted token gets.
var Permissions = map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"}

// App is one GitHub App installation.
type App struct {
	API            string // https://api.github.com
	ClientID       string // or the app ID
	InstallationID int64
	key            *rsa.PrivateKey
	Transport      forge.Transport
	Now            func() time.Time

	mu    sync.Mutex
	cache map[string]cached // repository name -> token
}

type cached struct {
	tok    secret.Token
	expiry time.Time
}

// LoadKey reads the App's PEM private key from a file only its owner can read.
func LoadKey(path string) (*rsa.PrivateKey, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("ghapp: %s must be a regular file readable by its owner only", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("ghapp: no PEM block in the key file")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("ghapp: the key is neither PKCS#1 nor PKCS#8")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("ghapp: the key is not RSA")
	}
	return rk, nil
}

// New returns an App signing with key.
func New(api, clientID string, installation int64, key *rsa.PrivateKey) *App {
	return &App{API: api, ClientID: clientID, InstallationID: installation, key: key, cache: map[string]cached{}}
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// JWT is the app's short-lived assertion.
func (a *App) JWT() (string, error) {
	now := a.now()
	head := b64([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": a.ClientID,
	})
	signing := head + "." + b64(claims)
	h := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

// Token returns an installation token for repo ("name", the installation's
// owner implied), minted or cached.
func (a *App) Token(ctx context.Context, repo string) (secret.Token, error) {
	a.mu.Lock()
	if c, ok := a.cache[repo]; ok && a.now().Add(5*time.Minute).Before(c.expiry) && !c.tok.IsZero() {
		a.mu.Unlock()
		return c.tok, nil
	}
	a.mu.Unlock()
	jwt, err := a.JWT()
	if err != nil {
		return secret.Token{}, err
	}
	body, _ := json.Marshal(map[string]any{"repositories": []string{repo}, "permissions": Permissions})
	tr := a.Transport
	if tr == nil {
		tr = forge.DefaultTransport()
	}
	rsp, err := tr.RoundTrip(ctx, &forge.Request{
		Method: "POST",
		URL:    a.API + "/app/installations/" + strconv.FormatInt(a.InstallationID, 10) + "/access_tokens",
		Header: map[string]string{
			"Authorization":        "Bearer " + jwt,
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
			"Content-Type":         "application/json",
		},
		Body:  body,
		Limit: 1 << 20,
	})
	if err != nil {
		return secret.Token{}, fmt.Errorf("ghapp: %s", secret.Redact(err.Error(), secret.New(jwt)))
	}
	if rsp.Status != 201 {
		return secret.Token{}, fmt.Errorf("ghapp: installation token: HTTP %d", rsp.Status)
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(rsp.Body, &out); err != nil || out.Token == "" {
		return secret.Token{}, errors.New("ghapp: malformed installation token response")
	}
	tok := secret.New(out.Token)
	a.mu.Lock()
	if old, ok := a.cache[repo]; ok {
		old.tok.Forget()
	}
	a.cache[repo] = cached{tok: tok, expiry: out.ExpiresAt}
	a.mu.Unlock()
	return tok, nil
}
