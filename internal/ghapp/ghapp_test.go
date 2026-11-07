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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMintNarrowAndCache(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/app/installations/42/access_tokens" {
			http.Error(w, "path", 404)
			return
		}
		jwt := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			http.Error(w, "jwt", 401)
			return
		}
		h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], sig) != nil {
			http.Error(w, "signature", 401)
			return
		}
		var c struct {
			Iat, Exp int64
			Iss      string
		}
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(raw, &c)
		now := time.Now().Unix()
		if c.Iss != "Iv1.client" || c.Iat > now-30 || c.Exp-c.Iat > 600 {
			http.Error(w, "claims", 401)
			return
		}
		var body struct {
			Repositories []string
			Permissions  map[string]string
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body.Repositories) != 1 || body.Repositories[0] != "deck" || len(body.Permissions) != 3 || body.Permissions["contents"] != "write" {
			http.Error(w, "the token must be narrowed", 422)
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_INSTALLATION_PLACEHOLDER", "expires_at": time.Now().Add(time.Hour).UTC()})
	}))
	defer srv.Close()
	a := New(srv.URL, "Iv1.client", 42, key)
	tok, err := a.Token(context.Background(), "deck")
	if err != nil || tok.Reveal() != "ghs_INSTALLATION_PLACEHOLDER" {
		t.Fatalf("token: %v", err)
	}
	if _, err := a.Token(context.Background(), "deck"); err != nil || calls.Load() != 1 {
		t.Fatalf("a cached token must not be minted again (%d calls)", calls.Load())
	}
	// Near expiry: minted again.
	a.Now = func() time.Time { return time.Now().Add(56 * time.Minute) }
	_, _ = a.Token(context.Background(), "deck")
	if calls.Load() != 2 {
		t.Fatalf("an expiring token must be minted again (%d calls)", calls.Load())
	}
	// Another repository: its own token, never the first one's.
	if _, err := a.Token(context.Background(), "other"); err == nil {
		t.Fatal("the fake refuses other repositories; the error must surface")
	}
}

func TestLoadKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	dir := t.TempDir()
	p1 := filepath.Join(dir, "pkcs1.pem")
	_ = os.WriteFile(p1, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	if _, err := LoadKey(p1); err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	p8 := filepath.Join(dir, "pkcs8.pem")
	_ = os.WriteFile(p8, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o400)
	if _, err := LoadKey(p8); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(dir, "open.pem")
	_ = os.WriteFile(open, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o644)
	if _, err := LoadKey(open); err == nil {
		t.Fatal("a world-readable key must be refused")
	}
	junk := filepath.Join(dir, "junk.pem")
	_ = os.WriteFile(junk, []byte("nope"), 0o600)
	if _, err := LoadKey(junk); err == nil {
		t.Fatal("junk")
	}
	if _, err := LoadKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing")
	}
}
