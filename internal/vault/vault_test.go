package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-browserhttp/browsergit/secret"
)

const tokA, tokB = "USER-A-TOKEN-PLACEHOLDER", "USER-B-TOKEN-PLACEHOLDER"

func newVault(t *testing.T) (*Vault, string) {
	t.Helper()
	dir := t.TempDir()
	v, err := Open(dir, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return v, dir
}

func TestPutGetDelete(t *testing.T) {
	v, _ := newVault(t)
	if err := v.Put("alice", "gitlab", secret.New(tokA)); err != nil {
		t.Fatal(err)
	}
	if err := v.Put("bob", "gitlab", secret.New(tokB)); err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Get("alice", "gitlab"); got.Reveal() != tokA {
		t.Fatal("alice")
	}
	if got, _ := v.Get("bob", "gitlab"); got.Reveal() != tokB {
		t.Fatal("bob")
	}
	if _, err := v.Get("carol", "gitlab"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := v.Delete("alice", "gitlab"); err != nil || v.Delete("alice", "gitlab") != nil {
		t.Fatal("delete")
	}
	if _, err := v.Get("alice", "gitlab"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted")
	}
}

func TestNothingOnDiskIsReadableOrPortable(t *testing.T) {
	v, dir := newVault(t)
	_ = v.Put("alice", "gitlab", secret.New(tokA))
	_ = v.Put("bob", "gitlab", secret.New(tokB))
	// No plaintext, no subject name on disk; files and directories owner-only.
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(p, "alice") || strings.Contains(p, "bob") {
			t.Errorf("a path names the user: %s", p)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is mode %v", p, info.Mode().Perm())
		}
		if !info.IsDir() {
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte("TOKEN-PLACEHOLDER")) {
				t.Errorf("plaintext in %s", p)
			}
		}
		return nil
	})
	// Bob's record copied over Alice's does not open as Alice's.
	a := filepath.Join(v.userDir("alice"), "gitlab.rec")
	b := filepath.Join(v.userDir("bob"), "gitlab.rec")
	rb, _ := os.ReadFile(b)
	if err := os.WriteFile(a, rb, 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, err := v.Get("alice", "gitlab"); !errors.Is(err, ErrCorrupt) || tok.Reveal() == tokB {
		t.Fatalf("another user's record opened: %v", err)
	}
	// A record renamed to another forge does not open either.
	_ = os.Rename(b, filepath.Join(v.userDir("bob"), "gitea.rec"))
	if _, err := v.Get("bob", "gitea"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a record moved to another forge opened: %v", err)
	}
	// Another master key opens nothing.
	v2, _ := Open(dir, bytes.Repeat([]byte{8}, 32))
	_ = v.Put("carol", "gitlab", secret.New("CAROL-TOKEN-PLACEHOLDER"))
	if _, err := v2.Get("carol", "gitlab"); !errors.Is(err, ErrCorrupt) {
		t.Fatal("another key opened a record")
	}
}

func TestCorruptRecordsAreRefusedNotPanicked(t *testing.T) {
	v, _ := newVault(t)
	_ = v.Put("alice", "gitlab", secret.New(tokA))
	p := filepath.Join(v.userDir("alice"), "gitlab.rec")
	orig, _ := os.ReadFile(p)
	for name, b := range map[string][]byte{
		"empty":     {},
		"truncated": orig[:len(orig)/2],
		"version":   append([]byte{9}, orig[1:]...),
		"flipped":   append(append([]byte(nil), orig[:len(orig)-1]...), orig[len(orig)-1]^1),
		"huge":      make([]byte, 1<<20),
	} {
		_ = os.WriteFile(p, b, 0o600)
		if _, err := v.Get("alice", "gitlab"); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestConcurrentWritersNeverTearARecord(t *testing.T) {
	v, _ := newVault(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok := tokA
			if i%2 == 1 {
				tok = tokB
			}
			_ = v.Put("alice", "gitlab", secret.New(tok))
			if got, err := v.Get("alice", "gitlab"); err != nil || (got.Reveal() != tokA && got.Reveal() != tokB) {
				t.Errorf("a torn read: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

func TestNamesAndKeys(t *testing.T) {
	v, _ := newVault(t)
	for _, f := range []string{"", "../x", "Git", "a/b", strings.Repeat("a", 40)} {
		if err := v.Put("alice", f, secret.New(tokA)); !errors.Is(err, ErrName) {
			t.Errorf("forge %q: %v", f, err)
		}
	}
	if err := v.Put("", "gitlab", secret.New(tokA)); !errors.Is(err, ErrName) {
		t.Fatal("empty subject")
	}
	if err := v.Put("alice", "gitlab", secret.Token{}); err == nil {
		t.Fatal("empty token")
	}
	if _, err := Open(t.TempDir(), []byte("short")); !errors.Is(err, ErrKeyFile) {
		t.Fatal("short key")
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "k")
	_ = os.WriteFile(good, []byte(strings.Repeat("ab", 32)+"\n"), 0o600)
	if k, err := LoadKey(good); err != nil || len(k) != 32 {
		t.Fatalf("hex key: %v", err)
	}
	raw := filepath.Join(dir, "raw")
	_ = os.WriteFile(raw, bytes.Repeat([]byte{1}, 32), 0o400)
	if _, err := LoadKey(raw); err != nil {
		t.Fatalf("raw key: %v", err)
	}
	open := filepath.Join(dir, "open")
	_ = os.WriteFile(open, bytes.Repeat([]byte{1}, 32), 0o644)
	if _, err := LoadKey(open); !errors.Is(err, ErrKeyFile) {
		t.Fatal("a world-readable key file must be refused")
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("nope"), 0o600)
	if _, err := LoadKey(bad); !errors.Is(err, ErrKeyFile) {
		t.Fatal("a malformed key must be refused")
	}
	if _, err := LoadKey(filepath.Join(dir, "missing")); !errors.Is(err, ErrKeyFile) {
		t.Fatal("missing")
	}
	if _, err := LoadKey(dir); !errors.Is(err, ErrKeyFile) {
		t.Fatal("a directory")
	}
}
