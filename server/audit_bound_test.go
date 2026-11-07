package server

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/go-slides/gitd/internal/vault"
)

// go-slides/gitd#2: a refused request must not be able to fill the disk
// through the audit log, and a user with no grant must not reach the vault.

func (hh *harness) logLen() int {
	hh.logMu.Lock()
	defer hh.logMu.Unlock()
	return hh.log.Len()
}

func (hh *harness) logText() string {
	hh.logMu.Lock()
	defer hh.logMu.Unlock()
	return hh.log.String()
}

func TestARefusedRequestWritesABoundedAuditLine(t *testing.T) {
	hh := newHarness(t)
	big := strings.Repeat("A", 8<<20)
	for name, c := range map[string]client{"no grant at all": hh.login("mallory"), "granted elsewhere": hh.login("alice")} {
		before := hh.logLen()
		w := hh.post(c, "/api/git/load", loadReq{Forge: "gitlab", Repo: big})
		grew := hh.logLen() - before
		if w.Code != http.StatusForbidden || grew > 1024 {
			t.Errorf("%s: status %d, the audit grew by %d bytes for one refused request", name, w.Code, grew)
		}
		before = hh.logLen()
		_ = hh.post(c, "/api/git/load", loadReq{Forge: big, Repo: "g/p"})
		if grew := hh.logLen() - before; grew > 1024 {
			t.Errorf("%s: a huge forge name grew the audit by %d bytes", name, grew)
		}
	}
	if strings.Contains(hh.logText(), "AAAAAAAAAAAAAAAA") {
		t.Fatal("a client-supplied, unchecked value reached the audit log")
	}
	// The control: a granted request still records its repository.
	a := hh.login("alice")
	_ = hh.post(a, "/api/git/load", loadP)
	if !strings.Contains(hh.logText(), `"repo":"g/p"`) {
		t.Fatal("control: a granted request must record its repository")
	}
}

func TestAUserWithNoGrantCannotWriteTheVault(t *testing.T) {
	hh := newHarness(t)
	m := hh.login("mallory")
	if w := hh.post(m, "/api/git/credential", credentialReq{Forge: "gitlab", Token: "MALLORY-TOKEN-PLACEHOLDER"}); w.Code != http.StatusForbidden {
		t.Fatalf("an ungranted user stored a credential: %d %s", w.Code, w.Body)
	}
	if _, err := hh.srv.vault.Get("mallory", "gitlab"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("the vault holds mallory's record: %v", err)
	}
	big := strings.Repeat("B", 1<<20)
	before := hh.logLen()
	_ = hh.post(m, "/api/git/credential", credentialReq{Forge: big, Token: "x"})
	if grew := hh.logLen() - before; grew > 1024 {
		t.Fatalf("a huge forge name grew the audit by %d bytes", grew)
	}
	// The control: a granted user still can.
	a := hh.login("alice")
	if w := hh.post(a, "/api/git/credential", credentialReq{Forge: "gitlab", Token: "ALICE-NEW-PLACEHOLDER"}); w.Code != 200 {
		t.Fatalf("control: %d", w.Code)
	}
}
