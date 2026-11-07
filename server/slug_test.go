package server

import (
	"strings"
	"testing"
	"time"

	"github.com/go-browserhttp/browsergit/remote"
	"github.com/go-browserhttp/browsergit/secret"
)

// go-slides/gitd#3: two users must never share a slides/<user>/ prefix.

func TestBranchPrefixesAreInjective(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{
		"origin": "https://slides.example",
		"master_key_file": "x", "data_dir": "x", "audit_file": "x",
		"forges": {"gl": {"kind": "gitlab", "api": "https://gitlab.example/api/v4", "auth": "user-token"}},
		"users": {
			"alice.smith@example.org": {"repos": ["gl:g/p"]},
			"alice-smith@example.org": {"repos": ["gl:g/p"]},
			"mallory": {"slug": "alice-smith-example-org", "repos": ["gl:g/p"]}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, nil, nil, nil, secret.Token{})
	seen := map[string]string{}
	subjects := []string{"alice.smith@example.org", "alice-smith@example.org", "mallory",
		strings.Repeat("u", 32) + "-one", strings.Repeat("u", 32) + "-two", "ÄÖÜ", "äöü", "", "x"}
	for _, sub := range subjects {
		p := s.slug(sub)
		if other, dup := seen[p]; dup {
			t.Errorf("%q and %q share slides/%s/", other, sub, p)
		}
		seen[p] = sub
		// Every branch made with the prefix is a valid ref, at its longest too.
		b := remote.BranchName("slides/"+p+"/", strings.Repeat("long title ", 20), time.Now())
		if err := remote.CheckBranch(b); err != nil {
			t.Errorf("%q: branch %q: %v", sub, b, err)
		}
		// A prefix is never a prefix of another's (slides/a/ vs slides/a-b/ is fine,
		// but the directory itself must differ).
		for q := range seen {
			if q != p && strings.HasPrefix(q+"/", p+"/") {
				t.Errorf("prefix %q nests in %q", p, q)
			}
		}
	}
	// Stable: the same subject always gets the same prefix.
	if s.slug("mallory") != s.slug("mallory") || !strings.HasPrefix(s.slug("mallory"), "alice-smith-example-org-") {
		t.Fatalf("configured name kept as the readable part: %q", s.slug("mallory"))
	}
}

func TestDuplicateConfiguredNamesAreRefused(t *testing.T) {
	_, err := ParseConfig([]byte(`{
		"origin": "https://slides.example",
		"master_key_file": "x", "data_dir": "x", "audit_file": "x",
		"forges": {"gl": {"kind": "gitlab", "api": "https://gitlab.example/api/v4", "auth": "user-token"}},
		"users": {
			"a": {"slug": "ada", "repos": ["gl:g/p"]},
			"b": {"slug": "ada", "repos": ["gl:g/p"]}
		}
	}`))
	if err == nil || !strings.Contains(err.Error(), "ada") {
		t.Fatalf("two users with the configured name ada: %v", err)
	}
}
