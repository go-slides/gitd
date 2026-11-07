package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixture writes a configuration with its secret files and returns its path.
func fixture(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "master.key")
	_ = os.WriteFile(key, []byte(strings.Repeat("ab", 32)), mode)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	app := filepath.Join(dir, "app.pem")
	_ = os.WriteFile(app, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)}), 0o600)
	ps := filepath.Join(dir, "proxy.secret")
	_ = os.WriteFile(ps, []byte("PROXY-SECRET-PLACEHOLDER\n"), 0o600)
	cfg := `{"listen":"127.0.0.1:0","origin":"https://slides.example",
		"master_key_file":"` + key + `","data_dir":"` + filepath.Join(dir, "data") + `","audit_file":"` + filepath.Join(dir, "audit.log") + `",
		"proxy_secret_file":"` + ps + `",
		"forges":{"github":{"kind":"github","api":"https://api.github.com","auth":"github-app","app_client_id":"Iv1.x","installation_id":7,"app_key_file":"` + app + `"},
		          "gitlab":{"kind":"gitlab","api":"https://gitlab.com/api/v4","auth":"user-token"}},
		"users":{"alice":{"repos":["github:o/deck","gitlab:g/sub/p"]}}}`
	p := filepath.Join(dir, "config.json")
	_ = os.WriteFile(p, []byte(cfg), 0o600)
	return p
}

func TestCheck(t *testing.T) {
	var out bytes.Buffer
	cmd := RootCmd()
	cmd.SetArgs([]string{"check", "--config", fixture(t, 0o600)})
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil || !strings.Contains(out.String(), "ok: 2 forges, 1 users") {
		t.Fatalf("%v %s", err, out.String())
	}
}

func TestSecretsComeFromPrivateFilesOnly(t *testing.T) {
	cmd := RootCmd()
	cmd.SetArgs([]string{"check", "--config", fixture(t, 0o644)})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("a world-readable master key must be refused")
	}
	// No flag takes a secret, and nothing reads one from the environment.
	for _, c := range RootCmd().Commands() {
		for _, name := range []string{"token", "key", "secret", "password"} {
			if c.Flags().Lookup(name) != nil {
				t.Fatalf("%s has a --%s flag", c.Name(), name)
			}
		}
	}
	src, _ := os.ReadFile("main.go")
	if bytes.Contains(src, []byte("os.Getenv")) || bytes.Contains(src, []byte("LookupEnv")) {
		t.Fatal("main reads the environment")
	}
	// A secret pasted into the configuration is an unknown field: refused.
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	_ = os.WriteFile(p, []byte(`{"origin":"https://x.example","master_key_file":"a","data_dir":"b","audit_file":"c","token":"x"}`), 0o600)
	cmd = RootCmd()
	cmd.SetArgs([]string{"check", "--config", p})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("an unknown field must be refused")
	}
}

func TestServeStopsOnCancel(t *testing.T) {
	srv, cfg, err := Build(fixture(t, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- run(ctx, &bytes.Buffer{}, srv, cfg) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop")
	}
}
