// Regression gate for the identity-header ordering of the /api/git/* block
// (go-slides/go-slides.github.io#100, gitd#11). It runs the REAL Caddy on the
// Caddyfile example EXTRACTED from README.md (never copied, so the doc cannot
// drift), with a fake oauth2-proxy on 127.0.0.1:4180 and a fake
// slides-gitd on 127.0.0.1:8091 that echoes the headers it received.
//
// Harness adaptations, and only these: the site address becomes
// http://127.0.0.1:<free port>, a global block turns auto_https and the admin
// endpoint off, and the secret file path points at a temp file.
//
// Without a caddy binary (CADDY_BIN, or caddy on PATH) the tests skip, unless
// REQUIRE_CADDY=1, as in CI, where a skip is a failure.
package caddytest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const secretPath = "/etc/caddy/gitd-proxy.secret"

// loadCaddyfile returns the Caddyfile text and the files it imports.
func loadCaddyfile(t *testing.T) (string, map[string]string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	// the first ```caddyfile block under "### Caddy and oauth2-proxy"
	_, after, ok := strings.Cut(string(b), "### Caddy and oauth2-proxy")
	if !ok {
		t.Fatal(`README.md has no "### Caddy and oauth2-proxy" section`)
	}
	_, after, ok = strings.Cut(after, "```caddyfile\n")
	if !ok {
		t.Fatal("no ```caddyfile block in that section")
	}
	block, _, ok := strings.Cut(after, "\n```")
	if !ok {
		t.Fatal("unterminated ```caddyfile block")
	}
	return block, nil
}

func caddyBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("CADDY_BIN")
	if bin == "" {
		bin, _ = exec.LookPath("caddy")
	}
	if bin == "" {
		if os.Getenv("REQUIRE_CADDY") == "1" {
			t.Fatal("REQUIRE_CADDY=1 but no caddy binary (CADDY_BIN or PATH)")
		}
		t.Skip("no caddy binary (set CADDY_BIN or put caddy on PATH); CI installs v2.11.7 and sets REQUIRE_CADDY=1")
	}
	return bin
}

var siteLine = regexp.MustCompile(`(?m)^slides\.example\.org \{`)

// adapt writes the adapted Caddyfile into a temp dir and returns its path.
func adapt(t *testing.T, port int) (string, string) {
	t.Helper()
	text, extra := loadCaddyfile(t)
	if !strings.Contains(text, secretPath) {
		t.Fatalf("the Caddyfile no longer names %s", secretPath)
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "gitd-proxy.secret")
	if err := os.WriteFile(secret, []byte("s3cret-from-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	text = strings.ReplaceAll(text, secretPath, secret)
	if n := len(siteLine.FindAllString(text, -1)); n != 1 {
		t.Fatalf("want one slides.example.org site block, found %d", n)
	}
	text = siteLine.ReplaceAllString(text, fmt.Sprintf("http://127.0.0.1:%d {", port))
	text = "{\n\tauto_https off\n\tadmin off\n}\n" + text
	for name, body := range extra {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cf := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cf, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return cf, secret
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type fakes struct {
	mu       sync.Mutex
	upstream []http.Header // what the fake slides-gitd received
}

func (f *fakes) upstreamHits() []http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]http.Header(nil), f.upstream...)
}

func listen(t *testing.T, addr string, h http.Handler) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("%s is needed by the test: %v", addr, err)
	}
	s := &http.Server{Handler: h}
	go s.Serve(l)
	t.Cleanup(func() { s.Close() })
}

func startFakes(t *testing.T) *fakes {
	f := &fakes{}
	// oauth2-proxy's /oauth2/auth: 202 plus the identity when signed in.
	listen(t, "127.0.0.1:4180", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Signed-In") == "1" {
			w.Header().Set("X-Auth-Request-User", "sub-real")
			w.Header().Set("X-Auth-Request-Email", "real@example.org")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	// slides-gitd: echoes the request headers it got.
	listen(t, "127.0.0.1:8091", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.upstream = append(f.upstream, r.Header.Clone())
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(r.Header)
	}))
	return f
}

func startCaddy(t *testing.T) (*fakes, string, string) {
	bin := caddyBin(t)
	f := startFakes(t)
	port := freePort(t)
	cf, secret := adapt(t, port)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "run", "--adapter", "caddyfile", "--config", cf)
	home := t.TempDir()
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+home, "XDG_CONFIG_HOME="+home, "HOME="+home)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); cmd.Wait() })
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("caddy did not listen on %s:\n%s", addr, out.String())
		}
	}
	return f, "http://" + addr, secret
}

func get(t *testing.T, base string, h map[string]string) (int, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/api/git/session", nil)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header
}

// A client-sent identity with no sign-in is refused, and never reaches slides-gitd.
func TestForgedIdentityWithoutSignInIs401(t *testing.T) {
	f, base, _ := startCaddy(t)
	code, _ := get(t, base, map[string]string{"X-Auth-Request-User": "sub-evil"})
	if code != 401 {
		t.Fatalf("status %d, want 401", code)
	}
	if n := len(f.upstreamHits()); n != 0 {
		t.Fatalf("upstream reached %d times, want 0", n)
	}
}

// The signed-in call carries the authenticated identity, once, and the secret
// from the file; the forged values never get through.
func TestSignedInIdentityReachesUpstreamForgeriesDoNot(t *testing.T) {
	f, base, _ := startCaddy(t)
	code, _ := get(t, base, map[string]string{
		"X-Test-Signed-In":     "1",
		"X-Auth-Request-User":  "sub-evil",
		"X-Auth-Request-Email": "evil@example.org",
		"X-Gitd-Proxy-Secret":  "forged",
	})
	if code != 200 {
		t.Fatalf("status %d, want 200", code)
	}
	hits := f.upstreamHits()
	if len(hits) != 1 {
		t.Fatalf("upstream hits %d, want 1", len(hits))
	}
	h := hits[0]
	if got := h.Values("X-Auth-Request-User"); len(got) != 1 || got[0] != "sub-real" {
		t.Errorf("X-Auth-Request-User = %q, want exactly [sub-real]", got)
	}
	if got := h.Values("X-Auth-Request-Email"); len(got) != 1 || got[0] != "real@example.org" {
		t.Errorf("X-Auth-Request-Email = %q, want exactly [real@example.org]", got)
	}
	if got := h.Values("X-Gitd-Proxy-Secret"); len(got) != 1 || got[0] != "s3cret-from-file" {
		t.Errorf("X-Gitd-Proxy-Secret = %q, want exactly the file's content", got)
	}
}

// walk lists, in written order, the identity-header deletions ("del:<Name>")
// and the forward_auth call ("forward_auth": a reverse_proxy to :4180 that has
// handle_response). It does not enter a reverse_proxy, whose handle_response
// holds forward_auth's own copy_headers.
func walk(v any, ev *[]string) {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			walk(e, ev)
		}
	case map[string]any:
		switch x["handler"] {
		case "headers":
			if req, ok := x["request"].(map[string]any); ok {
				if del, ok := req["delete"].([]any); ok {
					for _, d := range del {
						*ev = append(*ev, fmt.Sprintf("del:%v", d))
					}
				}
			}
			return
		case "reverse_proxy":
			if _, ok := x["handle_response"]; ok && strings.Contains(fmt.Sprint(x["upstreams"]), "4180") {
				*ev = append(*ev, "forward_auth")
			} else if strings.Contains(fmt.Sprint(x["upstreams"]), "8091") {
				*ev = append(*ev, "upstream")
			}
			return
		}
		// object keys in JSON are unordered: only "routes", "handle" and
		// "handler" lists carry order, and each is walked as a list.
		for _, k := range []string{"routes", "handle"} {
			if c, ok := x[k]; ok {
				walk(c, ev)
			}
		}
		for k, c := range x {
			if k != "routes" && k != "handle" {
				walk(c, ev)
			}
		}
	}
}

// The issue's check: the stripping handlers come BEFORE forward_auth, which
// comes before the proxy to slides-gitd.
func TestAdaptedHandlerOrder(t *testing.T) {
	bin := caddyBin(t)
	cf, _ := adapt(t, 8080)
	out, err := exec.Command(bin, "adapt", "--adapter", "caddyfile", "--config", cf).Output()
	if err != nil {
		t.Fatalf("caddy adapt: %v", err)
	}
	var doc any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var ev []string
	walk(doc, &ev)
	pos := map[string]int{}
	for i, e := range ev {
		if _, ok := pos[e]; !ok {
			pos[e] = i
		}
	}
	for _, name := range []string{"del:X-Auth-Request-User", "del:X-Auth-Request-Email", "del:X-Gitd-Proxy-Secret", "forward_auth", "upstream"} {
		if _, ok := pos[name]; !ok {
			t.Fatalf("%s missing from the adapted config; events: %v", name, ev)
		}
	}
	for _, d := range []string{"del:X-Auth-Request-User", "del:X-Auth-Request-Email", "del:X-Gitd-Proxy-Secret"} {
		if pos[d] > pos["forward_auth"] {
			t.Errorf("%s comes after forward_auth: the identity forward_auth copies is deleted; events: %v", d, ev)
		}
	}
	if pos["forward_auth"] > pos["upstream"] {
		t.Errorf("forward_auth after the upstream proxy; events: %v", ev)
	}
}
