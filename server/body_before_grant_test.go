package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// go-slides/gitd#8: an ungranted subject's body is refused without being read.

type countingBody struct{ n, left int }

func (c *countingBody) Read(p []byte) (int, error) {
	if c.left == 0 {
		return 0, io.EOF
	}
	k := min(len(p), c.left)
	for i := 0; i < k; i++ {
		p[i] = ' '
	}
	c.left -= k
	c.n += k
	return k, nil
}

func (hh *harness) postRaw(c client, path string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, body)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Auth-Request-User", c.subject)
	r.Header.Set("Origin", origin)
	r.Header.Set("X-Requested-With", "slides-gitd")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", c.csrf)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: c.cookie})
	return hh.do(r)
}

func TestAnUngrantedSubjectsBodyIsNotRead(t *testing.T) {
	hh := newHarness(t)
	m := hh.login("mallory") // no grant at all
	for _, p := range []string{"/api/git/load", "/api/git/propose", "/api/git/refresh", "/api/git/credential", "/api/git/credential/delete"} {
		b := &countingBody{left: 10 << 20}
		w := hh.postRaw(m, p, b)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "denied") {
			t.Errorf("%s: %d %s", p, w.Code, w.Body)
		}
		if b.n > 0 {
			t.Errorf("%s: %d bytes of an ungranted subject's body were read", p, b.n)
		}
	}
	if !strings.Contains(hh.logText(), `"outcome":"denied"`) {
		t.Fatal("the refusal must be audited")
	}
}

func TestAGrantedSubjectsSmallRequestsAreBoundedSmall(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	for _, p := range []string{"/api/git/load", "/api/git/refresh", "/api/git/credential"} {
		b := &countingBody{left: 10 << 20}
		hh.postRaw(a, p, b)
		if b.n > 64<<10 {
			t.Errorf("%s: read %d bytes", p, b.n)
		}
	}
}
