package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-browserhttp/browsergit/remote"
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

func TestAGrantedSubjectsGarbageIsBounded(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	for p, max := range map[string]int{"/api/git/load": listBodyBytes, "/api/git/refresh": listBodyBytes, "/api/git/credential": 8 << 10, "/api/git/propose": 64 << 20} {
		b := &countingBody{left: 100 << 20}
		hh.postRaw(a, p, b)
		if b.n > max+(64<<10) {
			t.Errorf("%s: read %d bytes", p, b.n)
		}
	}
}

// go-slides/gitd#14: a refresh carries one blob id per file.
func refreshBody(t *testing.T, repo string, files int) []byte {
	t.Helper()
	b := remote.Base{Forge: "gitlab", Repo: repo, Ref: "main", Commit: strings.Repeat("a", 40), Blobs: map[string]string{}}
	for i := 0; i < files; i++ {
		b.Blobs[fmt.Sprintf("talk/media/figure-%04d.png", i)] = strings.Repeat("b", 40)
	}
	out, err := json.Marshal(refreshReq{Forge: "gitlab", Base: b})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAGrantedSubjectCanRefreshALargeDeck(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	for _, n := range []int{10, 60, 500, 5000} {
		w := hh.postRaw(a, "/api/git/refresh", bytes.NewReader(refreshBody(t, "g/p", n)))
		if w.Code != http.StatusOK {
			t.Errorf("refresh of %d files: %d %s", n, w.Code, w.Body)
		}
	}
	// a load whose grant fields are first, then a long dir
	lb, _ := json.Marshal(loadReq{Forge: "gitlab", Repo: "g/p", Ref: "main", Dir: strings.Repeat("d/", 5000)})
	if w := hh.postRaw(a, "/api/git/load", bytes.NewReader(lb)); w.Code != http.StatusOK {
		t.Errorf("load with a 10 KB dir: %d %s", w.Code, w.Body)
	}
}

func TestAnUngrantedSubjectsLargeBodyIsReadOnlyToTheSmallBound(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice") // granted g/p only
	head := `{"forge":"gitlab","base":{"repo":"g/other","blobs":{"x":"`
	for p, h := range map[string]string{
		"/api/git/refresh": head,
		"/api/git/propose": head,
		"/api/git/load":    `{"forge":"gitlab","repo":"g/other","ref":"`,
	} {
		b := &countingBody{left: 10 << 20}
		w := hh.postRaw(a, p, io.MultiReader(strings.NewReader(h), b))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "denied") {
			t.Errorf("%s: %d %s", p, w.Code, w.Body)
		}
		if b.n+len(h) > smallBodyBytes+4096 {
			t.Errorf("%s: %d bytes read", p, b.n+len(h))
		}
	}
}

func TestAGrantedSubjectsOversizedBodyIsStillRefused(t *testing.T) {
	hh := newHarness(t)
	a := hh.login("alice")
	head := `{"forge":"gitlab","base":{"repo":"g/p","blobs":{"x":"`
	b := &countingBody{left: 10 << 20}
	w := hh.postRaw(a, "/api/git/refresh", io.MultiReader(strings.NewReader(head), b))
	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized refresh: %d %s", w.Code, w.Body)
	}
}
