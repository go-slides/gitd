package session

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSessionsAreBoundToOneIdentity(t *testing.T) {
	s := New()
	a := s.Create("alice")
	if len(a.ID) != 43 || len(a.CSRF) != 43 || a.ID == a.CSRF {
		t.Fatalf("session %+v", a)
	}
	if got, err := s.Get(a.ID, "alice"); err != nil || got.Subject != "alice" {
		t.Fatal(err)
	}
	// Bob presents Alice's cookie: refused, and Alice's session is gone.
	if _, err := s.Get(a.ID, "bob"); !errors.Is(err, ErrNotYours) {
		t.Fatal(err)
	}
	if _, err := s.Get(a.ID, "alice"); !errors.Is(err, ErrNone) {
		t.Fatal("a session presented by the wrong identity must die")
	}
	// An id the server never made (fixation, guessing).
	for _, id := range []string{"", "x", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, err := s.Get(id, "alice"); !errors.Is(err, ErrNone) {
			t.Fatalf("%q: %v", id, err)
		}
	}
}

func TestCSRF(t *testing.T) {
	s := New()
	a := s.Create("alice")
	b := s.Create("bob")
	if CheckCSRF(a, a.CSRF) != nil {
		t.Fatal("own token")
	}
	for _, p := range []string{"", b.CSRF, a.ID, a.CSRF + "x"} {
		if !errors.Is(CheckCSRF(a, p), ErrCSRF) {
			t.Fatalf("%q accepted", p)
		}
	}
	if !errors.Is(CheckCSRF(nil, "x"), ErrCSRF) {
		t.Fatal("nil session")
	}
}

func TestExpiryAndBounds(t *testing.T) {
	now := time.Now()
	s := New()
	s.Now = func() time.Time { return now }
	s.PerUser = 3
	var ids []string
	for i := 0; i < 5; i++ {
		now = now.Add(time.Second)
		ids = append(ids, s.Create("alice").ID)
	}
	if s.Len() != 3 {
		t.Fatalf("%d sessions, bound 3", s.Len())
	}
	if _, err := s.Get(ids[0], "alice"); !errors.Is(err, ErrNone) {
		t.Fatal("the oldest must be dropped")
	}
	now = now.Add(31 * time.Minute)
	if _, err := s.Get(ids[4], "alice"); !errors.Is(err, ErrExpired) {
		t.Fatal("idle expiry")
	}
	s2 := New()
	s2.Now = func() time.Time { return now }
	x := s2.Create("alice")
	for i := 0; i < 20; i++ { // kept busy, still bounded in age
		now = now.Add(25 * time.Minute)
		if _, err := s2.Get(x.ID, "alice"); err != nil {
			break
		}
	}
	if _, err := s2.Get(x.ID, "alice"); err == nil {
		t.Fatal("absolute expiry")
	}
	s2.Destroy("nothing")
}

func TestConcurrentUsers(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	for i := 0; i < 2*8; i++ { // within the per-user bound: none is evicted
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			who := []string{"alice", "bob"}[i%2]
			x := s.Create(who)
			got, err := s.Get(x.ID, who)
			if err != nil || got.Subject != who {
				t.Errorf("%s got %+v %v", who, got, err)
			}
		}(i)
	}
	wg.Wait()
}
