package session

import (
	"fmt"
	"testing"
	"time"
)

// go-slides/gitd#6: the store has an overall cap, and expired sessions that
// are never presented again are swept.

func TestTheStoreHasAnOverallCap(t *testing.T) {
	now := time.Now()
	s := New()
	s.Now = func() time.Time { return now }
	s.Max = 100
	var first string
	for i := 0; i < 150; i++ {
		now = now.Add(time.Millisecond)
		x := s.Create(fmt.Sprintf("user-%d", i))
		if i == 0 {
			first = x.ID
		}
	}
	if s.Len() > 100 {
		t.Fatalf("%d sessions, cap 100", s.Len())
	}
	if _, err := s.Get(first, "user-0"); err == nil {
		t.Fatal("the oldest session must be the one dropped")
	}
	if _, err := s.Get(s.Create("newest").ID, "newest"); err != nil {
		t.Fatal("the newest session must survive")
	}
}

func TestSweepRemovesExpiredSessionsNobodyPresents(t *testing.T) {
	now := time.Now()
	s := New()
	s.Now = func() time.Time { return now }
	for i := 0; i < 10; i++ {
		s.Create(fmt.Sprintf("u%d", i))
	}
	now = now.Add(10 * time.Minute)
	live := s.Create("still-here")
	now = now.Add(25 * time.Minute) // the first ten are idle past 30 min
	if n := s.Sweep(); n != 10 || s.Len() != 1 {
		t.Fatalf("swept %d, %d left", n, s.Len())
	}
	if _, err := s.Get(live.ID, "still-here"); err != nil {
		t.Fatal("a live session must not be swept")
	}
}
