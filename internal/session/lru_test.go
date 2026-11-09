package session

import (
	"fmt"
	"testing"
	"time"
)

// go-slides/gitd#8: one subject cannot push another out, and eviction at the
// cap is O(1) (the front of a list), not a scan of the store.

func TestOneSubjectNeverEvictsAnotherSubjectsSessions(t *testing.T) {
	now := time.Now()
	s := New()
	s.Now = func() time.Time { return now }
	victim := s.Create("victim")
	var first *Session
	for i := 0; i < 50; i++ {
		now = now.Add(time.Millisecond)
		x := s.Create("attacker")
		if i == 0 {
			first = x
		}
	}
	if _, err := s.Get(victim.ID, "victim"); err != nil {
		t.Fatalf("the victim lost a session to another subject: %v", err)
	}
	if got := s.bySubject["attacker"].Len(); got != 8 {
		t.Fatalf("the attacker holds %d sessions, want the default bound of 8", got)
	}
	if _, err := s.Get(first.ID, "attacker"); err == nil {
		t.Fatal("the attacker's OLDEST session must be the one dropped")
	}
	if s.Len() != 9 || s.all.Len() != 9 {
		t.Fatalf("%d in the map, %d in the list", s.Len(), s.all.Len())
	}
}

func TestTheNinthSessionDropsOnlyThatSubjectsOldest(t *testing.T) {
	now := time.Now()
	s := New()
	s.Now = func() time.Time { return now }
	var ids []string
	for i := 0; i < 8; i++ {
		now = now.Add(time.Millisecond)
		ids = append(ids, s.Create("u").ID)
		now = now.Add(time.Millisecond)
		s.Create(fmt.Sprintf("other-%d", i))
	}
	now = now.Add(time.Millisecond)
	s.Create("u")
	if _, err := s.Get(ids[0], "u"); err == nil {
		t.Fatal("the oldest of u must go")
	}
	for _, id := range ids[1:] {
		if _, err := s.Get(id, "u"); err != nil {
			t.Fatal("only the oldest may go")
		}
	}
	if s.Len() != 8+8 {
		t.Fatalf("%d sessions: another subject lost one", s.Len())
	}
}

func TestGlobalEvictionIsOneStepAndTakesTheGloballyOldest(t *testing.T) {
	now := time.Now()
	s := New()
	s.Now = func() time.Time { return now }
	s.Max = 1000
	var ids []string
	for i := 0; i < 1000; i++ {
		now = now.Add(time.Millisecond)
		ids = append(ids, s.Create(fmt.Sprintf("u%d", i)).ID)
	}
	s.steps = 0
	for i := 0; i < 200; i++ {
		now = now.Add(time.Millisecond)
		s.Create(fmt.Sprintf("n%d", i))
	}
	if s.steps != 200 {
		t.Fatalf("%d evictions for 200 creations at the cap: want exactly one each, no scan", s.steps)
	}
	if s.Len() != 1000 {
		t.Fatalf("%d sessions, cap 1000", s.Len())
	}
	for i, id := range ids {
		_, err := s.Get(id, fmt.Sprintf("u%d", i))
		if (i < 200) != (err != nil) {
			t.Fatalf("session %d: err %v; exactly the 200 oldest must be gone", i, err)
		}
	}
}

func TestSweepKeepsTheListsInStep(t *testing.T) {
	now := time.Now()
	s := New()
	s.Now = func() time.Time { return now }
	for i := 0; i < 20; i++ {
		s.Create(fmt.Sprintf("u%d", i%4))
	}
	now = now.Add(time.Hour)
	s.Create("fresh")
	if n := s.Sweep(); n != 20 {
		t.Fatalf("swept %d", n)
	}
	if s.all.Len() != 1 || len(s.bySubject) != 1 || s.Len() != 1 {
		t.Fatalf("lists out of step: %d, %d, %d", s.all.Len(), len(s.bySubject), s.Len())
	}
}
