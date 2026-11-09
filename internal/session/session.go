// Package session keeps gitd's own sessions: each bound to ONE identity (the
// OIDC subject oauth2-proxy vouches for), with its CSRF token.
//
// Identifiers are 32 random bytes the server makes; a client cannot choose one
// (fixation), and a cookie whose session belongs to anyone but the caller is
// not merely refused: the session is destroyed (a stolen cookie dies the
// first time it is presented by the wrong person).
package session

import (
	"container/list"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Errors.
var (
	ErrNone     = errors.New("session: none")
	ErrExpired  = errors.New("session: expired")
	ErrNotYours = errors.New("session: belongs to another identity")
	ErrCSRF     = errors.New("session: CSRF token mismatch")
)

// Session is one browser's session.
type Session struct {
	ID       string
	Subject  string
	CSRF     string
	created  time.Time
	lastSeen time.Time

	elAll, elMine *list.Element // positions in the store's two creation-order lists
}

// Store is an in-memory session store. A restart signs every browser out of
// gitd (not of the IdP): they fetch a new session transparently.
type Store struct {
	mu        sync.Mutex
	byID      map[string]*Session
	all       *list.List            // every session, oldest created at the front
	bySubject map[string]*list.List // each subject's sessions, same order
	steps     int                   // sessions evicted by Create (a test counter: O(1) each)
	Idle      time.Duration         // default 30 min
	Absolute  time.Duration         // default 8 h
	PerUser   int                   // most live sessions per subject (default 8; #8)
	Max       int                   // most live sessions in all (default 100000; #6)
	Now       func() time.Time
}

// New returns an empty store.
func New() *Store {
	return &Store{byID: map[string]*Session{}, all: list.New(), bySubject: map[string]*list.List{}}
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("session: no randomness: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) limits() (time.Duration, time.Duration, int) {
	idle, abs, per := s.Idle, s.Absolute, s.PerUser
	if idle <= 0 {
		idle = 30 * time.Minute
	}
	if abs <= 0 {
		abs = 8 * time.Hour
	}
	if per <= 0 {
		per = 8
	}
	return idle, abs, per
}

// Create makes a fresh session for subject, dropping the oldest of its
// sessions beyond the per-user bound.
func (s *Store) Create(subject string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _, per := s.limits()
	now := s.now()
	// go-slides/gitd#8: a subject over its own bound loses ITS oldest session
	// (never another subject's), and the overall cap drops the globally
	// oldest: both are the front of a list kept in creation order, O(1).
	mine := s.bySubject[subject]
	for mine != nil && mine.Len() >= per {
		s.steps++
		s.removeLocked(mine.Front().Value.(*Session))
	}
	max := s.Max
	if max <= 0 {
		max = 100000
	}
	for len(s.byID) >= max {
		s.steps++
		s.removeLocked(s.all.Front().Value.(*Session))
	}
	x := &Session{ID: token(), Subject: subject, CSRF: token(), created: now, lastSeen: now}
	s.byID[x.ID] = x
	x.elAll = s.all.PushBack(x)
	if s.bySubject[subject] == nil {
		s.bySubject[subject] = list.New()
	}
	x.elMine = s.bySubject[subject].PushBack(x)
	cp := *x
	cp.elAll, cp.elMine = nil, nil
	return &cp
}

// removeLocked drops x from the map and both lists.
func (s *Store) removeLocked(x *Session) {
	delete(s.byID, x.ID)
	s.all.Remove(x.elAll)
	if l := s.bySubject[x.Subject]; l != nil {
		l.Remove(x.elMine)
		if l.Len() == 0 {
			delete(s.bySubject, x.Subject)
		}
	}
}

// Get returns the session id for subject. A session of another subject is
// destroyed and refused; an expired one is destroyed.
func (s *Store) Get(id, subject string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.byID[id]
	if !ok || id == "" {
		return nil, ErrNone
	}
	if subtle.ConstantTimeCompare([]byte(x.Subject), []byte(subject)) != 1 {
		s.removeLocked(x)
		return nil, ErrNotYours
	}
	idle, abs, _ := s.limits()
	now := s.now()
	if now.Sub(x.lastSeen) > idle || now.Sub(x.created) > abs {
		s.removeLocked(x)
		return nil, ErrExpired
	}
	x.lastSeen = now
	cp := *x
	return &cp, nil
}

// CheckCSRF compares a presented token with the session's, in constant time.
func CheckCSRF(x *Session, presented string) error {
	if x == nil || presented == "" || subtle.ConstantTimeCompare([]byte(x.CSRF), []byte(presented)) != 1 {
		return ErrCSRF
	}
	return nil
}

// Sweep removes every expired session, presented again or not, and returns
// how many went. serve runs it periodically.
func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(s.now())
}

func (s *Store) sweepLocked(now time.Time) int {
	idle, abs, _ := s.limits()
	n := 0
	for _, x := range s.byID {
		if now.Sub(x.lastSeen) > idle || now.Sub(x.created) > abs {
			s.removeLocked(x)
			n++
		}
	}
	return n
}

// Destroy removes a session.
func (s *Store) Destroy(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x, ok := s.byID[id]; ok {
		s.removeLocked(x)
	}
}

// Len is the number of live sessions (for tests and metrics).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}
