// Package session keeps gitd's own sessions: each bound to ONE identity (the
// OIDC subject oauth2-proxy vouches for), with its CSRF token.
//
// Identifiers are 32 random bytes the server makes; a client cannot choose one
// (fixation), and a cookie whose session belongs to anyone but the caller is
// not merely refused: the session is destroyed (a stolen cookie dies the
// first time it is presented by the wrong person).
package session

import (
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
}

// Store is an in-memory session store. A restart signs every browser out of
// gitd (not of the IdP): they fetch a new session transparently.
type Store struct {
	mu       sync.Mutex
	byID     map[string]*Session
	Idle     time.Duration // default 30 min
	Absolute time.Duration // default 8 h
	PerUser  int           // most live sessions per subject (default 20)
	Now      func() time.Time
}

// New returns an empty store.
func New() *Store { return &Store{byID: map[string]*Session{}} }

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
		per = 20
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
	var mine []*Session
	for _, x := range s.byID {
		if x.Subject == subject {
			mine = append(mine, x)
		}
	}
	for len(mine) >= per {
		oldest := 0
		for i, x := range mine {
			if x.created.Before(mine[oldest].created) {
				oldest = i
			}
		}
		delete(s.byID, mine[oldest].ID)
		mine = append(mine[:oldest], mine[oldest+1:]...)
	}
	x := &Session{ID: token(), Subject: subject, CSRF: token(), created: now, lastSeen: now}
	s.byID[x.ID] = x
	cp := *x
	return &cp
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
		delete(s.byID, id)
		return nil, ErrNotYours
	}
	idle, abs, _ := s.limits()
	now := s.now()
	if now.Sub(x.lastSeen) > idle || now.Sub(x.created) > abs {
		delete(s.byID, id)
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

// Destroy removes a session.
func (s *Store) Destroy(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

// Len is the number of live sessions (for tests and metrics).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}
