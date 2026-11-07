// Package audit appends one JSON line per action: who, what, where, the
// outcome. Never a file's content, never a token, never an error's text (only
// its class): the record is safe to ship to a log system.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
	"unicode/utf8"
)

// Entry is one action.
type Entry struct {
	Time    time.Time `json:"time"`
	Subject string    `json:"subject"`
	Action  string    `json:"action"`
	Forge   string    `json:"forge,omitempty"`
	Repo    string    `json:"repo,omitempty"`
	Branch  string    `json:"branch,omitempty"`
	Files   int       `json:"files,omitempty"`
	Outcome string    `json:"outcome"` // ok, denied, error class
	Remote  string    `json:"remote,omitempty"`
}

// Log is an append-only log.
type Log struct {
	mu sync.Mutex
	w  io.Writer
}

// Open appends to path (created 0600).
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{w: f}, nil
}

// To writes to w (tests).
func To(w io.Writer) *Log { return &Log{w: w} }

// MaxField bounds every text field of an entry, so a line stays under 2 KiB
// whatever a caller passes in (go-slides/gitd#2).
const MaxField = 256

func bound(s string) string {
	if len(s) <= MaxField {
		return s
	}
	cut := MaxField
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// Write appends e.
func (l *Log) Write(e Entry) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	for _, f := range []*string{&e.Subject, &e.Action, &e.Forge, &e.Repo, &e.Branch, &e.Outcome, &e.Remote} {
		*f = bound(*f)
	}
	b, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}
