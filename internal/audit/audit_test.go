package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendOneLinePerEntry(t *testing.T) {
	var b bytes.Buffer
	l := To(&b)
	l.Write(Entry{Subject: "alice", Action: "load", Outcome: "ok"})
	l.Write(Entry{Subject: "bob", Action: "propose", Outcome: "denied"})
	var nilLog *Log
	nilLog.Write(Entry{})
	lines := bytes.Split(bytes.TrimSpace(b.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	var e Entry
	if err := json.Unmarshal(lines[1], &e); err != nil || e.Subject != "bob" || e.Time.IsZero() {
		t.Fatalf("%+v %v", e, err)
	}
	p := filepath.Join(t.TempDir(), "audit.log")
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(Entry{Action: "x"})
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	// every field is bounded, so a line is too, and a cut never splits a rune
	var big bytes.Buffer
	To(&big).Write(Entry{Subject: string(bytes.Repeat([]byte("é"), 5000)), Repo: string(bytes.Repeat([]byte("r"), 1<<20)), Remote: string(bytes.Repeat([]byte("1"), 1<<16))})
	if big.Len() > 2048 || !json.Valid(bytes.TrimSpace(big.Bytes())) {
		t.Fatalf("an entry of huge fields wrote %d bytes", big.Len())
	}
	if _, err := Open(filepath.Join(p, "nope")); err == nil {
		t.Fatal("a bad path")
	}
}
