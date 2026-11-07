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
	if _, err := Open(filepath.Join(p, "nope")); err == nil {
		t.Fatal("a bad path")
	}
}
