package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogAppendAndVerify(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	log := New(dir)
	if err := log.Append("run", []string{"service#token"}, "client"); err != nil {
		t.Fatal(err)
	}
	if err := log.Append("reveal", []string{"service#password"}, ""); err != nil {
		t.Fatal(err)
	}
	events, err := log.ReadAndVerify()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].PrevHash != events[0].Hash {
		t.Fatalf("unexpected events: %#v", events)
	}
}

func TestLogRejectsTampering(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	log := New(dir)
	if err := log.Append("run", []string{"service#token"}, "client"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, fileName)
	b, err := os.ReadFile(path) // #nosec G304 -- test path is rooted in t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 1
	if err := os.WriteFile(path, b, 0o600); err != nil { // #nosec G703 -- test path is rooted in t.TempDir.
		t.Fatal(err)
	}
	if _, err := log.ReadAndVerify(); err == nil {
		t.Fatal("expected tamper detection")
	}
	if err := log.Append("run", nil, "client"); err == nil {
		t.Fatal("expected fail-closed append")
	}
}
