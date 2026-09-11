package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRoundTripAndPasswordChange(t *testing.T) {
	t.Parallel()
	s := New(filepath.Join(t.TempDir(), "vault"))
	old := []byte("a sufficiently long password")
	next := []byte("another sufficiently long password")
	if err := s.Init(old); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{s.IdentityPath(), s.VaultPath()} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", path, info.Mode().Perm())
		}
	}
	id, data, err := s.Unlock(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := data.Set("api#token", []byte("token-value")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(data, id.Recipient()); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(old, next); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Unlock(old); err == nil {
		t.Fatal("old password still works")
	}
	_, data, err = s.Unlock(next)
	if err != nil {
		t.Fatal(err)
	}
	got, err := data.Get("api#token")
	if err != nil || string(got) != "token-value" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestStoreRejectsLoosePermissions(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "vault")
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // deliberately insecure permissions exercise fail-closed validation.
		t.Fatal(err)
	}
	s := New(dir)
	if err := s.Init([]byte("a sufficiently long password")); err == nil {
		t.Fatal("expected permission error")
	}
}
