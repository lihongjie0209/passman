package backup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lihongjie0209/passman/internal/store"
)

func TestBackupRoundTrip(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	password := []byte("a sufficiently long password")
	src := store.New(filepath.Join(root, "source"))
	if err := src.Init(password); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "vault.pmbak")
	if err := Create(src, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	identity, vaultData, catalogData, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	dst := store.New(filepath.Join(root, "dest"))
	if err := dst.ValidateCiphertexts(identity, vaultData, password); err != nil {
		t.Fatal(err)
	}
	if err := dst.ReplaceCiphertexts(identity, vaultData); err != nil {
		t.Fatal(err)
	}
	if len(catalogData) == 0 {
		t.Fatal("catalog missing")
	}
	if _, _, err := dst.Unlock(password); err != nil {
		t.Fatal(err)
	}
}
