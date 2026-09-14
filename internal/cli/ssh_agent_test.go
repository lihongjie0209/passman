package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupSSHConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(sshDir, "config")
	original := []byte("Host example\n    HostName example.test\n")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(home, ".config", "passman", "ssh-agent.sock")
	if err := setupSSHConfig(socket); err != nil {
		t.Fatal(err)
	}
	if err := setupSSHConfig(socket); err != nil {
		t.Fatalf("setup is not idempotent: %v", err)
	}
	config, err := os.ReadFile(configPath) // #nosec G304 -- test path is rooted in t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(config), "Include ~/.ssh/passman-agent.conf") != 1 || !strings.HasSuffix(string(config), string(original)) {
		t.Fatalf("unexpected SSH config: %q", config)
	}
	managed, err := os.ReadFile(filepath.Join(sshDir, "passman-agent.conf")) // #nosec G304 -- test path is rooted in t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(managed), `IdentityAgent "`+socket+`"`) {
		t.Fatalf("unexpected managed config: %q", managed)
	}
	for _, path := range []string{configPath, filepath.Join(sshDir, "passman-agent.conf")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", path, info.Mode().Perm())
		}
	}
}
