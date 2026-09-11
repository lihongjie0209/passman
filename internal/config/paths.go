package config

import (
	"fmt"
	"os"
	"path/filepath"
)

type Paths struct{ DataDir, RuntimeDir, Socket string }

func Resolve() (Paths, error) {
	dataDir := os.Getenv("PASSMAN_HOME")
	if dataDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return Paths{}, err
		}
		dataDir = filepath.Join(base, "passman")
	}
	runtimeDir := ""
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		runtimeDir = filepath.Join(xdg, "passman")
	}
	if runtimeDir == "" {
		runtimeDir = filepath.Join(os.TempDir(), fmt.Sprintf("passman-%d", os.Getuid()))
	}
	return Paths{DataDir: dataDir, RuntimeDir: runtimeDir, Socket: filepath.Join(runtimeDir, "daemon.sock")}, nil
}
