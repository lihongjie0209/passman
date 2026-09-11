package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/lihongjie0209/passman/internal/platform"
)

func StartBackground(ctx context.Context, socket string) error {
	if conn, err := netDial(socket); err == nil {
		_ = conn.Close()
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = null.Close() }()
	cmd := exec.Command(exe, "daemon", "serve") // #nosec G204 -- exe is the current signed/installed passman executable.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, null, null
	platform.Detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := netDial(socket); err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	return errors.New("daemon did not start")
}
