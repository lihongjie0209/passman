package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/lihongjie0209/passman/internal/redact"
)

type ExitError struct{ Code int }

func (e *ExitError) Error() string { return "child process exited with status " + strconv.Itoa(e.Code) }

type Options struct {
	Env    map[string][]byte
	Stdin  []byte
	Files  map[string][]byte
	Args   []string
	Stdout io.Writer
	Stderr io.Writer
}

func Run(ctx context.Context, opts Options) error {
	if len(opts.Args) == 0 {
		return errors.New("missing program after --")
	}
	tmpDir := ""
	filePaths := make(map[string]string)
	if len(opts.Files) > 0 {
		var err error
		tmpDir, err = os.MkdirTemp("", "passman-run-*")
		if err != nil {
			return fmt.Errorf("creating private temporary directory: %w", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()
		// #nosec G302 -- directories require execute permission; 0700 is owner-only.
		if err := os.Chmod(tmpDir, 0o700); err != nil {
			return err
		}
		for name, value := range opts.Files {
			path := filepath.Join(tmpDir, name)
			if err := os.WriteFile(path, value, 0o600); err != nil {
				return fmt.Errorf("creating injected file: %w", err)
			}
			filePaths[name] = path
		}
	}
	args := append([]string(nil), opts.Args...)
	for i := range args {
		for name, path := range filePaths {
			args[i] = strings.ReplaceAll(args[i], "{file:"+name+"}", path)
		}
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...) // #nosec G204 -- arbitrary direct execution is the documented run contract; no shell is implicit.
	cmd.Env = filteredEnvironment(opts.Env)
	for name, value := range opts.Env {
		if bytes.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("secret for environment variable %s contains NUL", name)
		}
		cmd.Env = append(cmd.Env, name+"="+string(value))
	}
	defer func() { cmd.Env = nil }()
	if opts.Stdin != nil {
		cmd.Stdin = bytes.NewReader(opts.Stdin)
	} else {
		cmd.Stdin = os.Stdin
	}
	secrets := make([][]byte, 0, len(opts.Env)+len(opts.Files)+1)
	for _, v := range opts.Env {
		secrets = append(secrets, v)
	}
	for _, v := range opts.Files {
		secrets = append(secrets, v)
	}
	if opts.Stdin != nil {
		secrets = append(secrets, opts.Stdin)
	}
	out := redact.New(opts.Stdout, secrets)
	errOut := redact.New(opts.Stderr, secrets)
	cmd.Stdout, cmd.Stderr = out, errOut
	err := cmd.Run()
	closeErr := errors.Join(out.Close(), errOut.Close())
	if err == nil {
		return closeErr
	}
	var execErr *exec.ExitError
	if errors.As(err, &execErr) {
		if status, ok := execErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return &ExitError{Code: 128 + int(status.Signal())}
			}
			return &ExitError{Code: status.ExitStatus()}
		}
	}
	if errors.Is(err, exec.ErrNotFound) {
		return &ExitError{Code: 127}
	}
	if errors.Is(err, os.ErrPermission) {
		return &ExitError{Code: 126}
	}
	return fmt.Errorf("starting child process: %w", err)
}

func filteredEnvironment(overrides map[string][]byte) []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+len(overrides))
	for _, item := range base {
		name, _, _ := strings.Cut(item, "=")
		if _, replaced := overrides[name]; !replaced {
			out = append(out, item)
		}
	}
	return out
}
