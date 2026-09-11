package runner

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunInjectsAndRedacts(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	secret := []byte("sentinel-secret")
	err := Run(context.Background(), Options{Env: map[string][]byte{"TOKEN": secret}, Args: []string{"sh", "-c", `printf '%s' "$TOKEN"; printf '%s' "$TOKEN" >&2`}, Stdout: &stdout, Stderr: &stderr})
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"stdout": stdout.String(), "stderr": stderr.String()} {
		if strings.Contains(value, string(secret)) {
			t.Fatalf("%s leaked secret", name)
		}
		if value != "[REDACTED]" {
			t.Fatalf("%s = %q", name, value)
		}
	}
}

func TestRunFilePlaceholder(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	err := Run(context.Background(), Options{Files: map[string][]byte{"KEY": []byte("file-secret")}, Args: []string{"sh", "-c", `cat "$1"`, "sh", "{file:KEY}"}, Stdout: &stdout, Stderr: &stdout})
	if err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "[REDACTED]" {
		t.Fatalf("got %q", stdout.String())
	}
}
