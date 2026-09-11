package redact

import (
	"bytes"
	"testing"
)

func TestWriterRedactsAcrossChunksAndLines(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	w := New(&out, [][]byte{[]byte("top-secret"), []byte("-----BEGIN KEY-----\nprivate-material-line\n-----END KEY-----")})
	for _, part := range []string{"before top-", "secret after\nprivate-", "material-line done"} {
		if _, err := w.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte("top-secret")) || bytes.Contains(out.Bytes(), []byte("private-material-line")) {
		t.Fatalf("secret leaked: %q", out.String())
	}
	if bytes.Count(out.Bytes(), marker) != 2 {
		t.Fatalf("expected two markers: %q", out.String())
	}
}

func TestWriterPassesUnrelatedOutput(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	w := New(&out, [][]byte{[]byte("secret")})
	_, _ = w.Write([]byte("hello world"))
	_ = w.Close()
	if out.String() != "hello world" {
		t.Fatalf("got %q", out.String())
	}
}
