//go:build linux || darwin

package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/lihongjie0209/passman/internal/ipc"
	"github.com/lihongjie0209/passman/internal/store"
)

func TestServerLifecycle(t *testing.T) {
	root := t.TempDir()
	password := []byte("a sufficiently long password")
	s := store.New(filepath.Join(root, "data"))
	if err := s.Init(password); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "run", "daemon.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := New(s)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, socket) }()
	client := ipc.Client{Socket: socket}
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := client.Call(ctx, ipc.Request{Op: "status"})
		if err == nil || resp.Error != "" || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := client.Call(ctx, ipc.Request{Op: "unlock", Password: password}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Call(ctx, ipc.Request{Op: "set", Ref: "api#token", Value: []byte("secret")}); err != nil {
		t.Fatal(err)
	}
	resp, err := client.Call(ctx, ipc.Request{Op: "resolve", Refs: []string{"api#token"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Values["api#token"]) != "secret" {
		t.Fatal("unexpected resolved value")
	}
	if _, err := client.Call(ctx, ipc.Request{Op: "lock"}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}
