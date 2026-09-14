//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/lihongjie0209/passman/internal/audit"
	"github.com/lihongjie0209/passman/internal/ipc"
	"github.com/lihongjie0209/passman/internal/store"
	"github.com/lihongjie0209/passman/internal/vault"
	"golang.org/x/crypto/ssh"
	sshprotocol "golang.org/x/crypto/ssh/agent"
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
	if _, err := client.Call(ctx, ipc.Request{Op: "set", Ref: "api#token", Value: []byte("secret"), Policy: vault.Policy{ExecOnly: true}, PolicySet: true}); err != nil {
		t.Fatal(err)
	}
	policyResp, err := client.Call(ctx, ipc.Request{Op: "policy_get", Ref: "api#token"})
	if err != nil || policyResp.Policy == nil || !policyResp.Policy.ExecOnly {
		t.Fatalf("unexpected policy: %#v, %v", policyResp.Policy, err)
	}
	resp, err := client.Call(ctx, ipc.Request{Op: "resolve", Refs: []string{"passman://api/token"}, Program: "test-client"})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Values["passman://api/token"]) != "secret" {
		t.Fatal("unexpected resolved value")
	}
	if _, err := client.Call(ctx, ipc.Request{Op: "reveal", Ref: "api#token", Password: password}); err == nil {
		t.Fatal("exec-only value was revealed")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "test")
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(block)
	if _, err := client.Call(ctx, ipc.Request{Op: "set", Ref: "ssh/test#private_key", Value: privatePEM, Policy: vault.Policy{ExecOnly: true}, PolicySet: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Call(ctx, ipc.Request{Op: "set", Ref: "ssh/not-exec-only#private_key", Value: privatePEM}); err != nil {
		t.Fatal(err)
	}
	clear(privatePEM)
	agentConn, err := net.Dial("unix", filepath.Join(root, "data", "ssh-agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	agentClient := sshprotocol.NewClient(agentConn)
	keys, err := agentClient.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "ssh/test#private_key" {
		t.Fatalf("unexpected SSH identities: %#v, %v", keys, err)
	}
	if err := agentClient.RemoveAll(); err == nil {
		t.Fatal("SSH agent allowed identity removal")
	}
	dataToSign := []byte("SSH agent protocol test")
	signature, err := agentClient.Sign(keys[0], dataToSign)
	if err != nil {
		t.Fatal(err)
	}
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := sshPublicKey.Verify(dataToSign, signature); err != nil {
		t.Fatalf("invalid SSH signature: %v", err)
	}
	if err := agentConn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Call(ctx, ipc.Request{Op: "policy_set", Ref: "api#token", Policy: vault.Policy{}, PolicyFields: []string{"exec_only"}}); err != nil {
		t.Fatal(err)
	}
	policyResp, err = client.Call(ctx, ipc.Request{Op: "policy_get", Ref: "api#token"})
	if err != nil || policyResp.Policy == nil || policyResp.Policy.ExecOnly {
		t.Fatalf("unexpected updated policy: %#v, %v", policyResp.Policy, err)
	}
	events, err := audit.New(filepath.Join(root, "data")).ReadAndVerify()
	if err != nil || len(events) != 3 || events[0].Program != "test-client" || events[0].Action != "run_allowed" || events[1].Action != "reveal_denied" || events[2].Action != "ssh_sign_allowed" {
		t.Fatalf("unexpected audit events: %#v, %v", events, err)
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
