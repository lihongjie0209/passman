package vault

import (
	"testing"
	"time"
)

func TestParseRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, ref string
		wantErr   bool
	}{
		{"valid", "ssh/prod#private_key", false},
		{"URI with path", "passman://ssh/prod/private_key", false},
		{"URI with fragment", "passman://ssh/prod#private_key", false},
		{"missing field", "ssh/prod", true},
		{"traversal", "ssh/../prod#key", true},
		{"empty segment", "ssh//prod#key", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ParseRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRef() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDataPolicies(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	d := New()
	if err := d.SetWithPolicy("service#token", []byte("secret"), Policy{ExecOnly: true, ExpiresAt: &future}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Get("service#token"); err == nil {
		t.Fatal("exec-only secret was revealable")
	}
	got, err := d.Resolve("passman://service/token")
	if err != nil || string(got) != "secret" {
		t.Fatalf("Resolve() = %q, %v", got, err)
	}
	past := now.Add(-time.Hour)
	if err := d.SetWithPolicy("service#expired", []byte("secret"), Policy{ExpiresAt: &past}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Resolve("service#expired"); err == nil {
		t.Fatal("expired secret was resolved")
	}
	metadata := d.List("service")
	if len(metadata) != 2 || !metadata[0].Expired && !metadata[1].Expired {
		t.Fatalf("expired metadata not reported: %#v", metadata)
	}
}

func TestDataUpdatePolicy(t *testing.T) {
	t.Parallel()
	d := New()
	if err := d.Set("service#token", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	if err := d.UpdatePolicy("service#token", Policy{ExecOnly: true, ExpiresAt: &expires}, []string{"exec_only", "expires_at"}); err != nil {
		t.Fatal(err)
	}
	policy, err := d.Policy("service#token")
	if err != nil {
		t.Fatal(err)
	}
	if !policy.ExecOnly || policy.ExpiresAt == nil || !policy.ExpiresAt.Equal(expires) {
		t.Fatalf("unexpected policy: %#v", policy)
	}
	if err := d.UpdatePolicy("service#token", Policy{}, []string{"exec_only", "expires_at"}); err != nil {
		t.Fatal(err)
	}
	policy, err = d.Policy("service#token")
	if err != nil {
		t.Fatal(err)
	}
	if policy.ExecOnly || policy.ExpiresAt != nil {
		t.Fatalf("policy was not cleared: %#v", policy)
	}
}

func TestDataLifecycle(t *testing.T) {
	t.Parallel()
	d := New()
	secret := []byte("correct horse battery staple")
	if err := d.Set("service#password", secret); err != nil {
		t.Fatal(err)
	}
	secret[0] = 'X'
	got, err := d.Get("service#password")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "correct horse battery staple" {
		t.Fatalf("unexpected value %q", got)
	}
	if len(d.List("service")) != 1 {
		t.Fatal("expected one metadata item")
	}
	if err := d.Remove("service#password"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Get("service#password"); err == nil {
		t.Fatal("removed value still exists")
	}
}
