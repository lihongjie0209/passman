package vault

import "testing"

func TestParseRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, ref string
		wantErr   bool
	}{
		{"valid", "ssh/prod#private_key", false},
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
