package catalog

import (
	"path/filepath"
	"testing"
)

func TestCatalogSetSearchAndTrack(t *testing.T) {
	t.Parallel()
	s := New(filepath.Join(t.TempDir(), "data"))
	item := Item{ID: "nas/prod", Name: "Home NAS", IP: "10.10.0.4", URL: "https://nas.example.test", Note: "primary storage", Tags: []string{"storage", "home"}}
	if err := s.Set(item); err != nil {
		t.Fatal(err)
	}
	if err := s.TrackField("nas/prod#password", true); err != nil {
		t.Fatal(err)
	}
	items, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].SecretFields) != 1 || items[0].SecretFields[0] != "password" {
		t.Fatalf("unexpected catalog: %#v", items)
	}
	if got := Search(items, "10.10.0.4"); len(got) != 1 {
		t.Fatalf("search got %d results", len(got))
	}
	raw, err := s.Export()
	if err != nil {
		t.Fatal(err)
	}
	other := New(filepath.Join(t.TempDir(), "restored"))
	if err := other.Replace(raw); err != nil {
		t.Fatal(err)
	}
	restored, err := other.Get("nas/prod")
	if err != nil || restored.URL != item.URL {
		t.Fatalf("restored %#v, %v", restored, err)
	}
}

func TestCatalogRejectsCredentialURL(t *testing.T) {
	t.Parallel()
	s := New(filepath.Join(t.TempDir(), "data"))
	err := s.Set(Item{ID: "bad", URL: "https://user:password@example.test"}) // #nosec G101 -- deliberate dummy credential tests URL rejection.
	if err == nil {
		t.Fatal("expected URL validation error")
	}
}
