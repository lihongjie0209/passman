package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lihongjie0209/passman/internal/vault"
)

const version = 1

type Item struct {
	ID           string    `json:"id"`
	Name         string    `json:"name,omitempty"`
	IP           string    `json:"ip,omitempty"`
	URL          string    `json:"url,omitempty"`
	Note         string    `json:"note,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	SecretFields []string  `json:"secret_fields,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Data struct {
	Version int             `json:"version"`
	Items   map[string]Item `json:"items"`
}
type Store struct{ dir string }

func New(dir string) *Store   { return &Store{dir: dir} }
func (s *Store) path() string { return filepath.Join(s.dir, "catalog.json") }

func (s *Store) List() ([]Item, error) {
	d, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]Item, 0, len(d.Items))
	for _, item := range d.Items {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) Export() ([]byte, error) {
	d, err := s.load()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(d, "", "  ")
}

func (s *Store) Replace(raw []byte) error {
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil || d.Version != version || d.Items == nil {
		return errors.New("invalid backup catalog")
	}
	for id, item := range d.Items {
		if id != item.ID {
			return errors.New("catalog ID mismatch")
		}
		if err := validate(item); err != nil {
			return err
		}
	}
	return s.update(func(current *Data) error { current.Version = d.Version; current.Items = d.Items; return nil })
}
func (s *Store) Get(id string) (Item, error) {
	if err := vault.ValidateEntry(id); err != nil {
		return Item{}, err
	}
	d, err := s.load()
	if err != nil {
		return Item{}, err
	}
	item, ok := d.Items[id]
	if !ok {
		return Item{}, errors.New("catalog entry not found")
	}
	return item, nil
}

func (s *Store) Set(item Item) error {
	if err := validate(item); err != nil {
		return err
	}
	return s.update(func(d *Data) error {
		old := d.Items[item.ID]
		item.SecretFields = old.SecretFields
		item.UpdatedAt = time.Now().UTC()
		item.Tags = unique(item.Tags)
		d.Items[item.ID] = item
		return nil
	})
}

func (s *Store) Remove(id string) error {
	if err := vault.ValidateEntry(id); err != nil {
		return err
	}
	return s.update(func(d *Data) error {
		if _, ok := d.Items[id]; !ok {
			return errors.New("catalog entry not found")
		}
		delete(d.Items, id)
		return nil
	})
}

func (s *Store) TrackField(ref string, add bool) error {
	entry, field, err := vault.ParseRef(ref)
	if err != nil {
		return err
	}
	return s.update(func(d *Data) error {
		item := d.Items[entry]
		item.ID = entry
		if add {
			item.SecretFields = append(item.SecretFields, field)
			item.SecretFields = unique(item.SecretFields)
		} else {
			out := item.SecretFields[:0]
			for _, v := range item.SecretFields {
				if v != field {
					out = append(out, v)
				}
			}
			item.SecretFields = out
		}
		item.UpdatedAt = time.Now().UTC()
		d.Items[entry] = item
		return nil
	})
}

func (s *Store) RemoveTracked(target string) error {
	if strings.Contains(target, "#") || strings.HasPrefix(target, "passman://") {
		return s.TrackField(target, false)
	}
	if err := vault.ValidateEntry(target); err != nil {
		return err
	}
	return s.update(func(d *Data) error {
		item, ok := d.Items[target]
		if !ok {
			return nil
		}
		item.SecretFields = nil
		item.UpdatedAt = time.Now().UTC()
		if item.Name == "" && item.IP == "" && item.URL == "" && item.Note == "" && len(item.Tags) == 0 {
			delete(d.Items, target)
		} else {
			d.Items[target] = item
		}
		return nil
	})
}

func Search(items []Item, query string) []Item {
	q := strings.ToLower(query)
	out := make([]Item, 0)
	for _, item := range items {
		hay := strings.ToLower(strings.Join(append([]string{item.ID, item.Name, item.IP, item.URL, item.Note}, item.Tags...), "\n"))
		if strings.Contains(hay, q) {
			out = append(out, item)
		}
	}
	return out
}

func validate(item Item) error {
	if err := vault.ValidateEntry(item.ID); err != nil {
		return err
	}
	if len(item.Name) > 256 || len(item.Note) > 4096 {
		return errors.New("catalog name or note exceeds size limit")
	}
	if item.IP != "" && net.ParseIP(item.IP) == nil {
		return errors.New("invalid IP address")
	}
	if item.URL != "" {
		u, err := url.Parse(item.URL)
		if err != nil || u.Scheme == "" {
			return errors.New("URL must be absolute")
		}
		if u.User != nil {
			return errors.New("URL must not contain credentials")
		}
	}
	if len(item.Tags) > 32 {
		return errors.New("too many tags")
	}
	for _, tag := range item.Tags {
		if tag == "" || len(tag) > 64 {
			return errors.New("invalid tag")
		}
	}
	return nil
}
func unique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Store) load() (*Data, error) {
	b, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return &Data{Version: version, Items: map[string]Item{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var d Data
	if err := json.Unmarshal(b, &d); err != nil || d.Version != version || d.Items == nil {
		return nil, errors.New("invalid catalog")
	}
	return &d, nil
}
func (s *Store) update(fn func(*Data) error) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	// #nosec G302 -- directories require execute permission; 0700 is owner-only.
	if err := os.Chmod(s.dir, 0o700); err != nil {
		return err
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	d, err := s.load()
	if err != nil {
		return err
	}
	if err := fn(d); err != nil {
		return err
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return atomicWrite(s.path(), b)
}
func (s *Store) lock() (func(), error) {
	path := filepath.Join(s.dir, ".catalog.lock")
	deadline := time.Now().Add(2 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- fixed lock path inside the configured catalog directory.
		if err == nil {
			return func() { _ = f.Close(); _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		info, statErr := os.Stat(path)
		if statErr == nil && time.Since(info.ModTime()) > 30*time.Second {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("catalog is busy")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".catalog-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("saving catalog: %w", err)
	}
	return nil
}
