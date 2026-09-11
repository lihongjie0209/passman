package vault

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	FormatVersion = 1
	MaxFieldSize  = 1 << 20
)

var (
	entryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	fieldPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Field struct {
	Value     []byte    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Entry struct {
	Fields map[string]Field `json:"fields"`
}

type Data struct {
	Version int              `json:"version"`
	Entries map[string]Entry `json:"entries"`
}

type Metadata struct {
	Entry     string    `json:"entry"`
	Field     string    `json:"field"`
	UpdatedAt time.Time `json:"updated_at"`
}

func New() *Data { return &Data{Version: FormatVersion, Entries: make(map[string]Entry)} }

func ValidateEntry(entry string) error {
	if !entryPattern.MatchString(entry) || strings.Contains(entry, "//") {
		return errors.New("invalid entry")
	}
	for _, part := range strings.Split(entry, "/") {
		if part == "." || part == ".." || part == "" {
			return errors.New("invalid entry path")
		}
	}
	return nil
}

func ParseRef(ref string) (string, string, error) {
	entry, field, ok := strings.Cut(ref, "#")
	if !ok || ValidateEntry(entry) != nil || !fieldPattern.MatchString(field) {
		return "", "", errors.New("invalid reference; expected <entry>#<field>")
	}
	return entry, field, nil
}

func (d *Data) Set(ref string, value []byte) error {
	entryName, fieldName, err := ParseRef(ref)
	if err != nil {
		return err
	}
	if len(value) == 0 {
		return errors.New("secret must not be empty")
	}
	if len(value) > MaxFieldSize {
		return errors.New("secret exceeds 1 MiB limit")
	}
	entry := d.Entries[entryName]
	if entry.Fields == nil {
		entry.Fields = make(map[string]Field)
	}
	entry.Fields[fieldName] = Field{Value: append([]byte(nil), value...), UpdatedAt: time.Now().UTC()}
	d.Entries[entryName] = entry
	return nil
}

func (d *Data) Get(ref string) ([]byte, error) {
	entryName, fieldName, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}
	entry, ok := d.Entries[entryName]
	if !ok {
		return nil, errors.New("secret not found")
	}
	field, ok := entry.Fields[fieldName]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return append([]byte(nil), field.Value...), nil
}

func (d *Data) Remove(target string) error {
	if strings.Contains(target, "#") {
		entryName, fieldName, err := ParseRef(target)
		if err != nil {
			return err
		}
		entry, ok := d.Entries[entryName]
		if !ok {
			return errors.New("secret not found")
		}
		if _, ok := entry.Fields[fieldName]; !ok {
			return errors.New("secret not found")
		}
		delete(entry.Fields, fieldName)
		if len(entry.Fields) == 0 {
			delete(d.Entries, entryName)
		} else {
			d.Entries[entryName] = entry
		}
		return nil
	}
	if err := ValidateEntry(target); err != nil {
		return err
	}
	if _, ok := d.Entries[target]; !ok {
		return errors.New("entry not found")
	}
	delete(d.Entries, target)
	return nil
}

func (d *Data) List(prefix string) []Metadata {
	var out []Metadata
	for entryName, entry := range d.Entries {
		if prefix != "" && entryName != prefix && !strings.HasPrefix(entryName, prefix+"/") {
			continue
		}
		for fieldName, field := range entry.Fields {
			out = append(out, Metadata{Entry: entryName, Field: fieldName, UpdatedAt: field.UpdatedAt})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Entry == out[j].Entry {
			return out[i].Field < out[j].Field
		}
		return out[i].Entry < out[j].Entry
	})
	return out
}
