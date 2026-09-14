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
	Value       []byte     `json:"value"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ExecOnly    bool       `json:"exec_only,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RotateAfter *time.Time `json:"rotate_after,omitempty"`
}

type Entry struct {
	Fields map[string]Field `json:"fields"`
}

type Data struct {
	Version int              `json:"version"`
	Entries map[string]Entry `json:"entries"`
}

type Metadata struct {
	Entry       string     `json:"entry"`
	Field       string     `json:"field"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ExecOnly    bool       `json:"exec_only,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RotateAfter *time.Time `json:"rotate_after,omitempty"`
	Expired     bool       `json:"expired,omitempty"`
	RotationDue bool       `json:"rotation_due,omitempty"`
}

type Policy struct {
	ExecOnly    bool       `json:"exec_only,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RotateAfter *time.Time `json:"rotate_after,omitempty"`
}

func (d *Data) Policy(ref string) (Policy, error) {
	field, err := d.field(ref)
	if err != nil {
		return Policy{}, err
	}
	return Policy{ExecOnly: field.ExecOnly, ExpiresAt: normalizedTime(field.ExpiresAt), RotateAfter: normalizedTime(field.RotateAfter)}, nil
}

func (d *Data) UpdatePolicy(ref string, policy Policy, fields []string) error {
	entryName, fieldName, err := ParseRef(ref)
	if err != nil {
		return err
	}
	entry, ok := d.Entries[entryName]
	if !ok {
		return errors.New("secret not found")
	}
	field, ok := entry.Fields[fieldName]
	if !ok {
		return errors.New("secret not found")
	}
	for _, name := range fields {
		switch name {
		case "exec_only":
			field.ExecOnly = policy.ExecOnly
		case "expires_at":
			field.ExpiresAt = normalizedTime(policy.ExpiresAt)
		case "rotate_after":
			field.RotateAfter = normalizedTime(policy.RotateAfter)
		default:
			return errors.New("invalid policy field")
		}
	}
	entry.Fields[fieldName] = field
	d.Entries[entryName] = entry
	return nil
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
	if strings.HasPrefix(ref, "passman://") {
		path := strings.TrimPrefix(ref, "passman://")
		if strings.Contains(path, "#") {
			ref = path
		} else if i := strings.LastIndexByte(path, '/'); i > 0 && i < len(path)-1 {
			ref = path[:i] + "#" + path[i+1:]
		} else {
			return "", "", errors.New("invalid passman URI; expected passman://<entry>/<field>")
		}
	}
	entry, field, ok := strings.Cut(ref, "#")
	if !ok || ValidateEntry(entry) != nil || !fieldPattern.MatchString(field) {
		return "", "", errors.New("invalid reference; expected <entry>#<field>")
	}
	return entry, field, nil
}

func (d *Data) Set(ref string, value []byte) error {
	return d.SetWithPolicy(ref, value, Policy{}, false)
}

func (d *Data) SetWithPolicy(ref string, value []byte, policy Policy, replacePolicy bool) error {
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
	field := entry.Fields[fieldName]
	field.Value = append([]byte(nil), value...)
	field.UpdatedAt = time.Now().UTC()
	if replacePolicy {
		field.ExecOnly = policy.ExecOnly
		field.ExpiresAt = normalizedTime(policy.ExpiresAt)
		field.RotateAfter = normalizedTime(policy.RotateAfter)
	}
	entry.Fields[fieldName] = field
	d.Entries[entryName] = entry
	return nil
}

func (d *Data) Get(ref string) ([]byte, error) {
	return d.get(ref, true, time.Now().UTC())
}

func (d *Data) Resolve(ref string) ([]byte, error) {
	return d.get(ref, false, time.Now().UTC())
}

func (d *Data) get(ref string, reveal bool, now time.Time) ([]byte, error) {
	field, err := d.field(ref)
	if err != nil {
		return nil, err
	}
	if field.ExpiresAt != nil && !now.Before(*field.ExpiresAt) {
		return nil, errors.New("secret has expired")
	}
	if reveal && field.ExecOnly {
		return nil, errors.New("secret is exec-only")
	}
	return append([]byte(nil), field.Value...), nil
}

func (d *Data) field(ref string) (Field, error) {
	entryName, fieldName, err := ParseRef(ref)
	if err != nil {
		return Field{}, err
	}
	entry, ok := d.Entries[entryName]
	if !ok {
		return Field{}, errors.New("secret not found")
	}
	field, ok := entry.Fields[fieldName]
	if !ok {
		return Field{}, errors.New("secret not found")
	}
	return field, nil
}

func (d *Data) Remove(target string) error {
	if strings.Contains(target, "#") || strings.HasPrefix(target, "passman://") {
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
			now := time.Now().UTC()
			out = append(out, Metadata{Entry: entryName, Field: fieldName, UpdatedAt: field.UpdatedAt, ExecOnly: field.ExecOnly, ExpiresAt: field.ExpiresAt, RotateAfter: field.RotateAfter, Expired: field.ExpiresAt != nil && !now.Before(*field.ExpiresAt), RotationDue: field.RotateAfter != nil && !now.Before(*field.RotateAfter)})
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

func normalizedTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	t := value.UTC()
	return &t
}
