package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const fileName = "audit.jsonl"

type Event struct {
	Sequence uint64    `json:"sequence"`
	Time     time.Time `json:"time"`
	Action   string    `json:"action"`
	Refs     []string  `json:"refs,omitempty"`
	Program  string    `json:"program,omitempty"`
	PrevHash string    `json:"prev_hash,omitempty"`
	Hash     string    `json:"hash"`
}

type Log struct{ path string }

func New(dir string) *Log { return &Log{path: filepath.Join(dir, fileName)} }

func (l *Log) Append(action string, refs []string, program string) error {
	events, err := l.ReadAndVerify()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("verifying audit log: %w", err)
	}
	var sequence uint64 = 1
	previous := ""
	if len(events) > 0 {
		sequence = events[len(events)-1].Sequence + 1
		previous = events[len(events)-1].Hash
	}
	event := Event{Sequence: sequence, Time: time.Now().UTC(), Action: action, Refs: append([]string(nil), refs...), Program: program, PrevHash: previous}
	hash, err := eventHash(event)
	if err != nil {
		return err
	}
	event.Hash = hash
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(l.path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("audit log must not be a symbolic link")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- fixed path inside the configured data directory.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("audit log must be a regular owner-only file")
	}
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func (l *Log) ReadAndVerify() ([]Event, error) {
	if info, err := os.Lstat(l.path); err != nil {
		return nil, err
	} else if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("audit log must not be a symbolic link")
	}
	f, err := os.Open(l.path) // #nosec G304 -- fixed path inside the configured data directory.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("audit log must be a regular owner-only file")
	}
	var events []Event
	scanner := bufio.NewScanner(io.LimitReader(f, 64<<20))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	previous := ""
	var sequence uint64 = 1
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, errors.New("invalid audit record")
		}
		if event.Sequence != sequence || event.PrevHash != previous {
			return nil, errors.New("broken audit chain")
		}
		want, err := eventHash(event)
		if err != nil || event.Hash != want {
			return nil, errors.New("invalid audit hash")
		}
		events = append(events, event)
		previous = event.Hash
		sequence++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func eventHash(event Event) (string, error) {
	event.Hash = ""
	b, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
