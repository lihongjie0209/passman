package backup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lihongjie0209/passman/internal/catalog"
	"github.com/lihongjie0209/passman/internal/store"
)

const maxBackup = 72 << 20

type manifest struct {
	Version int               `json:"version"`
	Created time.Time         `json:"created_at"`
	SHA256  map[string]string `json:"sha256"`
}

func Create(s *store.Store, output string) error {
	identity, vaultData, err := s.Ciphertexts()
	if err != nil {
		return err
	}
	files := map[string][]byte{"identity.age": identity, "vault.age": vaultData}
	catalogData, err := catalog.New(s.Dir()).Export()
	if err != nil {
		return err
	}
	files["catalog.json"] = catalogData
	m := manifest{Version: 1, Created: time.Now().UTC(), SHA256: map[string]string{}}
	for name, data := range files {
		sum := sha256.Sum256(data)
		m.SHA256[name] = hex.EncodeToString(sum[:])
	}
	manifestData, err := json.Marshal(m)
	if err != nil {
		return err
	}
	files["manifest.json"] = manifestData
	f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- output is an explicit user-selected backup destination.
	if err != nil {
		return fmt.Errorf("creating backup: %w", err)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(output)
		}
	}()
	tw := tar.NewWriter(f)
	for _, name := range []string{"manifest.json", "identity.age", "vault.age", "catalog.json"} {
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: m.Created}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func Read(input string) ([]byte, []byte, []byte, error) {
	f, err := os.Open(input) // #nosec G304 -- input is an explicit user-selected backup source.
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(io.LimitReader(f, maxBackup+1))
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, nil, errors.New("invalid backup archive")
		}
		if h.Name != "manifest.json" && h.Name != "identity.age" && h.Name != "vault.age" && h.Name != "catalog.json" {
			return nil, nil, nil, errors.New("backup contains an unexpected file")
		}
		if h.Size < 0 || h.Size > 64<<20 {
			return nil, nil, nil, errors.New("backup member exceeds size limit")
		}
		if _, exists := files[h.Name]; exists {
			return nil, nil, nil, errors.New("backup contains duplicate files")
		}
		data, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(data)) != h.Size {
			return nil, nil, nil, errors.New("truncated backup member")
		}
		files[h.Name] = data
	}
	var m manifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil || m.Version != 1 {
		return nil, nil, nil, errors.New("invalid backup manifest")
	}
	for _, name := range []string{"identity.age", "vault.age", "catalog.json"} {
		data, ok := files[name]
		if !ok {
			return nil, nil, nil, errors.New("backup is incomplete")
		}
		sum := sha256.Sum256(data)
		expected, err := hex.DecodeString(m.SHA256[name])
		if err != nil || !bytes.Equal(sum[:], expected) {
			return nil, nil, nil, errors.New("backup checksum mismatch")
		}
	}
	return files["identity.age"], files["vault.age"], files["catalog.json"], nil
}
