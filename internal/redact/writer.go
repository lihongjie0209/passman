package redact

import (
	"bytes"
	"io"
	"sort"
)

var marker = []byte("[REDACTED]")

type Writer struct {
	dst      io.Writer
	patterns [][]byte
	pending  []byte
	max      int
}

func New(dst io.Writer, secrets [][]byte) *Writer {
	seen := make(map[string]struct{})
	var patterns [][]byte
	for _, secret := range secrets {
		add := func(p []byte) {
			if len(p) == 0 {
				return
			}
			if _, ok := seen[string(p)]; ok {
				return
			}
			seen[string(p)] = struct{}{}
			patterns = append(patterns, append([]byte(nil), p...))
		}
		add(secret)
		for _, line := range bytes.Split(secret, []byte{'\n'}) {
			if len(line) >= 8 {
				add(line)
			}
		}
	}
	sort.Slice(patterns, func(i, j int) bool { return len(patterns[i]) > len(patterns[j]) })
	w := &Writer{dst: dst, patterns: patterns}
	for _, p := range patterns {
		if len(p) > w.max {
			w.max = len(p)
		}
	}
	return w
}

func (w *Writer) Write(p []byte) (int, error) {
	w.pending = append(w.pending, p...)
	if err := w.drain(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *Writer) Close() error { return w.drain(true) }

func (w *Writer) drain(flush bool) error {
	if len(w.patterns) == 0 {
		_, err := w.dst.Write(w.pending)
		w.pending = w.pending[:0]
		return err
	}
	for {
		idx, plen := -1, 0
		for _, pat := range w.patterns {
			i := bytes.Index(w.pending, pat)
			if i >= 0 && (idx < 0 || i < idx || i == idx && len(pat) > plen) {
				idx, plen = i, len(pat)
			}
		}
		if idx >= 0 {
			if _, err := w.dst.Write(w.pending[:idx]); err != nil {
				return err
			}
			if _, err := w.dst.Write(marker); err != nil {
				return err
			}
			w.pending = w.pending[idx+plen:]
			continue
		}
		keep := w.max - 1
		if flush {
			keep = 0
		}
		if len(w.pending) <= keep {
			return nil
		}
		n := len(w.pending) - keep
		if _, err := w.dst.Write(w.pending[:n]); err != nil {
			return err
		}
		w.pending = append(w.pending[:0], w.pending[n:]...)
		if !flush {
			return nil
		}
	}
}
