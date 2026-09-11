package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/lihongjie0209/passman/internal/vault"
)

const MaxMessage = 12 << 20

type Request struct {
	Op          string   `json:"op"`
	Password    []byte   `json:"password,omitempty"`
	NewPassword []byte   `json:"new_password,omitempty"`
	Ref         string   `json:"ref,omitempty"`
	Target      string   `json:"target,omitempty"`
	Value       []byte   `json:"value,omitempty"`
	Refs        []string `json:"refs,omitempty"`
	Prefix      string   `json:"prefix,omitempty"`
	TTLSeconds  int64    `json:"ttl_seconds,omitempty"`
}

type Response struct {
	OK       bool              `json:"ok"`
	Error    string            `json:"error,omitempty"`
	Values   map[string][]byte `json:"values,omitempty"`
	Value    []byte            `json:"value,omitempty"`
	Metadata []vault.Metadata  `json:"metadata,omitempty"`
}

type Client struct{ Socket string }

func (c Client) Call(ctx context.Context, req Request) (Response, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return Response{}, errors.New("daemon is not running; run `passman unlock`")
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil { //nolint:gosec // secrets are intentionally sent over an owner-only, peer-verified Unix socket.
		return Response{}, fmt.Errorf("sending request: %w", err)
	}
	var resp Response
	r := bufio.NewReaderSize(conn, 64*1024)
	dec := json.NewDecoder(&limitedReader{r: r, remaining: MaxMessage})
	if err := dec.Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("reading daemon response: %w", err)
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

type limitedReader struct {
	r         *bufio.Reader
	remaining int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		return 0, errors.New("IPC message exceeds limit")
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}
