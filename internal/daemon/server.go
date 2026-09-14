package daemon

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/lihongjie0209/passman/internal/audit"
	"github.com/lihongjie0209/passman/internal/ipc"
	"github.com/lihongjie0209/passman/internal/platform"
	"github.com/lihongjie0209/passman/internal/secure"
	"github.com/lihongjie0209/passman/internal/store"
	"github.com/lihongjie0209/passman/internal/vault"

	"filippo.io/age"
)

type Server struct {
	store     *store.Store
	mu        sync.Mutex
	identity  *age.X25519Identity
	data      *vault.Data
	stop      chan struct{}
	stopOnce  sync.Once
	lockTimer *time.Timer
	audit     *audit.Log
}

func New(s *store.Store) *Server {
	return &Server{store: s, stop: make(chan struct{}), audit: audit.New(s.Dir())}
}

func (s *Server) Serve(ctx context.Context, socket string) error {
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return err
	}
	// #nosec G302 -- directories require execute permission; 0700 is owner-only.
	if err := os.Chmod(filepath.Dir(socket), 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(filepath.Dir(socket))
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Getuid()
	if !ok || uid < 0 || uint64(stat.Uid) != uint64(uid) || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("runtime directory must be owner-only and not a symlink")
	}
	if conn, dialErr := netDial(socket); dialErr == nil {
		_ = conn.Close()
		return errors.New("daemon is already running")
	}
	_ = os.Remove(socket) // stale socket
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("listening on socket: %w", err)
	}
	defer func() { _ = ln.Close(); _ = os.Remove(socket) }()
	if err := os.Chmod(socket, 0o600); err != nil {
		return err
	}
	sshSocket := filepath.Join(s.store.Dir(), "ssh-agent.sock")
	sshListener, err := s.listenSSHAgent(sshSocket)
	if err != nil {
		return err
	}
	defer func() { _ = sshListener.Close(); _ = os.Remove(sshSocket) }()
	go s.acceptSSHAgent(sshListener)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
			_ = sshListener.Close()
		case <-s.stop:
			_ = ln.Close()
			_ = sshListener.Close()
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-s.stop:
				return nil
			default:
				return err
			}
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok || platform.VerifyPeer(unixConn) != nil {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var req ipc.Request
	dec := json.NewDecoder(io.LimitReader(conn, ipc.MaxMessage+1))
	if err := dec.Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(ipc.Response{Error: "invalid request"})
		return
	}
	resp := s.dispatch(&req)
	clear(req.Password)
	clear(req.NewPassword)
	clear(req.Value)
	_ = json.NewEncoder(conn).Encode(resp)
	if req.Op == "lock" && resp.OK {
		s.stopOnce.Do(func() { close(s.stop) })
	}
}

func (s *Server) dispatch(req *ipc.Request) ipc.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := func() ipc.Response { return ipc.Response{OK: true} }
	fail := func(err error) ipc.Response { return ipc.Response{Error: err.Error()} }
	switch req.Op {
	case "status":
		if s.data == nil {
			return fail(errors.New("vault is locked"))
		}
		return ok()
	case "unlock":
		if s.data != nil {
			return ok()
		}
		id, data, err := s.store.Unlock(req.Password)
		if err != nil {
			return fail(err)
		}
		s.identity, s.data = id, data
		if req.TTLSeconds > 0 {
			if s.lockTimer != nil {
				s.lockTimer.Stop()
			}
			s.lockTimer = time.AfterFunc(time.Duration(req.TTLSeconds)*time.Second, s.expire)
		}
		return ok()
	case "lock":
		if s.lockTimer != nil {
			s.lockTimer.Stop()
		}
		if s.data != nil {
			wipe(s.data)
		}
		s.data, s.identity = nil, nil
		return ok()
	}
	if s.data == nil {
		return fail(errors.New("vault is locked"))
	}
	switch req.Op {
	case "set":
		if err := s.data.SetWithPolicy(req.Ref, req.Value, req.Policy, req.PolicySet); err != nil {
			return fail(err)
		}
		if err := s.store.Save(s.data, s.identity.Recipient()); err != nil {
			return fail(err)
		}
		return ok()
	case "remove":
		if err := s.data.Remove(req.Target); err != nil {
			return fail(err)
		}
		if err := s.store.Save(s.data, s.identity.Recipient()); err != nil {
			return fail(err)
		}
		return ok()
	case "list":
		return ipc.Response{OK: true, Metadata: s.data.List(req.Prefix)}
	case "policy_get":
		policy, err := s.data.Policy(req.Ref)
		if err != nil {
			return fail(err)
		}
		return ipc.Response{OK: true, Policy: &policy}
	case "policy_set":
		if len(req.PolicyFields) == 0 {
			return fail(errors.New("no policy changes requested"))
		}
		if err := s.data.UpdatePolicy(req.Ref, req.Policy, req.PolicyFields); err != nil {
			return fail(err)
		}
		if err := s.store.Save(s.data, s.identity.Recipient()); err != nil {
			return fail(err)
		}
		return ok()
	case "resolve":
		values := make(map[string][]byte, len(req.Refs))
		total := 0
		for _, ref := range req.Refs {
			value, err := s.data.Resolve(ref)
			if err != nil {
				wipeValues(values)
				if auditErr := s.audit.Append("run_denied", req.Refs, req.Program); auditErr != nil {
					return fail(errors.New("audit write failed; secret access denied"))
				}
				return fail(err)
			}
			total += len(value)
			if total > 8<<20 {
				clear(value)
				wipeValues(values)
				if auditErr := s.audit.Append("run_denied", req.Refs, req.Program); auditErr != nil {
					return fail(errors.New("audit write failed; secret access denied"))
				}
				return fail(errors.New("resolved secrets exceed 8 MiB limit"))
			}
			values[ref] = value
		}
		if len(req.Refs) > 0 {
			if err := s.audit.Append("run_allowed", req.Refs, req.Program); err != nil {
				wipeValues(values)
				return fail(errors.New("audit write failed; secret access denied"))
			}
		}
		return ipc.Response{OK: true, Values: values}
	case "reveal":
		encID, err := os.ReadFile(s.store.IdentityPath())
		if err != nil {
			return fail(errors.New("authentication failed"))
		}
		id, err := secure.DecryptIdentity(encID, req.Password)
		if err != nil || subtle.ConstantTimeCompare([]byte(idString(id)), []byte(s.identity.String())) != 1 {
			if auditErr := s.audit.Append("reveal_denied", []string{req.Ref}, ""); auditErr != nil {
				return fail(errors.New("audit write failed; secret access denied"))
			}
			return fail(errors.New("authentication failed"))
		}
		value, err := s.data.Get(req.Ref)
		if err != nil {
			if auditErr := s.audit.Append("reveal_denied", []string{req.Ref}, ""); auditErr != nil {
				return fail(errors.New("audit write failed; secret access denied"))
			}
			return fail(err)
		}
		if err := s.audit.Append("reveal_allowed", []string{req.Ref}, ""); err != nil {
			clear(value)
			return fail(errors.New("audit write failed; secret access denied"))
		}
		return ipc.Response{OK: true, Value: value}
	case "passwd":
		if err := s.store.ChangePassword(req.Password, req.NewPassword); err != nil {
			return fail(err)
		}
		return ok()
	default:
		return fail(errors.New("unsupported operation"))
	}
}

func (s *Server) expire() {
	s.mu.Lock()
	if s.data != nil {
		wipe(s.data)
	}
	s.data, s.identity = nil, nil
	s.mu.Unlock()
	s.stopOnce.Do(func() { close(s.stop) })
}

func idString(id *age.X25519Identity) string {
	if id == nil {
		return ""
	}
	return id.String()
}
func wipe(data *vault.Data) {
	for _, e := range data.Entries {
		for _, f := range e.Fields {
			clear(f.Value)
		}
	}
}
func wipeValues(values map[string][]byte) {
	for _, v := range values {
		clear(v)
	}
}
