//go:build linux

package platform

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func VerifyPeer(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) { cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if sockErr != nil {
		return sockErr
	}
	uid := os.Getuid()
	if cred == nil || uid < 0 || uint64(cred.Uid) != uint64(uid) {
		return errors.New("peer UID mismatch")
	}
	return nil
}
