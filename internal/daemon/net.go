package daemon

import (
	"net"
	"time"
)

func netDial(socket string) (net.Conn, error) {
	return net.DialTimeout("unix", socket, 100*time.Millisecond)
}
