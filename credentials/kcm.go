package credentials

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"
)

// Operations of the KCM protocol, as numbered in kcm.h of MIT krb5.
const (
	kcmOpGetPrincipal    uint16 = 8
	kcmOpGetCredUUIDList uint16 = 9
	kcmOpGetCredByUUID   uint16 = 10
	kcmOpGetDefaultCache uint16 = 20
)

const (
	kcmUUIDLen  = 16
	kcmMaxReply = 10 << 20 // As MIT krb5 bounds replies.
	kcmTimeout  = 10 * time.Second
	// KRB5_FCC_NOFILE, the status of an operation on a missing cache.
	kcmErrNoCache uint32 = 0x96c73ac3
)

var errKCMNoCache = errors.New("no credentials cache found")

// kcmConn is a connection to a KCM daemon, such as sssd-kcm.
type kcmConn struct {
	net.Conn
}

// call sends an operation and returns the payload of its reply. A request
// holds its length, version 2.0, the operation and its arguments, a reply
// its length, the transport status, then the operation status and payload.
func (k kcmConn) call(op uint16, args ...[]byte) ([]byte, error) {
	req := binary.BigEndian.AppendUint16([]byte{0, 0, 0, 0, 2, 0}, op)
	for _, a := range args {
		req = append(req, a...)
	}
	n := len(req) - 4
	if n < 0 || n > kcmMaxReply {
		return nil, fmt.Errorf("kcm request of %d bytes is too large", n)
	}
	binary.BigEndian.PutUint32(req, uint32(n))
	if _, err := k.Write(req); err != nil {
		return nil, err
	}
	var h [8]byte
	if _, err := io.ReadFull(k, h[:]); err != nil {
		return nil, err
	}
	if code := binary.BigEndian.Uint32(h[4:]); code != 0 {
		return nil, fmt.Errorf("kcm error code %#x", code)
	}
	size := binary.BigEndian.Uint32(h[:4])
	if size < 4 || size > kcmMaxReply {
		return nil, fmt.Errorf("kcm reply of %d bytes is malformed", size)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(k, b); err != nil {
		return nil, err
	}
	switch code := binary.BigEndian.Uint32(b); code {
	case 0:
		return b[4:], nil
	case kcmErrNoCache:
		return nil, errKCMNoCache
	default:
		return nil, fmt.Errorf("kcm error code %#x", code)
	}
}

// loadKCMCCache loads a cache of the KCM daemon on socket, or the default
// cache of the user if name is empty.
func loadKCMCCache(socket, name string) (*CCache, error) {
	if socket == "-" {
		return nil, errors.New("kcm is disabled by kcm_socket")
	}
	conn, err := net.DialTimeout("unix", socket, kcmTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Bounds the whole load, as a daemon may never answer.
	if err := conn.SetDeadline(time.Now().Add(kcmTimeout)); err != nil {
		return nil, err
	}
	k := kcmConn{conn}
	if name == "" {
		b, err := k.call(kcmOpGetDefaultCache)
		if err != nil {
			return nil, err
		}
		name, _, _ = strings.Cut(string(b), "\x00")
	}
	arg := append([]byte(name), 0)
	p, err := k.call(kcmOpGetPrincipal, arg)
	// Heimdal answers a missing cache with no principal.
	if err == nil && len(p) == 0 {
		err = errKCMNoCache
	}
	if err != nil {
		return nil, fmt.Errorf("credential cache KCM:%s: %w", name, err)
	}
	ids, err := k.call(kcmOpGetCredUUIDList, arg)
	if err != nil {
		return nil, err
	}
	if len(ids)%kcmUUIDLen != 0 {
		return nil, fmt.Errorf("kcm uuid list of %d bytes", len(ids))
	}
	// KCM encodes principals and credentials as a v4 cache file does.
	b := append([]byte{5, 4, 0, 0}, p...)
	for id := range slices.Chunk(ids, kcmUUIDLen) {
		cred, err := k.call(kcmOpGetCredByUUID, arg, id)
		if err != nil {
			return nil, err
		}
		b = append(b, cred...)
	}
	c := new(CCache)
	if err := c.Unmarshal(b); err != nil {
		return nil, err
	}
	return c, nil
}
