package client

import (
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tcpKDC starts a loopback listener that reads a length prefixed request and then replies with whatever reply
// returns, given the request body. It returns the address to dial.
func tcpKDC(t *testing.T, reply func(req []byte) []byte) map[int]string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}

		defer c.Close()

		hb := make([]byte, 4)
		if _, err = io.ReadFull(c, hb); err != nil {
			return
		}

		req := make([]byte, binary.BigEndian.Uint32(hb))
		if _, err = io.ReadFull(c, req); err != nil {
			return
		}

		_, _ = c.Write(reply(req))
	}()

	return map[int]string{1: ln.Addr().String()}
}

// allocationCeiling bounds what the tests below accept as "did not allocate the declared length".
//
// runtime.MemStats.TotalAlloc counts the whole process, so a parallel test allocating at the same moment is
// included and a tight bound is flaky. The values being defended against are 512MiB and 2GiB, while the noise from
// neighbouring tests is single digit megabytes, so a ceiling between the two discriminates reliably.
const allocationCeiling = 64 << 20

// framed prefixes b with its length, as RFC 4120 Section 7.2.2 requires.
func framed(b []byte) []byte {
	hb := make([]byte, 4)
	binary.BigEndian.PutUint32(hb, uint32(len(b)))

	return append(hb, b...)
}

func TestSendTCPRoundTrip(t *testing.T) {
	t.Parallel()

	kdcs := tcpKDC(t, func(req []byte) []byte { return framed(append([]byte("reply to "), req...)) })

	rb, err := dialSendTCP(&net.Dialer{Timeout: time.Second}, kdcs, []byte("request"))

	require.NoError(t, err)
	assert.Equal(t, "reply to request", string(rb))
}

func TestSendTCPRejectsAnOversizedLengthPrefix(t *testing.T) {
	t.Parallel()

	// The length prefix is chosen by the peer and previously sized an allocation directly: the largest a uint32
	// can express is 4GiB.
	const declared = 512 << 20

	kdcs := tcpKDC(t, func([]byte) []byte {
		hb := make([]byte, 4)
		binary.BigEndian.PutUint32(hb, declared)

		return hb
	})

	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	_, err := dialSendTCP(&net.Dialer{Timeout: time.Second}, kdcs, []byte("request"))

	runtime.ReadMemStats(&after)

	assert.Error(t, err)
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(allocationCeiling),
		"the declared length was allocated before it was validated")
}

func TestSendTCPRejectsAReservedHighBitInTheLengthPrefix(t *testing.T) {
	t.Parallel()

	// RFC 4120 Section 7.2.2: "The high bit of the length is reserved for future expansion and MUST currently be
	// set to zero." RFC 5021 defines what a set bit means, which this library does not implement, so a reply
	// carrying one is refused rather than read as a two gigabyte length.
	kdcs := tcpKDC(t, func([]byte) []byte {
		hb := make([]byte, 4)
		binary.BigEndian.PutUint32(hb, 0x80000004)

		return append(hb, []byte("body")...)
	})

	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	_, err := dialSendTCP(&net.Dialer{Timeout: time.Second}, kdcs, []byte("request"))

	runtime.ReadMemStats(&after)

	assert.Error(t, err)
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(allocationCeiling),
		"a length with the reserved high bit set was allocated as a two gigabyte reply")
}

func TestSendTCPReadsALengthPrefixSplitAcrossSegments(t *testing.T) {
	t.Parallel()

	// A short read of the four byte header left the remaining bytes zero and the length silently wrong.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}

		defer c.Close()

		hb := make([]byte, 4)
		if _, err = io.ReadFull(c, hb); err != nil {
			return
		}

		req := make([]byte, binary.BigEndian.Uint32(hb))
		if _, err = io.ReadFull(c, req); err != nil {
			return
		}

		body := []byte("a reply split across two segments")

		full := framed(body)

		// Deliberately split inside the length prefix.
		_, _ = c.Write(full[:2])
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write(full[2:])
	}()

	rb, err := dialSendTCP(&net.Dialer{Timeout: time.Second}, map[int]string{1: ln.Addr().String()}, []byte("request"))

	require.NoError(t, err)
	assert.Equal(t, "a reply split across two segments", string(rb))
}

// wrappedConn is a net.Conn that is not a *net.TCPConn or a *net.UDPConn, which is what any dialer doing something
// useful returns: a SOCKS proxy, a TLS conn, or an instrumented one.
type wrappedConn struct {
	net.Conn
}

type wrappingDialer struct{}

func (wrappingDialer) Dial(network, addr string) (net.Conn, error) {
	c, err := net.DialTimeout(network, addr, time.Second)
	if err != nil {
		return nil, err
	}

	return wrappedConn{Conn: c}, nil
}

func TestDialSendTCPAcceptsACustomDialer(t *testing.T) {
	t.Parallel()

	kdcs := tcpKDC(t, func(req []byte) []byte { return framed(append([]byte("reply to "), req...)) })

	require.NotPanics(t, func() {
		rb, err := dialSendTCP(wrappingDialer{}, kdcs, []byte("request"))

		require.NoError(t, err)
		assert.Equal(t, "reply to request", string(rb))
	})
}

func TestDialSendUDPAcceptsACustomDialerAndLargeReplies(t *testing.T) {
	t.Parallel()

	// A reply was read into a fixed 4096 byte buffer, and a UDP datagram larger than the buffer is truncated
	// silently rather than reported. An Active Directory reply carrying a PAC routinely exceeds that.
	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte(i)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 65535)

		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}

		_, _ = pc.WriteTo(body, addr)
	}()

	require.NotPanics(t, func() {
		rb, err := dialSendUDP(wrappingDialer{}, map[int]string{1: pc.LocalAddr().String()}, []byte("request"))

		require.NoError(t, err)
		assert.Equal(t, body, rb)
	})
}
