package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/messages"
)

const (
	// maxKDCReply bounds the reply this client will read from a KDC over TCP. The length prefix of RFC 4120
	// Section 7.2.2 is chosen by the peer and the largest a uint32 can express is 4GiB, so it is not allocated
	// unchecked. A reply is a ticket and its encrypted part; even an Active Directory one carrying a large PAC
	// is tens of kilobytes, so a megabyte is generous.
	maxKDCReply = 1 << 20

	// tcpLengthReserved is the high bit of the TCP length prefix. RFC 4120 Section 7.2.2: "The high bit of the
	// length is reserved for future expansion and MUST currently be set to zero." RFC 5021 defines what a set
	// bit means, which this library does not implement, so a reply carrying one is refused rather than read as
	// a two gigabyte length.
	tcpLengthReserved = 1 << 31

	// maxUDPReply is the largest UDP datagram that can carry a reply. Reading into a smaller buffer discards the
	// remainder of a larger datagram silently rather than reporting it; a reply too large for a datagram is
	// answered by the KDC with KRB_ERR_RESPONSE_TOO_BIG, which sendToKDC retries over TCP.
	maxUDPReply = 65535

	// lengthHeaderLen is the width of the TCP length prefix of RFC 4120 Section 7.2.2.
	lengthHeaderLen = 4
)

// SendToKDC performs network actions to send data to the KDC.
func (cl *Client) sendToKDC(b []byte, realm string) (rb []byte, err error) {
	if cl.Config.LibDefaults.UDPPreferenceLimit == 1 {
		if rb, err = cl.sendKDCTCP(realm, b); err != nil {
			if e, ok := err.(messages.KRBError); ok {
				return rb, e
			}

			return rb, fmt.Errorf("communication error with KDC via TCP: %w", err)
		}

		return rb, nil
	}

	var errtcp, errudp error

	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		if rb, err = cl.sendKDCUDP(realm, b); err != nil {
			if e, ok := err.(messages.KRBError); ok && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				return rb, e
			}

			errudp = err

			if rb, err = cl.sendKDCTCP(realm, b); err != nil {
				if e, ok := err.(messages.KRBError); ok {
					return rb, e
				}

				errtcp = err

				return rb, fmt.Errorf("failed to communicate with KDC. Attempts made with UDP (%v) and then TCP (%v)", errudp, errtcp)
			}
		}

		return rb, nil
	}

	if rb, err = cl.sendKDCTCP(realm, b); err != nil {
		if e, ok := err.(messages.KRBError); ok {
			return rb, e
		}

		errtcp = err

		if rb, err = cl.sendKDCUDP(realm, b); err != nil {
			if e, ok := err.(messages.KRBError); ok {
				return rb, e
			}

			errudp = err

			return rb, fmt.Errorf("failed to communicate with KDC. Attempts made with TCP (%v) and then UDP (%v)", errtcp, errudp)
		}
	}

	return rb, nil
}

// sendKDCUDP sends bytes to the KDC via UDP.
func (cl *Client) sendKDCUDP(realm string, b []byte) (rb []byte, err error) {
	_, kdcs, err := cl.Config.GetKDCs(realm, false)
	if err != nil {
		return nil, err
	}

	if rb, err = dialSendUDP(cl.settings.dialer, kdcs, b); err != nil {
		return nil, err
	}

	return checkForKRBError(rb)
}

// dialSendUDP establishes a UDP connection to a KDC.
func dialSendUDP(dialer Dialer, kdcs map[int]string, b []byte) (rb []byte, err error) {
	var errs []string

	for i := 1; i <= len(kdcs); i++ {
		var conn net.Conn

		if conn, err = dialer.Dial("udp", kdcs[i]); err != nil {
			errs = append(errs, fmt.Sprintf("error establishing connection to %s: %v", kdcs[i], err))

			continue
		}

		if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			errs = append(errs, fmt.Sprintf("error setting deadline on connection to %s: %v", kdcs[i], err))
			conn.Close()

			continue
		}

		if rb, err = sendUDP(conn, b); err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))

			continue
		}

		return rb, nil
	}

	return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
}

// sendUDP sends bytes to connection over UDP.
func sendUDP(conn net.Conn, b []byte) ([]byte, error) {
	var r []byte

	defer conn.Close()

	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to (%s): %w", conn.RemoteAddr().String(), err)
	}

	// Sized to the largest datagram that can arrive. A shorter buffer does not fail on a larger reply, it
	// silently discards the remainder, and an Active Directory reply carrying a PAC routinely exceeds a few
	// kilobytes.
	udpbuf := make([]byte, maxUDPReply)

	n, err := conn.Read(udpbuf)

	r = udpbuf[:n]
	if err != nil {
		return r, fmt.Errorf("sending over UDP failed to %s: %w", conn.RemoteAddr().String(), err)
	}

	if len(r) < 1 {
		return r, fmt.Errorf("no response data from %s", conn.RemoteAddr().String())
	}

	return r, nil
}

// sendKDCTCP sends bytes to the KDC via TCP.
func (cl *Client) sendKDCTCP(realm string, b []byte) ([]byte, error) {
	var r []byte

	_, kdcs, err := cl.Config.GetKDCs(realm, true)
	if err != nil {
		return r, err
	}

	r, err = dialSendTCP(cl.settings.dialer, kdcs, b)
	if err != nil {
		return r, err
	}

	return checkForKRBError(r)
}

// dialKDCTCP establishes a TCP connection to a KDC.
func dialSendTCP(dialer Dialer, kdcs map[int]string, b []byte) ([]byte, error) {
	var errs []string

	for i := 1; i <= len(kdcs); i++ {
		conn, err := dialer.Dial("tcp", kdcs[i])
		if err != nil {
			errs = append(errs, fmt.Sprintf("error establishing connection to %s: %v", kdcs[i], err))
			continue
		}

		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			errs = append(errs, fmt.Sprintf("error setting deadline on connection to %s: %v", kdcs[i], err))
			conn.Close()

			continue
		}

		rb, err := sendTCP(conn, b)
		if err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))
			continue
		}

		return rb, nil
	}

	return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
}

// sendTCP sends bytes to connection over TCP.
//
// The length prefix that precedes the reply is chosen by the peer, so it is validated before it is used to size an
// allocation: RFC 4120 Section 7.2.2 reserves its high bit, and the remainder is bounded by maxKDCReply.
func sendTCP(conn net.Conn, b []byte) ([]byte, error) {
	defer conn.Close()

	var r []byte
	// RFC 4120 7.2.2 specifies the first 4 bytes indicate the length of the message in big endian order.
	hb := make([]byte, lengthHeaderLen)
	binary.BigEndian.PutUint32(hb, uint32(len(b)))
	b = append(hb, b...)

	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %w", conn.RemoteAddr().String(), err)
	}

	sh := make([]byte, lengthHeaderLen)

	// Read in full: a short read would leave the remaining octets zero and the length silently wrong.
	_, err = io.ReadFull(conn, sh)
	if err != nil {
		return r, fmt.Errorf("error reading response size header: %w", err)
	}

	s := binary.BigEndian.Uint32(sh)

	if s&tcpLengthReserved != 0 {
		return r, fmt.Errorf("KDC %s set the reserved high bit of the response length, which RFC 4120 section 7.2.2 requires to be zero", conn.RemoteAddr().String())
	}

	if s < 1 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}

	if s > maxKDCReply {
		return r, fmt.Errorf("KDC %s declared a response of %d bytes, which exceeds the maximum of %d", conn.RemoteAddr().String(), s, maxKDCReply)
	}

	rb := make([]byte, s)

	_, err = io.ReadFull(conn, rb)
	if err != nil {
		return r, fmt.Errorf("error reading response: %w", err)
	}

	return rb, nil
}

// checkForKRBError checks if the response bytes from the KDC are a KRBError.
func checkForKRBError(b []byte) (rb []byte, err error) {
	var e messages.KRBError

	if err = e.Unmarshal(b); err == nil {
		return b, e
	}

	return b, nil
}
