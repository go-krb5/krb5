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

			continue
		}

		if rb, err = sendUDP(conn.(*net.UDPConn), b); err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))

			continue
		}

		return rb, nil
	}

	return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
}

// sendUDP sends bytes to connection over UDP.
func sendUDP(conn *net.UDPConn, b []byte) ([]byte, error) {
	var r []byte

	defer conn.Close()

	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to (%s): %w", conn.RemoteAddr().String(), err)
	}

	udpbuf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(udpbuf)

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
			continue
		}

		rb, err := sendTCP(conn.(*net.TCPConn), b)
		if err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))
			continue
		}

		return rb, nil
	}

	return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
}

// sendTCP sends bytes to connection over TCP.
func sendTCP(conn *net.TCPConn, b []byte) ([]byte, error) {
	defer conn.Close()

	var r []byte
	// RFC 4120 7.2.2 specifies the first 4 bytes indicate the length of the message in big endian order.
	hb := make([]byte, 4)
	binary.BigEndian.PutUint32(hb, uint32(len(b)))
	b = append(hb, b...)

	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %w", conn.RemoteAddr().String(), err)
	}

	sh := make([]byte, 4)

	_, err = conn.Read(sh)
	if err != nil {
		return r, fmt.Errorf("error reading response size header: %w", err)
	}

	s := binary.BigEndian.Uint32(sh)

	rb := make([]byte, s)

	_, err = io.ReadFull(conn, rb)
	if err != nil {
		return r, fmt.Errorf("error reading response: %w", err)
	}

	if len(rb) < 1 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
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
