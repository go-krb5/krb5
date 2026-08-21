package kadmin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// Protocol version numbers for the kpasswd request message.
const (
	// VersionChangePassword is the protocol version number of the original Kerberos change password protocol. The
	// KRB_PRIV user data of such a request is the new password in the clear and the KDC changes the password of the
	// principal that the AP_REQ ticket was issued to.
	VersionChangePassword uint16 = 0x0001

	// VersionSetPassword is the protocol version number of the set password protocol defined by RFC 3244. The
	// KRB_PRIV user data of such a request is a marshaled ChangePasswdData and the KDC sets the password of the
	// principal named by its targname, which requires the requestor to be authorized to administer that principal.
	VersionSetPassword uint16 = 0xff80
)

// Request message for changing or setting a password.
type Request struct {
	// Version is the protocol version number of the request, which selects the operation the KDC performs. It must
	// be VersionChangePassword or VersionSetPassword.
	Version uint16
	APREQ   messages.APReq
	KRBPriv messages.KRBPriv
}

// Reply message for a password change.
type Reply struct {
	MessageLength int
	Version       int
	APREPLength   int
	APREP         messages.APRep
	KRBPriv       messages.KRBPriv
	KRBError      messages.KRBError
	IsKRBError    bool
	ResultCode    uint16
	Result        string
}

// Marshal a Request into a byte slice.
func (m *Request) Marshal() (b []byte, err error) {
	if m.Version != VersionChangePassword && m.Version != VersionSetPassword {
		return nil, fmt.Errorf("invalid kadmin request protocol version number: %#04x", m.Version)
	}

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, m.Version)

	ab, e := m.APREQ.Marshal()
	if e != nil {
		return nil, fmt.Errorf("error marshaling AP_REQ: %v", e)
	}

	if len(ab) > math.MaxUint16 {
		return nil, errors.New("length of AP_REQ greater then max Uint16 size")
	}

	al := make([]byte, 2)
	binary.BigEndian.PutUint16(al, uint16(len(ab)))

	b = append(b, al...)
	b = append(b, ab...)

	pb, err := m.KRBPriv.Marshal()
	if err != nil {
		return nil, fmt.Errorf("error marshaling KRB_Priv: %w", err)
	}

	b = append(b, pb...)

	if len(b)+2 > math.MaxUint16 {
		return nil, errors.New("length of message greater then max Uint16 size")
	}

	ml := make([]byte, 2)
	binary.BigEndian.PutUint16(ml, uint16(len(b)+2))

	b = append(ml, b...)

	return b, nil
}

// replyHeaderLen is the width of the fixed part of a kpasswd reply: the message length, the protocol version
// number and the AP-REP length, each a two octet big-endian integer. RFC 3244 Section 2.
const replyHeaderLen = 6

// resultCodeLen is the width of the result code that begins the user data of a kpasswd reply. RFC 3244 Section 2.
const resultCodeLen = 2

// Unmarshal a byte slice into a Reply.
func (m *Reply) Unmarshal(b []byte) error {
	if len(b) < replyHeaderLen {
		return fmt.Errorf("kadmin reply is %d bytes, shorter than its %d byte header", len(b), replyHeaderLen)
	}

	m.MessageLength = int(binary.BigEndian.Uint16(b[0:2]))

	m.Version = int(binary.BigEndian.Uint16(b[2:4]))
	if m.Version != 1 {
		return fmt.Errorf("kadmin reply has incorrect protocol version number: %d", m.Version)
	}

	m.APREPLength = int(binary.BigEndian.Uint16(b[4:6]))

	if m.MessageLength < replyHeaderLen || m.MessageLength > len(b) {
		return fmt.Errorf("kadmin reply declares a message length of %d, which is not between %d and the %d bytes received",
			m.MessageLength, replyHeaderLen, len(b))
	}

	if replyHeaderLen+m.APREPLength > m.MessageLength {
		return fmt.Errorf("kadmin reply declares an AP_REP of %d bytes, which does not fit within its %d byte message",
			m.APREPLength, m.MessageLength)
	}

	if m.APREPLength != 0 {
		err := m.APREP.Unmarshal(b[6 : 6+m.APREPLength])
		if err != nil {
			return err
		}

		err = m.KRBPriv.Unmarshal(b[6+m.APREPLength : m.MessageLength])
		if err != nil {
			return err
		}
	} else {
		m.IsKRBError = true

		// The error from unmarshalling is discarded because the reply being a KRB-ERROR is itself the outcome:
		// Decrypt returns m.KRBError to the caller whether or not its contents could be read.
		_ = m.KRBError.Unmarshal(b[replyHeaderLen:m.MessageLength])

		// EData is attacker supplied and need not carry a result code. When it does not, ResultCode and Result
		// are left unset rather than defaulted, and Decrypt still reports the KRB-ERROR.
		if c, r, err := parseResponse(m.KRBError.EData); err == nil {
			m.ResultCode, m.Result = c, r
		}
	}

	return nil
}

// parseResponse splits the result code from the message that follows it in a kpasswd reply's user data.
//
// A caller must not treat an unreadable response as a successful one: KRB5_KPASSWD_SUCCESS is zero, so defaulting
// the code would report a password change that never happened as having succeeded.
func parseResponse(b []byte) (c uint16, s string, err error) {
	if len(b) < resultCodeLen {
		return 0, "", fmt.Errorf("kadmin response is %d bytes, too short to carry its %d byte result code",
			len(b), resultCodeLen)
	}

	return binary.BigEndian.Uint16(b[:resultCodeLen]), string(b[resultCodeLen:]), nil
}

// Decrypt the encrypted part of the KRBError within the change password Reply.
func (m *Reply) Decrypt(key types.EncryptionKey) error {
	if m.IsKRBError {
		return m.KRBError
	}

	err := m.KRBPriv.DecryptEncPart(key)
	if err != nil {
		return err
	}

	if m.ResultCode, m.Result, err = parseResponse(m.KRBPriv.DecryptedEncPart.UserData); err != nil {
		return err
	}

	return nil
}
