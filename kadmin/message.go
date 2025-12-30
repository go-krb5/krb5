package kadmin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// Request message for changing password.
type Request struct {
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
	b = []byte{255, 128}

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

// Unmarshal a byte slice into a Reply.
func (m *Reply) Unmarshal(b []byte) error {
	m.MessageLength = int(binary.BigEndian.Uint16(b[0:2]))

	m.Version = int(binary.BigEndian.Uint16(b[2:4]))
	if m.Version != 1 {
		return fmt.Errorf("kadmin reply has incorrect protocol version number: %d", m.Version)
	}

	m.APREPLength = int(binary.BigEndian.Uint16(b[4:6]))
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

		// TODO: Figure out the reason for ignoring the error and document it. It's probably because the error is
		//       already indicated by the struct values.
		_ = m.KRBError.Unmarshal(b[6:m.MessageLength])
		m.ResultCode, m.Result = parseResponse(m.KRBError.EData)
	}

	return nil
}

func parseResponse(b []byte) (c uint16, s string) {
	c = binary.BigEndian.Uint16(b[0:2])

	buf := bytes.NewBuffer(b[2:])

	m := make([]byte, len(b)-2)

	binary.Read(buf, binary.BigEndian, &m)

	return c, string(m)
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

	m.ResultCode, m.Result = parseResponse(m.KRBPriv.DecryptedEncPart.UserData)

	return nil
}
