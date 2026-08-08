package gssapi

import (
	"crypto/md5"
	"encoding/binary"
)

// ChannelBindings holds GSS-API channel binding information, mirroring the
// gss_channel_bindings_struct of RFC 2744. Its MD5 hash forms the 16-byte Bnd
// field of the RFC 4121 §4.1.1 authenticator checksum, binding the security
// context to the underlying transport (e.g. tls-server-end-point per
// RFC 5929).
//
// A nil *ChannelBindings represents GSS_C_NO_CHANNEL_BINDINGS and is handled by
// callers as a zero Bnd field; a non-nil value with empty fields is distinct
// and still contributes to the hash.
type ChannelBindings struct {
	InitiatorAddrType uint32
	InitiatorAddress  []byte
	AcceptorAddrType  uint32
	AcceptorAddress   []byte
	ApplicationData   []byte
}

// Bytes marshals the channel bindings per RFC 4121 §4.1.1.2 and returns their
// 16-byte MD5 hash, suitable for the Bnd field of the authenticator checksum.
//
// The marshaling emits, in order, the little-endian initiator address type and
// address, the little-endian acceptor address type and address, and the
// application data; each address and the application data is prefixed by its
// little-endian 4-byte length.
func (c *ChannelBindings) Bytes() []byte {
	var b []byte

	putUint32 := func(v uint32) {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	putBuffer := func(v []byte) {
		putUint32(uint32(len(v)))
		b = append(b, v...)
	}

	putUint32(c.InitiatorAddrType)
	putBuffer(c.InitiatorAddress)
	putUint32(c.AcceptorAddrType)
	putBuffer(c.AcceptorAddress)
	putBuffer(c.ApplicationData)

	sum := md5.Sum(b)

	return sum[:]
}
