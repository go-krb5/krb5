package gssapi

import (
	"crypto/md5" //nolint:gosec // RFC 1964 §1.1.1 fixes MD5 as the channel bindings digest. It is a protocol constant, not a collision resistance claim, and cannot be substituted without breaking interoperability.
	"encoding/binary"
)

// Channel binding address types as assigned by RFC 2744 Section 3.11.
const (
	AddressTypeUnspecified uint32 = 0
	AddressTypeLocal       uint32 = 1
	AddressTypeIPv4        uint32 = 2
	AddressTypeDECnet      uint32 = 12
	AddressTypeIPv6        uint32 = 24
)

// channelBindingFieldLen is the width of each address type and length field in the marshalled structure.
const channelBindingFieldLen = 4

// channelBindingFields is the number of fixed width fields in the marshalled structure: two address types and three
// lengths.
const channelBindingFields = 5

// ChannelBinding is the GSS-API channel bindings structure of RFC 2744 Section 3.11. It binds a security context to
// the transport channel underneath it so that a credential captured on one channel cannot be replayed on another.
//
// For the TLS binding types of RFC 5929 and RFC 9266 the address fields are left unset and everything is carried in
// ApplicationData. Use NewChannelBindingTLSServerEndPoint, NewChannelBindingTLSExporter or
// NewChannelBindingTLSUnique rather than populating this struct directly.
//
// A nil *ChannelBinding means "no channel bindings" and is safe to use with either method.
type ChannelBinding struct {
	InitiatorAddrType uint32
	InitiatorAddress  []byte
	AcceptorAddrType  uint32
	AcceptorAddress   []byte
	ApplicationData   []byte
}

// Bytes returns the channel bindings marshalled as described by RFC 1964 Section 1.1.1, with every integer in
// little-endian order. The length prefix of a field is written even when that field is empty.
//
// It returns nil if the receiver is nil.
func (c *ChannelBinding) Bytes() []byte {
	if c == nil {
		return nil
	}

	b := make([]byte, 0, channelBindingFields*channelBindingFieldLen+
		len(c.InitiatorAddress)+len(c.AcceptorAddress)+len(c.ApplicationData))

	b = binary.LittleEndian.AppendUint32(b, c.InitiatorAddrType)
	b = appendChannelBindingField(b, c.InitiatorAddress)
	b = binary.LittleEndian.AppendUint32(b, c.AcceptorAddrType)
	b = appendChannelBindingField(b, c.AcceptorAddress)
	b = appendChannelBindingField(b, c.ApplicationData)

	return b
}

// Bnd returns the MD5 hash of the marshalled channel bindings. This is the Bnd field of the GSS-API authenticator
// checksum described by RFC 4121 Section 4.1.1, which occupies bytes 4 to 19 of that checksum.
//
// It returns the zero value if the receiver is nil, which is how RFC 4121 encodes the absence of channel bindings.
func (c *ChannelBinding) Bnd() [16]byte {
	if c == nil {
		return [16]byte{}
	}

	return md5.Sum(c.Bytes()) //nolint:gosec // See the package level rationale on the md5 import.
}

// appendChannelBindingField appends a little-endian length prefix followed by the field itself.
func appendChannelBindingField(b, field []byte) []byte {
	b = binary.LittleEndian.AppendUint32(b, uint32(len(field)))

	return append(b, field...)
}
