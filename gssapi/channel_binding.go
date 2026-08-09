package gssapi

import (
	"crypto/md5" //nolint:gosec // RFC 1964 §1.1.1 fixes MD5 as the channel bindings digest. It is a protocol constant, not a collision resistance claim, and cannot be substituted without breaking interoperability.
	"encoding/binary"
)

// Channel binding address types for the InitiatorAddrType and AcceptorAddrType fields. RFC 2744 Section 3.11 names
// the address families those fields may carry; the numeric values are assigned by the gssapi.h header RFC 2744
// publishes in Appendix A, which is also where the GSS_C_AF_ prefixed names these mirror come from. The set below is
// the RFC 2744 families this library declares for callers building their own, non-TLS channel bindings, plus the
// MIT/Heimdal IPv6 value described below; this library itself only ever references AddressTypeUnspecified and
// AddressTypeIPv4.
//
// AddressTypeIPv6 is the exception: RFC 2744 predates IPv6 and assigns no value for it anywhere. 24 is the value MIT
// Kerberos and Heimdal both give GSS_C_AF_INET6, and is declared for interoperability with them rather than on the
// authority of the RFC.
//
// The TLS binding types of RFC 5929 and RFC 9266 use only AddressTypeUnspecified: they leave both address fields
// unset and carry everything in ApplicationData.
const (
	AddressTypeUnspecified uint32 = 0
	AddressTypeLocal       uint32 = 1
	AddressTypeIPv4        uint32 = 2
	AddressTypeDECnet      uint32 = 12
	AddressTypeIPv6        uint32 = 24
	AddressTypeNullAddr    uint32 = 255
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
// Each field must be no longer than 4294967295 octets, the limit RFC 4121 Section 4.1.1.2 places on interoperable
// channel binding buffers, because the length prefix is four octets wide. No TLS binding type comes close: the
// longest is tls-server-end-point over a SHA-512 signed certificate, at 85 octets.
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
//
// The length prefix is four octets wide because RFC 1964 Section 1.1.1 fixes it there, which is also why RFC 4121
// Section 4.1.1.2 limits interoperable channel binding buffers to 4294967295 octets. A field longer than that cannot
// be represented and is not rejected here: Bytes has no error to return, and returning a short or empty marshalling
// instead would yield a Bnd that collides with a legitimate one, which is worse than a length that cannot occur. See
// the documented limit on Bytes.
func appendChannelBindingField(b, field []byte) []byte {
	//nolint:gosec // G115: len cannot exceed math.MaxUint32 here for any channel binding that RFC 4121 Section
	// 4.1.1.2 considers interoperable, and on a 32 bit platform int cannot exceed it at all. Reaching this would
	// require a single field over 4GiB; the longest TLS binding type is 85 octets.
	b = binary.LittleEndian.AppendUint32(b, uint32(len(field)))

	return append(b, field...)
}
