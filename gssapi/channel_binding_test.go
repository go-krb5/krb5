package gssapi

import (
	"crypto/md5" //nolint:gosec // Asserts the RFC 1964 mandated digest.
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChannelBindingBytesShouldMarshalRFC1964Layout(t *testing.T) {
	t.Parallel()

	cb := &ChannelBinding{
		InitiatorAddrType: AddressTypeIPv4,
		InitiatorAddress:  []byte{10, 0, 0, 1},
		AcceptorAddrType:  AddressTypeIPv4,
		AcceptorAddress:   []byte{10, 0, 0, 2},
		ApplicationData:   []byte("tls-server-end-point:xyz"),
	}

	expected := make([]byte, 0, 52)
	expected = append(expected,
		0x02, 0x00, 0x00, 0x00, // initiator address type.
		0x04, 0x00, 0x00, 0x00, // initiator address length.
		10, 0, 0, 1,
		0x02, 0x00, 0x00, 0x00, // acceptor address type.
		0x04, 0x00, 0x00, 0x00, // acceptor address length.
		10, 0, 0, 2,
		0x18, 0x00, 0x00, 0x00, // application data length (24).
	)
	expected = append(expected, []byte("tls-server-end-point:xyz")...)

	assert.Equal(t, expected, cb.Bytes())
}

// TestChannelBindingBytesShouldWriteLengthsForEmptyFields asserts the length prefix of an unset field is still
// emitted. MIT's kg_checksum_channel_bindings does this and interoperability depends on matching it.
func TestChannelBindingBytesShouldWriteLengthsForEmptyFields(t *testing.T) {
	t.Parallel()

	cb := &ChannelBinding{ApplicationData: []byte("ab")}

	assert.Equal(t, []byte{
		0, 0, 0, 0, // initiator address type.
		0, 0, 0, 0, // initiator address length.
		0, 0, 0, 0, // acceptor address type.
		0, 0, 0, 0, // acceptor address length.
		2, 0, 0, 0, // application data length.
		'a', 'b',
	}, cb.Bytes())
}

func TestChannelBindingBndShouldHashTheMarshalledStructure(t *testing.T) {
	t.Parallel()

	cb := &ChannelBinding{ApplicationData: []byte("ab")}

	assert.Equal(t, md5.Sum(cb.Bytes()), cb.Bnd()) //nolint:gosec
}

// TestChannelBindingShouldBeNilSafe asserts a nil binding means "no channel bindings" and yields the 16 zero bytes
// RFC 4121 expects, which is what keeps the default behaviour unchanged.
func TestChannelBindingShouldBeNilSafe(t *testing.T) {
	t.Parallel()

	var cb *ChannelBinding

	assert.Nil(t, cb.Bytes())
	assert.Equal(t, [16]byte{}, cb.Bnd())
}
