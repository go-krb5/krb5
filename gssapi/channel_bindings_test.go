package gssapi

import (
	"crypto/md5"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChannelBindings_Bytes_ApplicationDataOnly(t *testing.T) {
	t.Parallel()

	cb := &ChannelBindings{ApplicationData: []byte("test")}

	// RFC 4121 §4.1.1.2 marshaling: little-endian 4-byte fields, each
	// gss_buffer prefixed by its 4-byte length. Address types and empty
	// addresses contribute their length words (all zero here); only the
	// application data carries bytes.
	want := []byte{
		0x00, 0x00, 0x00, 0x00, // initiator addrtype
		0x00, 0x00, 0x00, 0x00, // initiator address length (0)
		0x00, 0x00, 0x00, 0x00, // acceptor addrtype
		0x00, 0x00, 0x00, 0x00, // acceptor address length (0)
		0x04, 0x00, 0x00, 0x00, // application data length (4)
		't', 'e', 's', 't',
	}
	sum := md5.Sum(want)

	assert.Equal(t, sum[:], cb.Bytes())
	assert.Len(t, cb.Bytes(), 16)
}

func TestChannelBindings_Bytes_WithAddresses(t *testing.T) {
	t.Parallel()

	cb := &ChannelBindings{
		InitiatorAddrType: 2,
		InitiatorAddress:  []byte{127, 0, 0, 1},
		AcceptorAddrType:  2,
		AcceptorAddress:   []byte{10, 0, 0, 5},
		ApplicationData:   []byte("app"),
	}

	want := []byte{
		0x02, 0x00, 0x00, 0x00, // initiator addrtype (2)
		0x04, 0x00, 0x00, 0x00, // initiator address length (4)
		127, 0, 0, 1,
		0x02, 0x00, 0x00, 0x00, // acceptor addrtype (2)
		0x04, 0x00, 0x00, 0x00, // acceptor address length (4)
		10, 0, 0, 5,
		0x03, 0x00, 0x00, 0x00, // application data length (3)
		'a', 'p', 'p',
	}
	sum := md5.Sum(want)

	assert.Equal(t, sum[:], cb.Bytes())
}

// An all-empty but non-nil binding still hashes its five length words, which
// is distinct from GSS_C_NO_CHANNEL_BINDINGS (a nil *ChannelBindings, handled
// by callers as a zero Bnd field).
func TestChannelBindings_Bytes_Empty(t *testing.T) {
	t.Parallel()

	cb := &ChannelBindings{}

	sum := md5.Sum(make([]byte, 20))

	assert.Equal(t, sum[:], cb.Bytes())
}
