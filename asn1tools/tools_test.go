package asn1tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetLengthFromASNRejectsShortInput(t *testing.T) {
	t.Parallel()

	testCases := [][]byte{
		nil,
		{},
		{0x30},                   // tag with no length octet
		{0x30, 0x82},             // long form declaring two length octets that are not there
		{0x30, 0x84, 0x00, 0x01}, // long form declaring four, only two present
	}

	for _, b := range testCases {
		require.NotPanics(t, func() {
			assert.Zero(t, GetLengthFromASN(b))
		}, "GetLengthFromASN(%#v)", b)

		require.NotPanics(t, func() {
			assert.Zero(t, GetNumberBytesInLengthHeader(b))
		}, "GetNumberBytesInLengthHeader(%#v)", b)
	}
}

func TestGetLengthFromASNShortForm(t *testing.T) {
	t.Parallel()

	b := []byte{0x30, 0x05, 1, 2, 3, 4, 5}

	assert.Equal(t, 5, GetLengthFromASN(b))
	assert.Equal(t, 1, GetNumberBytesInLengthHeader(b))
}

func TestGetLengthFromASNLongForm(t *testing.T) {
	t.Parallel()

	b := append([]byte{0x30, 0x82, 0x01, 0x00}, make([]byte, 256)...)

	assert.Equal(t, 256, GetLengthFromASN(b))
	assert.Equal(t, 3, GetNumberBytesInLengthHeader(b))
}
