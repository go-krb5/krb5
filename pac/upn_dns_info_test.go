package pac

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/test/testdata"
)

func TestUPN_DNSInfo_Unmarshal(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_UPN_DNS_Info)
	require.NoError(t, err)

	var k UPNDNSInfo

	require.NoError(t, k.Unmarshal(b))

	assert.Equal(t, uint16(42), k.UPNLength)
	assert.Equal(t, uint16(16), k.UPNOffset)
	assert.Equal(t, uint16(22), k.DNSDomainNameLength)
	assert.Equal(t, uint16(64), k.DNSDomainNameOffset)
	assert.Equal(t, "testuser1@test.gokrb5", k.UPN)
	assert.Equal(t, "TEST.GOKRB5", k.DNSDomain)
	assert.Equal(t, uint32(0), k.Flags)
}

func TestUPN_DNSInfo_UnmarshalRejectsFieldOutsideBuffer(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		header []uint16
	}{
		{"UPN offset beyond the buffer", []uint16{0x0100, 0x0100, 0, 0}},
		{"UPN length runs past the end", []uint16{0xFFFF, 16, 0, 0}},
		{"UPN offset and length sum wraps a uint16", []uint16{0xFFF0, 0x0020, 0, 0}},
		{"DNS domain name offset beyond the buffer", []uint16{0, 16, 0x0100, 0x0100}},
		{"DNS domain name length runs past the end", []uint16{0, 16, 0xFFFF, 16}},
		{"DNS domain name offset and length sum wraps a uint16", []uint16{0, 16, 0xFFF0, 0x0020}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := make([]byte, 24)
			for i, v := range tc.header {
				binary.LittleEndian.PutUint16(b[i*2:], v)
			}

			var k UPNDNSInfo

			require.NotPanics(t, func() {
				assert.ErrorContains(t, k.Unmarshal(b), "lies outside")
			})
		})
	}
}
