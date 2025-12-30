package pac

import (
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

	assert.Equal(t, uint16(42), k.UPNLength, "UPN Length not as expected")
	assert.Equal(t, uint16(16), k.UPNOffset, "UPN Offset not as expected")
	assert.Equal(t, uint16(22), k.DNSDomainNameLength, "DNS Domain Length not as expected")
	assert.Equal(t, uint16(64), k.DNSDomainNameOffset, "DNS Domain Offset not as expected")
	assert.Equal(t, "testuser1@test.gokrb5", k.UPN)
	assert.Equal(t, "TEST.GOKRB5", k.DNSDomain)
	assert.Equal(t, uint32(0), k.Flags, "DNS Domain not as expected")
}
