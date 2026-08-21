package pac

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestPAC_SignatureData_Unmarshal_Server_Signature(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_Server_Signature)
	require.NoError(t, err)

	var k SignatureData

	bz, err := k.Unmarshal(b)
	require.NoError(t, err)

	sig, _ := hex.DecodeString("1e251d98d552be7df384f550")
	zeroed, _ := hex.DecodeString("10000000000000000000000000000000")

	assert.Equal(t, uint32(chksumtype.HMAC_SHA1_96_AES256), k.SignatureType)
	assert.Equal(t, sig, k.Signature)
	assert.Equal(t, uint16(0), k.RODCIdentifier)
	assert.Equal(t, zeroed, bz)
}

func TestPAC_SignatureData_Unmarshal_KDC_Signature(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_KDC_Signature)
	require.NoError(t, err)

	var k SignatureData

	bz, err := k.Unmarshal(b)
	require.NoError(t, err)

	sig, _ := hex.DecodeString("340be28b48765d0519ee9346cf53d822")
	zeroed, _ := hex.DecodeString("76ffffff00000000000000000000000000000000")

	assert.Equal(t, chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED, k.SignatureType)
	assert.Equal(t, sig, k.Signature)
	assert.Equal(t, uint16(0), k.RODCIdentifier)
	assert.Equal(t, zeroed, bz)
}

func TestPAC_SignatureData_Unmarshal_CMAC_Camellia256_Signature(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString("12000000b1cc961bcb5585abd8d5ae4a2f3f7fea")
	require.NoError(t, err)

	var k SignatureData

	bz, err := k.Unmarshal(b)
	require.NoError(t, err)

	sig, _ := hex.DecodeString("b1cc961bcb5585abd8d5ae4a2f3f7fea")
	zeroed, _ := hex.DecodeString("1200000000000000000000000000000000000000")

	assert.Equal(t, uint32(chksumtype.CMAC_CAMELLIA256), k.SignatureType)
	assert.Equal(t, sig, k.Signature)
	assert.Equal(t, uint16(0), k.RODCIdentifier)
	assert.Equal(t, zeroed, bz)
}

func TestPAC_SignatureData_Unmarshal_Unknown_Signature_Type(t *testing.T) {
	t.Parallel()

	// 0x7fffffff is not a checksum type in iana/chksumtype, and is in the range the IANA registry
	// leaves unassigned.
	b, err := hex.DecodeString("ffffff7f0011223344556677")
	require.NoError(t, err)

	var k SignatureData

	bz, err := k.Unmarshal(b)
	require.NoError(t, err)

	sig, _ := hex.DecodeString("0011223344556677")
	zeroed, _ := hex.DecodeString("ffffff7f0000000000000000")

	assert.Equal(t, uint32(0x7fffffff), k.SignatureType)
	assert.Equal(t, sig, k.Signature)
	// No RODC identifier: with no known length there is nothing to tell a trailing identifier from
	// signature bytes, so the whole remainder is taken as the signature.
	assert.Equal(t, uint16(0), k.RODCIdentifier)
	assert.Equal(t, zeroed, bz)
}

func TestPAC_SignatureData_Unmarshal_Unknown_Type_Only(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString("ffffff7f")
	require.NoError(t, err)

	var k SignatureData

	bz, err := k.Unmarshal(b)
	require.NoError(t, err)

	assert.Equal(t, uint32(0x7fffffff), k.SignatureType)
	assert.Empty(t, k.Signature)
	assert.Equal(t, b, bz)
}
