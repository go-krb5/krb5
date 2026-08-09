package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/etypeID"
)

// TestSupportedETypesShouldRoundTripTheWireFormat pins the encoding MS-KILE Section 2.2.7 fixes: a 32 bit unsigned
// integer in little-endian format. Getting the byte order wrong would advertise DES where AES was meant.
func TestSupportedETypesShouldRoundTripTheWireFormat(t *testing.T) {
	t.Parallel()

	s := SupportedETypes(SupportedETypeAES256CTSHMACSHA196 | SupportedETypeAES128CTSHMACSHA196)

	b := s.Marshal()
	require.Len(t, b, 4)
	assert.Equal(t, []byte{0x18, 0x00, 0x00, 0x00}, b, "AES128 (0x08) and AES256 (0x10) little-endian")

	out, err := UnmarshalSupportedETypes(b)
	require.NoError(t, err)
	assert.Equal(t, s, out)
}

// TestUnmarshalSupportedETypesShouldRejectAWrongWidth asserts a value that is not four octets is refused rather
// than read from whatever is present. MS-KILE Section 2.2.7 fixes the width.
func TestUnmarshalSupportedETypesShouldRejectAWrongWidth(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"Empty", nil},
		{"Short", []byte{0x18, 0x00, 0x00}},
		{"Long", []byte{0x18, 0x00, 0x00, 0x00, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := UnmarshalSupportedETypes(tc.in)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "rather than 4")
		})
	}
}

// TestSupportedETypesBitValues pins every bit MS-KILE Section 2.2.7 assigns. These are the values an Active
// Directory KDC reads; a wrong one silently advertises a different encryption type.
func TestSupportedETypesBitValues(t *testing.T) {
	t.Parallel()

	assert.Equal(t, uint32(0x00000001), SupportedETypeDESCBCCRC)
	assert.Equal(t, uint32(0x00000002), SupportedETypeDESCBCMD5)
	assert.Equal(t, uint32(0x00000004), SupportedETypeRC4HMAC)
	assert.Equal(t, uint32(0x00000008), SupportedETypeAES128CTSHMACSHA196)
	assert.Equal(t, uint32(0x00000010), SupportedETypeAES256CTSHMACSHA196)
	assert.Equal(t, uint32(0x00000020), SupportedETypeAES256CTSHMACSHA196SK)
	assert.Equal(t, uint32(0x00000040), SupportedETypeAES128CTSHMACSHA256128)
	assert.Equal(t, uint32(0x00000080), SupportedETypeAES256CTSHMACSHA384192)
	assert.Equal(t, uint32(0x00010000), SupportedETypeFAST)
	assert.Equal(t, uint32(0x00020000), SupportedETypeCompoundIdentity)
	assert.Equal(t, uint32(0x00040000), SupportedETypeClaims)
	assert.Equal(t, uint32(0x00080000), SupportedETypeResourceSIDCompressionDisabled)
}

// TestSupportedETypesShouldMapBitsToEncryptionTypes asserts each encryption type bit names the right encryption
// type, in both directions.
func TestSupportedETypesShouldMapBitsToEncryptionTypes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		bit  uint32
		id   int32
	}{
		{"DESCBCCRC", SupportedETypeDESCBCCRC, etypeID.DES_CBC_CRC},
		{"DESCBCMD5", SupportedETypeDESCBCMD5, etypeID.DES_CBC_MD5},
		{"RC4HMAC", SupportedETypeRC4HMAC, etypeID.RC4_HMAC},
		{"AES128SHA196", SupportedETypeAES128CTSHMACSHA196, etypeID.AES128_CTS_HMAC_SHA1_96},
		{"AES256SHA196", SupportedETypeAES256CTSHMACSHA196, etypeID.AES256_CTS_HMAC_SHA1_96},
		{"AES128SHA256128", SupportedETypeAES128CTSHMACSHA256128, etypeID.AES128_CTS_HMAC_SHA256_128},
		{"AES256SHA384192", SupportedETypeAES256CTSHMACSHA384192, etypeID.AES256_CTS_HMAC_SHA384_192},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.True(t, SupportedETypes(tc.bit).Contains(tc.id))
			assert.Equal(t, []int32{tc.id}, SupportedETypes(tc.bit).ETypeIDs())
			assert.Equal(t, SupportedETypes(tc.bit), NewSupportedETypesFromIDs([]int32{tc.id}))
		})
	}
}

// TestSupportedETypesShouldNotTreatTheSessionKeyPolicyBitAsAnEncryptionType asserts the J bit is excluded.
// MS-KILE Section 2.2.7 describes AES256-CTS-HMAC-SHA1-96-SK as an instruction to the KDC to enforce AES session
// keys when legacy ciphers are in use, not as an encryption type a peer can decrypt with. Reporting it as one
// would advertise an encryption type that does not exist.
func TestSupportedETypesShouldNotTreatTheSessionKeyPolicyBitAsAnEncryptionType(t *testing.T) {
	t.Parallel()

	s := SupportedETypes(SupportedETypeAES256CTSHMACSHA196SK)

	assert.Empty(t, s.ETypeIDs())
	assert.False(t, s.Contains(etypeID.AES256_CTS_HMAC_SHA1_96))
}

// TestSupportedETypesIntersectShouldDropCapabilityBits asserts that only encryption type bits survive an
// intersection. The capability bits describe what a party can do rather than what two parties share, and this
// library advertises none of them.
func TestSupportedETypesIntersectShouldDropCapabilityBits(t *testing.T) {
	t.Parallel()

	kdc := SupportedETypes(SupportedETypeAES256CTSHMACSHA196 | SupportedETypeAES128CTSHMACSHA196 |
		SupportedETypeRC4HMAC | SupportedETypeFAST | SupportedETypeClaims)
	server := SupportedETypes(SupportedETypeAES256CTSHMACSHA196 | SupportedETypeRC4HMAC |
		SupportedETypeCompoundIdentity)

	got := kdc.Intersect(server)

	assert.Equal(t, SupportedETypes(SupportedETypeAES256CTSHMACSHA196|SupportedETypeRC4HMAC), got)
	assert.Equal(t, []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC}, got.ETypeIDs())
}

// TestSupportedETypesIntersectShouldTreatZeroAsUnknown asserts an absent advertisement does not collapse the
// result to nothing. MS-KILE gives no way to distinguish "advertised none" from "did not advertise", so a zero
// value cannot be read as a claim that no encryption type is common.
func TestSupportedETypesIntersectShouldTreatZeroAsUnknown(t *testing.T) {
	t.Parallel()

	known := SupportedETypes(SupportedETypeAES256CTSHMACSHA196 | SupportedETypeFAST)
	want := SupportedETypes(SupportedETypeAES256CTSHMACSHA196)

	assert.Equal(t, want, known.Intersect(0), "an unknown peer leaves our own types standing")
	assert.Equal(t, want, SupportedETypes(0).Intersect(known), "and the same in the other direction")
	assert.True(t, SupportedETypes(0).Intersect(0).IsZero())
}

// TestNewSupportedETypesFromIDsShouldSkipUnassignedEncryptionTypes asserts an encryption type with no bit assigned
// by MS-KILE Section 2.2.7 is dropped rather than mapped to an arbitrary bit. The specification requires all other
// bits to be zero when sent.
func TestNewSupportedETypesFromIDsShouldSkipUnassignedEncryptionTypes(t *testing.T) {
	t.Parallel()

	s := NewSupportedETypesFromIDs([]int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.DES3_CBC_SHA1_KD})

	assert.Equal(t, SupportedETypes(SupportedETypeAES256CTSHMACSHA196), s)
	assert.Equal(t, []int32{etypeID.AES256_CTS_HMAC_SHA1_96}, s.ETypeIDs())
}
