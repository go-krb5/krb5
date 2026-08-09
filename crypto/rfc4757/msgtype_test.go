package rfc4757

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/keyusage"
)

// TestUsageToMSMsgTypeShouldFollowRFC4757Table asserts the key usage to message type mapping enumerated by RFC 4757
// Section 3, which lists a T value for each of the fifteen key usages it covers. Most usages carry their own number
// through unchanged; the two that do not are items 3 and 9, both of which RFC 4757 gives T=8.
//
// T is the value HMACed into the key derivation of every RC4-HMAC operation (see Encrypt, Checksum and DeriveKey), so
// a wrong value here does not fail loudly. It produces a key both peers compute differently, and the only symptom is
// an integrity check failure with nothing pointing at the cause.
func TestUsageToMSMsgTypeShouldFollowRFC4757Table(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		usage uint32
		want  uint32
	}{
		{"AsReqPaEncTimestamp", 1, 1},
		{"AsRepTicket", 2, 2},
		{"AsRepEncPartClientKey", 3, 8},
		{"TgsReqAuthorizationDataSessionKey", 4, 4},
		{"TgsReqAuthorizationDataSubkey", 5, 5},
		{"TgsReqAuthenticatorCksum", 6, 6},
		{"TgsReqAuthenticator", 7, 7},
		{"TgsRepEncPartSessionKey", 8, 8},
		{"TgsRepEncPartSubkey", 9, 8},
		{"ApReqAuthenticatorCksum", 10, 10},
		{"ApReqAuthenticator", 11, 11},
		{"ApRepEncPart", 12, 12},
		{"KrbPrivEncPart", 13, 13},
		{"KrbCredEncPart", 14, 14},
		{"KrbSafeCksum", 15, 15},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tb := UsageToMSMsgType(tc.usage)

			require.Len(t, tb, 4, "T is a four octet field")
			assert.Equal(t, tc.want, binary.LittleEndian.Uint32(tb))
		})
	}
}

// TestUsageToMSMsgTypeShouldEncodeLittleEndianNotVarint pins the encoding itself. RFC 4757 Sections 3, 4 and 5 each
// state that T is "encoded as a little-endian four-byte integer", and this was implemented with binary.PutUvarint
// until it was corrected.
//
// The two encodings agree for every value below 128, which is why the varint implementation interoperated: the
// largest T that RFC 4757 assigns is 15. They diverge from 128 upwards, so this asserts the divergence directly. No
// real key usage reaches that value today, which is exactly why the encoding needs a test rather than a caller to
// catch a regression.
func TestUsageToMSMsgTypeShouldEncodeLittleEndianNotVarint(t *testing.T) {
	t.Parallel()

	// Below the varint continuation-bit boundary the two encodings coincide, so a T in RFC 4757's range cannot
	// distinguish them.
	for _, usage := range []uint32{1, 15, 127} {
		varint := make([]byte, 4)
		binary.PutUvarint(varint, uint64(usage))

		assert.Equal(t, varint, UsageToMSMsgType(usage),
			"below 128 the little-endian and varint encodings agree, so real T values cannot detect the difference")
	}

	// At and above 128 a varint sets the continuation bit and spills into the second octet, which is not a
	// little-endian uint32 any longer.
	varint := make([]byte, 4)
	binary.PutUvarint(varint, 128)
	require.Equal(t, []byte{0x80, 0x01, 0x00, 0x00}, varint, "a varint of 128 spills into the second octet")

	assert.Equal(t, []byte{0x80, 0x00, 0x00, 0x00}, UsageToMSMsgType(128),
		"T must be a little-endian four octet integer, never a varint")
}

// TestUsageToMSMsgTypeGSSAPIUsages documents the mapping for the GSS-API per-message key usages of RFC 4121, which
// fall outside the fifteen items RFC 4757 Section 3 enumerates.
//
// This records current behaviour rather than asserting it is right. RFC 4757 item 13 covers "data encrypted with GSS
// Wrap" (T=13) and item 15 covers "data signed in GSS MIC" (T=15), yet GSSAPI_ACCEPTOR_SIGN is mapped to 13 here, the
// wrap value, while the three other GSS-API usages pass through unchanged as 22, 24 and 25; none of which appears in
// RFC 4757 at all. Whether that is a bug or an undocumented match for what Windows actually does has not been
// established; do not change it without testing against a real Windows KDC. RC4-HMAC is deprecated and no longer
// registered by default (see BREAKING.md), so this path is unreachable unless an application opts back in with
// crypto.RegisterDeprecatedRC4HMAC.
func TestUsageToMSMsgTypeGSSAPIUsages(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		usage uint32
		want  uint32
	}{
		{"AcceptorSeal", keyusage.GSSAPI_ACCEPTOR_SEAL, 22},
		{"AcceptorSign", keyusage.GSSAPI_ACCEPTOR_SIGN, 13},
		{"InitiatorSeal", keyusage.GSSAPI_INITIATOR_SEAL, 24},
		{"InitiatorSign", keyusage.GSSAPI_INITIATOR_SIGN, 25},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, binary.LittleEndian.Uint32(UsageToMSMsgType(tc.usage)))
		})
	}
}
