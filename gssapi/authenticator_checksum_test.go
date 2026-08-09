package gssapi

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthenticatorChecksumMarshalShouldProduce24OctetsWithoutDelegation pins the default path: the checksum an
// initiator that is not delegating emits must be byte for byte what it was before delegation existed.
func TestAuthenticatorChecksumMarshalShouldProduce24OctetsWithoutDelegation(t *testing.T) {
	t.Parallel()

	c := &AuthenticatorChecksum{Flags: ContextFlagInteg | ContextFlagConf}

	b, err := c.Marshal()
	require.NoError(t, err)

	require.Len(t, b, 24)
	assert.Equal(t, uint32(16), binary.LittleEndian.Uint32(b[:4]))
	assert.Equal(t, make([]byte, 16), b[4:20])
	assert.Equal(t, uint32(ContextFlagInteg|ContextFlagConf), binary.LittleEndian.Uint32(b[20:24]))
}

// TestAuthenticatorChecksumMarshalShouldAppendDelegation asserts the DlgOpt, Dlgth and Deleg fields of RFC 4121
// Section 4.1.1 follow Flags, and that the delegation flag is derived from the field rather than trusted from the
// caller.
func TestAuthenticatorChecksumMarshalShouldAppendDelegation(t *testing.T) {
	t.Parallel()

	deleg := []byte("a marshalled KRB_CRED")

	c := &AuthenticatorChecksum{Flags: ContextFlagInteg, Deleg: deleg}

	b, err := c.Marshal()
	require.NoError(t, err)

	require.Len(t, b, 28+len(deleg))
	assert.Equal(t, uint32(ContextFlagInteg|ContextFlagDeleg), binary.LittleEndian.Uint32(b[20:24]),
		"a non-empty Deleg must set GSS_C_DELEG_FLAG so the field and the flag cannot disagree")
	assert.Equal(t, uint16(1), binary.LittleEndian.Uint16(b[24:26]), "DlgOpt is the delegation option identifier 1")
	assert.Equal(t, uint16(len(deleg)), binary.LittleEndian.Uint16(b[26:28]))
	assert.Equal(t, deleg, b[28:])
}

// TestAuthenticatorChecksumMarshalShouldRefuseTheFlagWithoutTheField pins the defect this type exists to make
// unrepresentable: a 28 octet checksum claiming a delegation with all its delegation fields zeroed. MIT rejects
// that with GSS_S_FAILURE on reading DlgOpt as 0.
func TestAuthenticatorChecksumMarshalShouldRefuseTheFlagWithoutTheField(t *testing.T) {
	t.Parallel()

	c := &AuthenticatorChecksum{Flags: ContextFlagInteg | ContextFlagDeleg}

	b, err := c.Marshal()

	require.ErrorIs(t, err, ErrDelegationMissing)
	assert.Nil(t, b)
}

// TestAuthenticatorChecksumMarshalShouldRefuseAnOversizeDelegation asserts the MIT interoperability bound. MIT's
// init_sec_context.c rejects credmsg.length+28 > KRB5_INT16_MAX, so a KRB_CRED larger than 32739 octets is one no
// MIT acceptor is prepared to read even though the two octet Dlgth field could express it.
func TestAuthenticatorChecksumMarshalShouldRefuseAnOversizeDelegation(t *testing.T) {
	t.Parallel()

	atLimit := &AuthenticatorChecksum{Deleg: bytes.Repeat([]byte{0xAA}, ChecksumMaxDelegLen)}
	b, err := atLimit.Marshal()
	require.NoError(t, err, "the largest interoperable Deleg must still marshal")
	assert.Len(t, b, 28+ChecksumMaxDelegLen)

	over := &AuthenticatorChecksum{Deleg: bytes.Repeat([]byte{0xAA}, ChecksumMaxDelegLen+1)}
	b, err = over.Marshal()
	require.ErrorIs(t, err, ErrDelegationTooLarge)
	assert.Nil(t, b)
}

// TestAuthenticatorChecksumExtsShouldFollowWhicheverFieldIsLast asserts the placement RFC 4121 Section 4.1.1 gives
// Exts: "When delegation is not used, but the Exts field is present, the Exts field starts at octet 24."
func TestAuthenticatorChecksumExtsShouldFollowWhicheverFieldIsLast(t *testing.T) {
	t.Parallel()

	exts := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	without := &AuthenticatorChecksum{Exts: exts}
	b, err := without.Marshal()
	require.NoError(t, err)
	require.Len(t, b, 24+len(exts))
	assert.Equal(t, exts, b[24:])

	with := &AuthenticatorChecksum{Deleg: []byte("cred"), Exts: exts}
	b, err = with.Marshal()
	require.NoError(t, err)
	require.Len(t, b, 28+4+len(exts))
	assert.Equal(t, exts, b[32:])
}

// TestAuthenticatorChecksumShouldRoundTrip covers both regimes through Marshal then Unmarshal.
func TestAuthenticatorChecksumShouldRoundTrip(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   AuthenticatorChecksum
	}{
		{"NoDelegation", AuthenticatorChecksum{Bnd: [16]byte{1, 2, 3}, Flags: ContextFlagConf}},
		{"WithDelegation", AuthenticatorChecksum{Bnd: [16]byte{4, 5, 6}, Flags: ContextFlagConf, Deleg: []byte("cred")}},
		{"WithExts", AuthenticatorChecksum{Flags: ContextFlagConf, Exts: []byte{9, 9}}},
		{"WithBoth", AuthenticatorChecksum{Flags: ContextFlagConf, Deleg: []byte("cred"), Exts: []byte{9, 9}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b, err := tc.in.Marshal()
			require.NoError(t, err)

			var out AuthenticatorChecksum
			require.NoError(t, out.Unmarshal(b))

			assert.Equal(t, tc.in.Bnd, out.Bnd)
			assert.Equal(t, tc.in.Deleg, out.Deleg)
			assert.Equal(t, tc.in.Exts, out.Exts)
			assert.Equal(t, len(tc.in.Deleg) > 0, out.Delegated())
		})
	}
}

// TestAuthenticatorChecksumUnmarshalShouldTolerateAShortChecksum asserts the leniency that keeps this parser from
// rejecting AP_REQs that succeed today. VerifyAPREQ now parses unconditionally to discover whether delegation is
// claimed, parsing more often must not reject more often.
func TestAuthenticatorChecksumUnmarshalShouldTolerateAShortChecksum(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"Empty", nil},
		{"OneOctetShort", make([]byte, 23)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var c AuthenticatorChecksum

			require.NoError(t, c.Unmarshal(tc.in), "a checksum too short to interpret is not an error here")
			assert.False(t, c.Delegated())
			assert.Nil(t, c.Deleg)
		})
	}
}

// TestAuthenticatorChecksumUnmarshalShouldRejectAnUnsupportedLgth asserts the parser reports a layout it cannot
// interpret rather than reading fixed offsets anyway. Lgth is the width of Bnd, so any value other than 16 moves
// Flags and everything after it.
func TestAuthenticatorChecksumUnmarshalShouldRejectAnUnsupportedLgth(t *testing.T) {
	t.Parallel()

	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[:4], 8)

	var c AuthenticatorChecksum

	err := c.Unmarshal(b)

	var lgthErr ChecksumLgthError

	require.ErrorAs(t, err, &lgthErr)
	assert.Equal(t, uint32(8), lgthErr.Lgth)
	assert.Contains(t, err.Error(), "declares a Bnd length of 8 rather than 16")
	assert.False(t, c.Delegated(), "the struct is left zeroed when the layout cannot be interpreted")
}

// TestAuthenticatorChecksumUnmarshalShouldRejectMalformedDelegation asserts that once a checksum claims delegation,
// strictness applies. A checksum that says it carries a credential and then does not is defective.
func TestAuthenticatorChecksumUnmarshalShouldRejectMalformedDelegation(t *testing.T) {
	t.Parallel()

	// delegChecksum builds a well formed delegating checksum, then applies mutate to it.
	delegChecksum := func(mutate func([]byte)) []byte {
		c := &AuthenticatorChecksum{Deleg: []byte("cred")}
		b, err := c.Marshal()
		require.NoError(t, err)
		mutate(b)

		return b
	}

	for _, tc := range []struct {
		name    string
		in      []byte
		wantMsg string
	}{
		{
			name:    "TruncatedBeforeDlgth",
			in:      delegChecksum(func(b []byte) {})[:26],
			wantMsg: "too short to carry the delegation fields",
		},
		{
			name:    "WrongDlgOpt",
			in:      delegChecksum(func(b []byte) { binary.LittleEndian.PutUint16(b[24:26], 2) }),
			wantMsg: "delegation option identifier 2 rather than 1",
		},
		{
			name:    "DlgthPastTheEnd",
			in:      delegChecksum(func(b []byte) { binary.LittleEndian.PutUint16(b[26:28], 4096) }),
			wantMsg: "declares a Deleg length of 4096",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var c AuthenticatorChecksum

			err := c.Unmarshal(tc.in)

			require.ErrorIs(t, err, ErrDelegationMalformed)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

// TestAuthenticatorChecksumMarshalShouldClearUndefinedFlags asserts the sender obligation of RFC 4121 Section
// 4.1.1.1: "Undefined flag values MUST be cleared by the sender, and unknown flags MUST be ignored by the
// receiver." Before this mask existed, ContextFlagAnon and any high bit a caller passed reached the wire.
func TestAuthenticatorChecksumMarshalShouldClearUndefinedFlags(t *testing.T) {
	t.Parallel()

	c := &AuthenticatorChecksum{
		Flags: ContextFlagInteg | ContextFlagConf | ContextFlagAnon | 0x00000100 | 0x80000000,
	}

	b, err := c.Marshal()
	require.NoError(t, err)

	assert.Equal(t, uint32(ContextFlagInteg|ContextFlagConf), binary.LittleEndian.Uint32(b[20:24]),
		"ContextFlagAnon, GSS_C_TRANS_FLAG and the undefined high bit must all be cleared")
}

// TestAuthenticatorChecksumMarshalShouldPreserveTheVendorFlagRange asserts the mask does not break Windows or MIT.
// RFC 4121 Section 4.1.1.1 reserves flag values 4096 to 524288 "for use with legacy vendor-specific extensions to
// this mechanism", and that is where the RFC 4757 Section 7.1 flags MS-KILE sets in this field live:
// GSS_C_DCE_STYLE 0x1000, GSS_C_IDENTIFY_FLAG 0x2000 and GSS_C_EXTENDED_ERROR_FLAG 0x4000, plus MIT's
// GSS_C_DELEG_POLICY_FLAG 0x8000. Clearing those would be a conformance fix that broke interoperation.
func TestAuthenticatorChecksumMarshalShouldPreserveTheVendorFlagRange(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		flag uint32
	}{
		{"GSSCDCEStyle", 0x1000},
		{"GSSCIdentify", 0x2000},
		{"GSSCExtendedError", 0x4000},
		{"GSSCDelegPolicy", 0x8000},
		{"ReservedRangeLowBit", 1 << 12},
		{"ReservedRangeHighBit", 1 << 19},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := &AuthenticatorChecksum{Flags: ContextFlagInteg | tc.flag}

			b, err := c.Marshal()
			require.NoError(t, err)

			assert.Equal(t, ContextFlagInteg|tc.flag, binary.LittleEndian.Uint32(b[20:24]))
		})
	}

	// The bit immediately above the reserved range is not vendor space and must go.
	c := &AuthenticatorChecksum{Flags: ContextFlagInteg | (1 << 20)}

	b, err := c.Marshal()
	require.NoError(t, err)
	assert.Equal(t, uint32(ContextFlagInteg), binary.LittleEndian.Uint32(b[20:24]))
}

// TestAuthenticatorChecksumMarshalShouldStillRefuseDelegationAfterMasking asserts the mask does not defeat the
// flag-without-field guard: ContextFlagDeleg survives the mask, so a caller setting it with an empty Deleg is
// still refused rather than quietly emitting a 24 octet checksum.
func TestAuthenticatorChecksumMarshalShouldStillRefuseDelegationAfterMasking(t *testing.T) {
	t.Parallel()

	c := &AuthenticatorChecksum{Flags: ContextFlagDeleg | ContextFlagAnon}

	b, err := c.Marshal()

	require.ErrorIs(t, err, ErrDelegationMissing)
	assert.Nil(t, b)
}
