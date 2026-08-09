package types

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/iana/flags"
)

func TestKerberosFlags_SetFlag(t *testing.T) {
	t.Parallel()

	b := []byte{byte(64), byte(0), byte(0), byte(16)}

	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	assert.Equal(t, b, f.Bytes)
}

func TestKerberosFlags_UnsetFlag(t *testing.T) {
	t.Parallel()

	b := []byte{byte(64), byte(0), byte(0), byte(0)}

	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	UnsetFlag(&f, flags.RenewableOK)
	assert.Equal(t, b, f.Bytes)
}

func TestKerberosFlags_IsFlagSet(t *testing.T) {
	t.Parallel()

	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	UnsetFlag(&f, flags.Proxiable)
	assert.True(t, IsFlagSet(&f, flags.Forwardable))
	assert.True(t, IsFlagSet(&f, flags.RenewableOK))
	assert.False(t, IsFlagSet(&f, flags.Proxiable))
}

// TestKerberosFlagsIsFlagSetShouldNotIndexPastAShortBitString covers flags that arrived from the wire rather than
// from SetFlag. A BIT STRING carries its own length, so a peer can encode an empty or truncated one: the KrbCredInfo
// of a delegated KRB_CRED reaches credentials.Credential.TicketFlags unaltered, and reading a flag out of it used to
// index past the end and panic the process.
func TestKerberosFlagsIsFlagSetShouldNotIndexPastAShortBitString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		flags asn1.BitString
		flag  int
	}{
		{"ShouldReportUnsetForAZeroValue", asn1.BitString{}, flags.Forwardable},
		{"ShouldReportUnsetForAnEmptyByteSlice", asn1.BitString{Bytes: []byte{}, BitLength: 0}, flags.Forwardable},
		{"ShouldReportUnsetForAFlagPastTheEnd", asn1.BitString{Bytes: []byte{0xff}, BitLength: 8}, flags.RenewableOK},
		{"ShouldReportUnsetForANegativeFlag", asn1.BitString{Bytes: []byte{0xff, 0xff, 0xff, 0xff}, BitLength: 32}, -1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := tc.flags

			assert.NotPanics(t, func() {
				assert.False(t, IsFlagSet(&f, tc.flag))
			})
		})
	}
}

// TestKerberosFlagsSetAndUnsetShouldNotIndexPastTheBitString covers the same exposure on the mutating helpers: a
// flag number beyond the four octets they pad to, and a negative one, must not index out of range.
func TestKerberosFlagsSetAndUnsetShouldNotIndexPastTheBitString(t *testing.T) {
	t.Parallel()

	t.Run("SetFlagShouldGrowForAFlagPastFourOctets", func(t *testing.T) {
		t.Parallel()

		var f asn1.BitString

		assert.NotPanics(t, func() { SetFlag(&f, 32) })
		assert.Equal(t, []byte{0, 0, 0, 0, 128}, f.Bytes)
		assert.Equal(t, 40, f.BitLength)
		assert.True(t, IsFlagSet(&f, 32))
	})

	t.Run("SetFlagShouldIgnoreANegativeFlag", func(t *testing.T) {
		t.Parallel()

		var f asn1.BitString

		assert.NotPanics(t, func() { SetFlag(&f, -1) })
		assert.Empty(t, f.Bytes)
	})

	t.Run("UnsetFlagShouldIgnoreAFlagPastTheEnd", func(t *testing.T) {
		t.Parallel()

		var f asn1.BitString
		SetFlag(&f, flags.Forwardable)

		assert.NotPanics(t, func() { UnsetFlag(&f, 32) })
		assert.Equal(t, []byte{64, 0, 0, 0}, f.Bytes)
		assert.True(t, IsFlagSet(&f, flags.Forwardable))
	})

	t.Run("UnsetFlagShouldIgnoreANegativeFlag", func(t *testing.T) {
		t.Parallel()

		var f asn1.BitString
		SetFlag(&f, flags.Forwardable)

		assert.NotPanics(t, func() { UnsetFlag(&f, -1) })
		assert.Equal(t, []byte{64, 0, 0, 0}, f.Bytes)
	})
}
