package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/adtype"
)

// TestADAPOptionsShouldRoundTripTheWireFormat pins the encoding MS-KILE Section 3.2.5.2 fixes: the ad-data of
// KERB_AP_OPTIONS_CBT "encoded as a four byte little-endian unsigned integer".
func TestADAPOptionsShouldRoundTripTheWireFormat(t *testing.T) {
	t.Parallel()

	b := ADAPOptions(ADAPOptionsCBT).Marshal()

	require.Len(t, b, 4)
	assert.Equal(t, []byte{0x00, 0x40, 0x00, 0x00}, b, "0x4000 little-endian")

	o, err := UnmarshalADAPOptions(b)
	require.NoError(t, err)
	assert.True(t, o.Has(ADAPOptionsCBT))
	assert.False(t, o.Has(ADAPOptionsUnverifiedTargetName))
}

// TestUnmarshalADAPOptionsShouldRejectAWrongWidth asserts a value that is not four octets is refused rather than
// read from whatever is present.
func TestUnmarshalADAPOptionsShouldRejectAWrongWidth(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"Empty", nil},
		{"Short", []byte{0x00, 0x40, 0x00}},
		{"Long", []byte{0x00, 0x40, 0x00, 0x00, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := UnmarshalADAPOptions(tc.in)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "rather than 4")
		})
	}
}

// TestADAPOptionsAuthorizationDataShouldNestInADIfRelevant asserts the container MS-KILE Section 3.2.5.2 requires:
// the element goes "in the first AD-IF-RELEVANT element". A bare top level entry would be read by acceptors that
// do not understand it as mandatory authorization data rather than as advisory.
func TestADAPOptionsAuthorizationDataShouldNestInADIfRelevant(t *testing.T) {
	t.Parallel()

	ad, err := ADAPOptions(ADAPOptionsCBT).AuthorizationData()
	require.NoError(t, err)

	require.Len(t, ad, 1)
	assert.Equal(t, adtype.ADIfRelevant, ad[0].ADType)

	assert.True(t, ADAPOptionsFromAuthorizationData(ad).Has(ADAPOptionsCBT),
		"what we write must be what we read")
}

// TestADAPOptionsFromAuthorizationDataShouldToleratePlacement asserts the reader accepts the value nested as
// MS-KILE specifies and bare at the top level. The value says what a peer supports; a peer that placed it one
// level out has still said it.
func TestADAPOptionsFromAuthorizationDataShouldToleratePlacement(t *testing.T) {
	t.Parallel()

	nested, err := ADAPOptions(ADAPOptionsCBT).AuthorizationData()
	require.NoError(t, err)
	assert.True(t, ADAPOptionsFromAuthorizationData(nested).Has(ADAPOptionsCBT))

	bare := AuthorizationData{
		{ADType: adtype.ADAuthDataAPOptions, ADData: ADAPOptions(ADAPOptionsCBT).Marshal()},
	}
	assert.True(t, ADAPOptionsFromAuthorizationData(bare).Has(ADAPOptionsCBT))
}

// TestADAPOptionsFromAuthorizationDataShouldReturnZeroWhenAbsentOrMalformed asserts the absence of the element and
// a corrupt one are both reported as "not advertised" rather than as an error. The value is read to learn what a
// peer supports, so failing the exchange over it would trade a working authentication for a hint.
func TestADAPOptionsFromAuthorizationDataShouldReturnZeroWhenAbsentOrMalformed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   AuthorizationData
	}{
		{"Nil", nil},
		{"Empty", AuthorizationData{}},
		{"OtherType", AuthorizationData{{ADType: adtype.ADWin2KPAC, ADData: []byte{1, 2, 3, 4}}}},
		{"MalformedValue", AuthorizationData{{ADType: adtype.ADAuthDataAPOptions, ADData: []byte{1, 2}}}},
		{"MalformedNesting", AuthorizationData{{ADType: adtype.ADIfRelevant, ADData: []byte{0xFF, 0xFF}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Zero(t, ADAPOptionsFromAuthorizationData(tc.in))
		})
	}
}
