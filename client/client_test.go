package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

func TestAssumePreauthentication(t *testing.T) {
	t.Parallel()

	cl := NewWithKeytab("username", "REALM", &keytab.Keytab{}, &config.Config{}, AssumePreAuthentication(true))

	require.True(t, cl.settings.assumePreAuthentication)
	require.True(t, cl.settings.AssumePreAuthentication())
}

func TestPreAuthETypeRejectsEmptyETypeInfo(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		patyp int32
		value any
	}{
		{"empty ETYPE-INFO2", patype.PA_ETYPE_INFO2, types.ETypeInfo2{}},
		{"empty ETYPE-INFO", patype.PA_ETYPE_INFO, types.ETypeInfo{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			v, err := asn1.Marshal(tc.value,
				asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
			require.NoError(t, err)

			pas, err := asn1.Marshal(types.PADataSequence{{PADataType: tc.patyp, PADataValue: v}},
				asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
			require.NoError(t, err)

			krberr := messages.KRBError{EData: pas}

			require.NotPanics(t, func() {
				_, err := preAuthEType(&krberr)
				assert.Error(t, err)
			})
		})
	}
}

func TestPreAuthETypeSkipsUnsupportedEntries(t *testing.T) {
	t.Parallel()

	info := types.ETypeInfo2{
		{EType: etypeID.RC4_HMAC},
		{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Salt: "TEST.GOKRB5testuser"},
	}

	v, err := asn1.Marshal(info, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	pas, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: v}},
		asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	krberr := messages.KRBError{EData: pas}

	et, err := preAuthEType(&krberr)

	require.NoError(t, err)
	assert.Equal(t, etypeID.AES256_CTS_HMAC_SHA1_96, et.GetETypeID())
}
