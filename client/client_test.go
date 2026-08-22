package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
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

func TestKeyShouldSaltWithTheClientsOwnPrincipalNotTheKRBErrors(t *testing.T) {
	t.Parallel()

	// RFC 4120 Section 3.1: a KRB-ERROR is not integrity protected, so the principal and realm it names are the
	// attacker's choice on any path where the error can be substituted. The default string-to-key salt must come
	// from the identity the client is authenticating as.
	pas, err := asn1.Marshal(types.PADataSequence{},
		asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	krberr := messages.KRBError{
		ErrorCode: errorcode.KDC_ERR_PREAUTH_REQUIRED,
		CName:     types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "attacker"),
		CRealm:    attackerRealm,
		EData:     pas,
	}

	cl := NewWithPassword("testuser", "TEST.GOKRB5", "passwordvalue", &config.Config{})

	et, err := crypto.GetEType(etypeID.AES256_CTS_HMAC_SHA1_96)
	require.NoError(t, err)

	key, _, err := cl.Key(et, 0, &krberr)
	require.NoError(t, err)

	expected, _, err := crypto.GetKeyFromPassword("passwordvalue", cl.Credentials.CName(), cl.Credentials.Domain(),
		etypeID.AES256_CTS_HMAC_SHA1_96, types.PADataSequence{})
	require.NoError(t, err)

	assert.Equal(t, expected.KeyValue, key.KeyValue)
}

func TestKeyShouldStillHonourTheExplicitSaltInTheKRBErrors(t *testing.T) {
	t.Parallel()

	// RFC 4120 Section 5.2.7.5: the salt in PA-ETYPE-INFO2 is what the KDC actually stretched the password with,
	// so it is honoured even though it too arrives unauthenticated. Only the default is taken from the client.
	info := types.ETypeInfo2{{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Salt: "TEST.GOKRB5explicitsalt"}}

	v, err := asn1.Marshal(info, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	pas, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: v}},
		asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	krberr := messages.KRBError{
		ErrorCode: errorcode.KDC_ERR_PREAUTH_REQUIRED,
		CName:     types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "attacker"),
		CRealm:    attackerRealm,
		EData:     pas,
	}

	cl := NewWithPassword("testuser", "TEST.GOKRB5", "passwordvalue", &config.Config{})

	et, err := crypto.GetEType(etypeID.AES256_CTS_HMAC_SHA1_96)
	require.NoError(t, err)

	key, _, err := cl.Key(et, 0, &krberr)
	require.NoError(t, err)

	expected, err := et.StringToKey("passwordvalue", "TEST.GOKRB5explicitsalt", et.GetDefaultStringToKeyParams())
	require.NoError(t, err)

	assert.Equal(t, expected, key.KeyValue)
}

const attackerRealm = "EVIL.GOKRB5"
