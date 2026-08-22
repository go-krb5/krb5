package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/types"
)

func TestGetKeyFromPasswordShouldDeriveWithTheChosenETypesStringToKeyParams(t *testing.T) {
	t.Parallel()

	pas := etypeInfo2PAData(t, types.ETypeInfo2{{EType: etypeID.AES256_CTS_HMAC_SHA384_192, Salt: s2kSalt}})

	cname := types.PrincipalName{NameString: []string{s2kUser}}

	key, et, err := GetKeyFromPassword(s2kPassword, cname, s2kRealm, etypeID.AES256_CTS_HMAC_SHA1_96, pas)
	require.NoError(t, err)
	require.Equal(t, etypeID.AES256_CTS_HMAC_SHA384_192, et.GetETypeID())

	expected, err := et.StringToKey(s2kPassword, s2kSalt, et.GetDefaultStringToKeyParams())
	require.NoError(t, err)

	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordShouldPreferAnExplicitS2KParamsOverTheDefault(t *testing.T) {
	t.Parallel()

	// RFC 4120 Section 5.2.7.5 carries s2kparams for the KDC to state a count that is not the type's default.
	iterations, err := hex.DecodeString("00001000")
	require.NoError(t, err)

	pas := etypeInfo2PAData(t, types.ETypeInfo2{
		{EType: etypeID.AES256_CTS_HMAC_SHA384_192, Salt: s2kSalt, S2KParams: iterations},
	})

	cname := types.PrincipalName{NameString: []string{s2kUser}}

	key, et, err := GetKeyFromPassword(s2kPassword, cname, s2kRealm, etypeID.AES256_CTS_HMAC_SHA1_96, pas)
	require.NoError(t, err)
	require.Equal(t, etypeID.AES256_CTS_HMAC_SHA384_192, et.GetETypeID())

	expected, err := et.StringToKey(s2kPassword, s2kSalt, "00001000")
	require.NoError(t, err)

	assert.Equal(t, expected, key.KeyValue)
	require.NotEqual(t, "00001000", et.GetDefaultStringToKeyParams())
}

func TestGetKeyFromPasswordShouldDeriveWithTheChosenETypesParamsThroughETypeInfo(t *testing.T) {
	t.Parallel()

	// PA-ETYPE-INFO has no s2kparams field at all, so the type it names can only be derived with that type's
	// own default.
	info := types.ETypeInfo{{EType: etypeID.AES256_CTS_HMAC_SHA384_192, Salt: []byte(s2kSalt)}}

	v, err := asn1.Marshal(info, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO, PADataValue: v}}

	cname := types.PrincipalName{NameString: []string{s2kUser}}

	key, et, err := GetKeyFromPassword(s2kPassword, cname, s2kRealm, etypeID.AES256_CTS_HMAC_SHA1_96, pas)
	require.NoError(t, err)
	require.Equal(t, etypeID.AES256_CTS_HMAC_SHA384_192, et.GetETypeID())

	expected, err := et.StringToKey(s2kPassword, s2kSalt, et.GetDefaultStringToKeyParams())
	require.NoError(t, err)

	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordShouldDeriveWithTheRequestedETypesParamsWithoutPAData(t *testing.T) {
	t.Parallel()

	cname := types.PrincipalName{NameString: []string{s2kUser}}

	key, et, err := GetKeyFromPassword(s2kPassword, cname, s2kRealm, etypeID.AES256_CTS_HMAC_SHA1_96,
		types.PADataSequence{})
	require.NoError(t, err)
	require.Equal(t, etypeID.AES256_CTS_HMAC_SHA1_96, et.GetETypeID())

	expected, err := et.StringToKey(s2kPassword, cname.GetSalt(s2kRealm), et.GetDefaultStringToKeyParams())
	require.NoError(t, err)

	assert.Equal(t, expected, key.KeyValue)
}

const (
	s2kPassword = "passwordvalue"
	s2kSalt     = "TEST.GOKRB5testuser"
	s2kRealm    = "TEST.GOKRB5"
	s2kUser     = "testuser"
)

func etypeInfo2PAData(t *testing.T, info types.ETypeInfo2) types.PADataSequence {
	t.Helper()

	v, err := asn1.Marshal(info, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	return types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: v}}
}
