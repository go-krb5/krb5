package types

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/adtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/test/testdata"
)

func unmarshalAuthenticatorTest(t *testing.T, v string) Authenticator {
	var a Authenticator

	b, err := hex.DecodeString(v)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	return a
}

func TestUnmarshalAuthenticator(t *testing.T) {
	t.Parallel()
	a := unmarshalAuthenticatorTest(t, testdata.MarshaledKRB5authenticator)
	// Parse the test time value into a time.Time type.
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.AVNO)
	assert.Equal(t, testdata.TEST_REALM, a.CRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString)
	assert.Equal(t, int32(1), a.Cksum.CksumType)
	assert.Equal(t, []byte("1234"), a.Cksum.Checksum)
	assert.Equal(t, 123456, a.Cusec)
	assert.Equal(t, tt, a.CTime)
	assert.Equal(t, int32(1), a.SubKey.KeyType)
	assert.Equal(t, []byte("12345678"), a.SubKey.KeyValue)
	assert.Equal(t, 2, len(a.AuthorizationData))

	for _, entry := range a.AuthorizationData {
		assert.Equal(t, adtype.ADIfRelevant, entry.ADType)
		assert.Equal(t, []byte(testdata.TEST_AUTHORIZATION_DATA_VALUE), entry.ADData)
	}
}

func TestUnmarshalAuthenticator_optionalsempty(t *testing.T) {
	t.Parallel()
	a := unmarshalAuthenticatorTest(t, testdata.MarshaledKRB5authenticatorOptionalsEmpty)
	// Parse the test time value into a time.Time type.
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.AVNO)
	assert.Equal(t, testdata.TEST_REALM, a.CRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString)
	assert.Equal(t, 123456, a.Cusec)
	assert.Equal(t, tt, a.CTime)
}

func TestUnmarshalAuthenticator_optionalsNULL(t *testing.T) {
	t.Parallel()
	a := unmarshalAuthenticatorTest(t, testdata.MarshaledKRB5authenticatorOptionalsNULL)
	// Parse the test time value into a time.Time type.
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.AVNO)
	assert.Equal(t, testdata.TEST_REALM, a.CRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString)
	assert.Equal(t, 123456, a.Cusec)
	assert.Equal(t, tt, a.CTime)
}

func TestMarshalAuthenticator(t *testing.T) {
	t.Parallel()

	var a Authenticator

	b, err := hex.DecodeString(testdata.MarshaledKRB5authenticator)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	mb, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)
}
