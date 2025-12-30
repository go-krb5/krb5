package types

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/adtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestUnmarshalAuthorizationData(t *testing.T) {
	t.Parallel()

	var a AuthorizationData

	b, err := hex.DecodeString(testdata.MarshaledKRB5authorization_data)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, 2, len(a))

	for _, entry := range a {
		assert.Equal(t, adtype.ADIfRelevant, entry.ADType)
		assert.Equal(t, []byte("foobar"), entry.ADData)
	}
}

func TestUnmarshalAuthorizationData_kdcissued(t *testing.T) {
	t.Parallel()

	var a ADKDCIssued

	b, err := hex.DecodeString(testdata.MarshaledKRB5ad_kdcissued)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, int32(1), a.ADChecksum.CksumType)
	assert.Equal(t, []byte("1234"), a.ADChecksum.Checksum)
	assert.Equal(t, testdata.TEST_REALM, a.IRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Isname.NameType)
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Isname.NameString)
	assert.Equal(t, 2, len(a.Elements))

	for _, ele := range a.Elements {
		assert.Equal(t, adtype.ADIfRelevant, ele.ADType)
		assert.Equal(t, []byte(testdata.TEST_AUTHORIZATION_DATA_VALUE), ele.ADData)
	}
}
