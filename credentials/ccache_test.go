package credentials

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestParse(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)

	c := new(CCache)

	require.NoError(t, c.Unmarshal(b))

	assert.Equal(t, uint8(4), c.Version, "Version not as expected")
	assert.Equal(t, 1, len(c.Header.fields), "Number of header fields not as expected")
	assert.Equal(t, uint16(1), c.Header.fields[0].tag, "Header tag not as expected")
	assert.Equal(t, uint16(8), c.Header.fields[0].length, "Length of header not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.DefaultPrincipal.Realm)
	assert.Equal(t, "testuser1", c.DefaultPrincipal.PrincipalName.PrincipalNameString(), "Default client principaal name not as expected")
	assert.Equal(t, 3, len(c.Credentials), "Number of credentials not as expected")

	tgtpn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", "TEST.GOKRB5"},
	}
	assert.True(t, c.Contains(tgtpn), "Cache does not contain TGT credential")

	httppn := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	assert.True(t, c.Contains(httppn), "Cache does not contain HTTP SPN credential")
}

func TestCCache_GetClientPrincipalName(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)

	c := new(CCache)

	require.NoError(t, c.Unmarshal(b))

	pn := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"testuser1"},
	}
	assert.Equal(t, pn, c.GetClientPrincipalName(), "Client PrincipalName not as expected")
}

func TestCCache_GetClientCredentials(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)

	c := new(CCache)

	require.NoError(t, c.Unmarshal(b))

	pn := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"testuser1"},
	}

	cred := c.GetClientCredentials()
	assert.Equal(t, "TEST.GOKRB5", cred.Domain(), "Client realm in credential not as expected")
	assert.Equal(t, pn, cred.CName(), "Client Principal Name not as expected")
	assert.Equal(t, "testuser1", cred.UserName(), "Username not as expected")
}

func TestCCache_GetClientRealm(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)

	c := new(CCache)

	require.NoError(t, c.Unmarshal(b))

	assert.Equal(t, "TEST.GOKRB5", c.GetClientRealm(), "Client realm not as expected")
}

func TestCCache_GetEntry(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)

	c := new(CCache)

	require.NoError(t, c.Unmarshal(b))

	httppn := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}

	cred, ok := c.GetEntry(httppn)
	require.True(t, ok)
	assert.Equal(t, httppn, cred.Server.PrincipalName)
}

func TestCCache_GetEntries(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)

	c := new(CCache)

	require.NoError(t, c.Unmarshal(b))

	creds := c.GetEntries()
	assert.Equal(t, 2, len(creds), "Number of credentials entries not as expected")
}
