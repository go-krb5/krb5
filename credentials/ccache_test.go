package credentials

import (
	"encoding/hex"
	"runtime"
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

	assert.Equal(t, uint8(4), c.Version)
	assert.Equal(t, 1, len(c.Header.fields))
	assert.Equal(t, uint16(1), c.Header.fields[0].tag)
	assert.Equal(t, uint16(8), c.Header.fields[0].length)
	assert.Equal(t, "TEST.GOKRB5", c.DefaultPrincipal.Realm)
	assert.Equal(t, "testuser1", c.DefaultPrincipal.PrincipalName.PrincipalNameString())
	assert.Equal(t, 3, len(c.Credentials))

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
	assert.Equal(t, pn, c.GetClientPrincipalName())
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
	assert.Equal(t, "TEST.GOKRB5", cred.Domain())
	assert.Equal(t, pn, cred.CName())
	assert.Equal(t, "testuser1", cred.UserName())
}

func TestCCache_GetClientRealm(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)

	c := new(CCache)

	require.NoError(t, c.Unmarshal(b))

	assert.Equal(t, "TEST.GOKRB5", c.GetClientRealm())
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
	assert.Equal(t, 2, len(creds))
}

func TestCCacheUnmarshalRejectsMalformedData(t *testing.T) {
	t.Parallel()

	valid, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)

	testCases := []struct {
		name string
		b    []byte
	}{
		{"empty", []byte{}},
		{"first byte only", valid[:1]},
		{"version byte only", valid[:2]},
		{"truncated header length", valid[:3]},
		{"truncated header field", valid[:6]},
		{"truncated default principal", valid[:20]},
		{"truncated mid credential", valid[:len(valid)/2]},
		{"truncated one byte short", valid[:len(valid)-1]},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var c CCache

			require.NotPanics(t, func() {
				assert.Error(t, c.Unmarshal(tc.b))
			})
		})
	}
}

func TestCCacheUnmarshalRejectsNegativeLength(t *testing.T) {
	t.Parallel()

	b := []byte{
		0x05, 0x04, // version 4
		0x00, 0x00, // zero length header
		0x00, 0x00, 0x00, 0x01, // default principal: name type
		0x00, 0x00, 0x00, 0x01, // one component
		0xFF, 0xFF, 0xFF, 0xFF, // realm length of -1
		0x41,
	}

	var c CCache

	require.NotPanics(t, func() {
		assert.Error(t, c.Unmarshal(b))
	})
}

func TestCCacheUnmarshalRejectsImplausibleCounts(t *testing.T) {
	t.Parallel()

	principal := []byte{
		0x00, 0x00, 0x00, 0x01, // name type
		0x00, 0x00, 0x00, 0x00, // no components
		0x00, 0x00, 0x00, 0x00, // zero length realm
	}

	b := []byte{0x05, 0x04, 0x00, 0x00}
	b = append(b, principal...)           // default principal
	b = append(b, principal...)           // credential client
	b = append(b, principal...)           // credential server
	b = append(b, 0x00, 0x12)             // keyblock type
	b = append(b, 0x00, 0x00, 0x00, 0x00) // zero length key
	b = append(b, make([]byte, 16)...)    // four timestamps
	b = append(b, 0x00)                   // is skey
	b = append(b, 0x00, 0x00, 0x00, 0x00) // ticket flags
	b = append(b, 0x7F, 0xFF, 0xFF, 0xFF) // address count of 2147483647

	var c CCache

	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	require.NotPanics(t, func() {
		assert.Error(t, c.Unmarshal(b))
	})

	runtime.ReadMemStats(&after)

	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20),
		"the address count was allocated before it was validated")
}
