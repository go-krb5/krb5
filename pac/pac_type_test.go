package pac

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestPACTypeVerify(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_AD_WIN2K_PAC)
	require.NoError(t, err)

	var pac PACType

	require.NoError(t, pac.Unmarshal(b))

	b, _ = hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	pn, _ := types.ParseSPNString("sysHTTP")

	key, _, err := kt.GetEncryptionKey(pn, "TEST.GOKRB5", 2, 18)
	require.NoError(t, err)

	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)

	require.NoError(t, pac.ProcessPACInfoBuffers(key, l))

	pacInvalidServerSig := pac
	pacInvalidServerSig.ServerChecksum.Signature[0] ^= 0xFF
	pacInvalidNilKerbValidationInfo := pac
	pacInvalidNilKerbValidationInfo.KerbValidationInfo = nil
	pacInvalidNilServerSig := pac
	pacInvalidNilServerSig.ServerChecksum = nil
	pacInvalidNilKdcSig := pac
	pacInvalidNilKdcSig.KDCChecksum = nil
	pacInvalidClientInfo := pac
	pacInvalidClientInfo.ClientInfo = nil

	var pacs = []struct {
		pac PACType
	}{
		{pacInvalidServerSig},
		{pacInvalidNilKerbValidationInfo},
		{pacInvalidNilServerSig},
		{pacInvalidNilKdcSig},
		{pacInvalidClientInfo},
	}

	for _, s := range pacs {
		v, err := s.pac.verify(key)
		assert.False(t, v)
		assert.Error(t, err)
	}
}
