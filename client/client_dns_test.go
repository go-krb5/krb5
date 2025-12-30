package client

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestClient_Login_DNSKDCs(t *testing.T) {
	test.Privileged(t)

	c, _ := config.NewFromString(testdata.KRB5_CONF)
	c.LibDefaults.DNSLookupKDC = true
	c.Realms = []config.Realm{}

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()

	require.NoError(t, kt.Unmarshal(b))

	cl := NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())
}
