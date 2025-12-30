package client

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestClient_SuccessfulLogin_AD(t *testing.T) {
	test.AD(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_USER_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF_AD)
	cl := NewWithKeytab("testuser1", "USER.GOKRB5", kt, c, DisablePAFXFAST(true))

	require.NoError(t, cl.Login())
}

func TestClient_SuccessfulLogin_AD_Without_PreAuth(t *testing.T) {
	test.AD(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER3_USER_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF_AD)
	cl := NewWithKeytab("testuser3", "USER.GOKRB5", kt, c, DisablePAFXFAST(true))

	require.NoError(t, cl.Login())
}

func TestClient_GetServiceTicket_AD(t *testing.T) {
	test.AD(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_USER_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF_AD)
	cl := NewWithKeytab("testuser1", "USER.GOKRB5", kt, c)

	require.NoError(t, cl.Login())

	spn := "HTTP/user2.user.gokrb5"

	tkt, key, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	b, _ = hex.DecodeString(testdata.KEYTAB_TESTUSER2_USER_GOKRB5)
	skt := keytab.New()
	require.NoError(t, skt.Unmarshal(b))

	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser2"}}

	assert.NoError(t, tkt.DecryptEncPart(skt, &sname))

	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)

	isPAC, pac, err := tkt.GetPACType(skt, &sname, l)
	assert.NoError(t, err)

	assert.True(t, isPAC)
	assert.Equal(t, "USER", pac.KerbValidationInfo.LogonDomainName.String())
}

func TestClient_GetServiceTicket_AD_TRUST_USER_DOMAIN(t *testing.T) {
	test.AD(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_USER_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF_AD)
	c.LibDefaults.Canonicalize = true
	c.LibDefaults.DefaultTktEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	cl := NewWithKeytab("testuser1", "USER.GOKRB5", kt, c, DisablePAFXFAST(true))

	require.NoError(t, cl.Login())

	spn := "HTTP/host.res.gokrb5"

	tkt, key, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, etypeID.ETypesByName["rc4-hmac"], key.KeyType)

	b, _ = hex.DecodeString(testdata.KEYTAB_SYSHTTP_RES_GOKRB5)
	skt := keytab.New()
	require.NoError(t, skt.Unmarshal(b))

	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"sysHTTP"}}

	assert.NoError(t, tkt.DecryptEncPart(skt, &sname))

	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)

	isPAC, pac, err := tkt.GetPACType(skt, &sname, l)
	assert.NoError(t, err)

	assert.True(t, isPAC)
	assert.Equal(t, "testuser1", pac.KerbValidationInfo.EffectiveName.Value)
}

func TestClient_GetServiceTicket_AD_USER_DOMAIN(t *testing.T) {
	test.AD(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_USER_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF_AD)
	c.LibDefaults.Canonicalize = true
	c.LibDefaults.DefaultTktEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"rc4-hmac"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName["rc4-hmac"]}
	cl := NewWithKeytab("testuser1", "USER.GOKRB5", kt, c, DisablePAFXFAST(true))

	require.NoError(t, cl.Login())

	spn := "HTTP/user2.user.gokrb5"

	tkt, _, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, spn, tkt.SName.PrincipalNameString())

	b, err = hex.DecodeString(testdata.KEYTAB_TESTUSER2_USER_GOKRB5)
	require.NoError(t, err)

	skt := keytab.New()

	require.NoError(t, skt.Unmarshal(b))

	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser2"}}

	assert.NoError(t, tkt.DecryptEncPart(skt, &sname))

	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)

	isPAC, pac, err := tkt.GetPACType(skt, &sname, l)
	assert.NoError(t, err)

	assert.True(t, isPAC)
	assert.Equal(t, "testuser1", pac.KerbValidationInfo.EffectiveName.Value)
}
