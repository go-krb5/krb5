package client_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestClient_SuccessfulLogin_Keytab(t *testing.T) {
	test.Integration(t)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	var tests = []string{
		testdata.KDC_PORT_TEST_GOKRB5,
		testdata.KDC_PORT_TEST_GOKRB5_OLD,
		testdata.KDC_PORT_TEST_GOKRB5_LASTEST,
	}
	for _, tst := range tests {
		c.Realms[0].KDC = []string{addr + ":" + tst}
		cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

		assert.NoError(t, cl.Login())
	}
}

func TestClient_SuccessfulLogin_Password(t *testing.T) {
	test.Integration(t)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	var tests = []string{
		testdata.KDC_PORT_TEST_GOKRB5,
		testdata.KDC_PORT_TEST_GOKRB5_OLD,
		testdata.KDC_PORT_TEST_GOKRB5_LASTEST,
	}
	for _, tst := range tests {
		c.Realms[0].KDC = []string{addr + ":" + tst}
		cl := client.NewWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue", c)

		assert.NoError(t, cl.Login())
	}
}

func TestClient_SuccessfulLogin_TCPOnly(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	c.LibDefaults.UDPPreferenceLimit = 1
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())
}

func TestClient_ASExchange_TGSExchange_EncTypes_Keytab(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_LASTEST}

	var tests = []string{
		"des3-cbc-sha1-kd",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha256-128",
		"aes256-cts-hmac-sha384-192",
		"rc4-hmac",
	}
	for _, tst := range tests {
		c.LibDefaults.DefaultTktEnctypes = []string{tst}
		c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		c.LibDefaults.DefaultTGSEnctypes = []string{tst}
		c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

		assert.NoError(t, cl.Login())

		tkt, key, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
		assert.NoError(t, err)

		assert.Equal(t, "TEST.GOKRB5", tkt.Realm, "Realm in ticket not as expected for %s test", tst)
		assert.Equal(t, etypeID.ETypesByName[tst], key.KeyType, "Key is not for enctype %s", tst)
	}
}

func TestClient_ASExchange_TGSExchange_EncTypes_Password(t *testing.T) {
	test.Integration(t)

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_LASTEST}

	var tests = []string{
		"des3-cbc-sha1-kd",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha256-128",
		"aes256-cts-hmac-sha384-192",
		"rc4-hmac",
	}
	for _, tst := range tests {
		c.LibDefaults.DefaultTktEnctypes = []string{tst}
		c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		c.LibDefaults.DefaultTGSEnctypes = []string{tst}
		c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		cl := client.NewWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue", c)

		assert.NoError(t, cl.Login())

		tkt, key, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
		assert.NoError(t, err)

		assert.Equal(t, "TEST.GOKRB5", tkt.Realm, "Realm in ticket not as expected for %s test", tst)
		assert.Equal(t, etypeID.ETypesByName[tst], key.KeyType, "Key is not for enctype %s", tst)
	}
}

func TestClient_FailedLogin(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5_WRONGPASSWD)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER2_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser2", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth_TCPOnly(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER2_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	c.LibDefaults.UDPPreferenceLimit = 1
	cl := client.NewWithKeytab("testuser2", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())
}

func TestClient_NetworkTimeout(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)
	c.Realms[0].KDC = []string{testdata.KDC_IP_TEST_GOKRB5_BADADDR + ":88"}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())
}

func TestClient_NetworkTryNextKDC(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{testdata.KDC_IP_TEST_GOKRB5_BADADDR + ":88",
		testdata.KDC_IP_TEST_GOKRB5_BADADDR + ":88",
		addr + ":" + testdata.KDC_PORT_TEST_GOKRB5,
	}

	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())

	require.NoError(t, cl.Login())
}

func TestClient_GetServiceTicket(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())

	tkt, key, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	tkt2, key2, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)
}

func TestClient_GetServiceTicket_CanonicalizeTrue(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)
	c.LibDefaults.Canonicalize = true

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())

	tkt, key, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	tkt2, key2, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)
}

func TestClient_GetServiceTicket_InvalidSPN(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())

	spn := "host.test.gokrb5"
	_, _, err := cl.GetServiceTicket(spn)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "KDC_ERR_S_PRINCIPAL_UNKNOWN"))
}

func TestClient_GetServiceTicket_OlderKDC(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_OLD}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())

	tkt, key, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)
}

func TestMultiThreadedClientUse(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	var wg sync.WaitGroup
	wg.Add(5)

	for i := 0; i < 5; i++ {
		go func() {
			defer wg.Done()

			err := cl.Login()
			if err != nil {
				panic(err)
			}
		}()
	}

	wg.Wait()

	var wg2 sync.WaitGroup
	wg2.Add(5)

	for i := 0; i < 5; i++ {
		go func() {
			defer wg2.Done()

			err := spnegoGet(cl)
			if err != nil {
				panic(err)
			}
		}()
	}

	wg2.Wait()
}

func spnegoGet(cl *client.Client) error {
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}

	r, _ := http.NewRequest(http.MethodGet, url+"/modgssapi/index.html", nil)

	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		return fmt.Errorf("request error: %v\n", err)
	}

	if httpResp.StatusCode != http.StatusUnauthorized {
		return errors.New("did not get unauthorized code when no SPNEGO header set")
	}

	err = spnego.SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5")
	if err != nil {
		return fmt.Errorf("error setting client SPNEGO header: %v", err)
	}

	httpResp, err = http.DefaultClient.Do(r)
	if err != nil {
		return fmt.Errorf("request error: %v\n", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return errors.New("did not get OK code when SPNEGO header set")
	}

	return nil
}

func TestNewFromCCache(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)

	cc := new(credentials.CCache)

	require.NoError(t, cc.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}

	cl, err := client.NewFromCCache(cc, c)
	require.NoError(t, err)
	require.NotNil(t, cl)

	ok, err := cl.IsConfigured()
	assert.True(t, ok)
	assert.NoError(t, err)
}

// Login to the TEST.GOKRB5 domain and request service ticket for resource in the RESDOM.GOKRB5 domain.
// There is a trust between the two domains.
func TestClient_GetServiceTicket_Trusted_Resource_Domain(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	for i, r := range c.Realms {
		if r.Realm == "TEST.GOKRB5" {
			c.Realms[i].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
		}

		if r.Realm == "RESDOM.GOKRB5" {
			c.Realms[i].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_RESDOM}
		}
	}

	c.LibDefaults.DefaultRealm = "TEST.GOKRB5"
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	c.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}

	require.NoError(t, cl.Login())

	spn := "HTTP/host.resdom.gokrb5"

	tkt, key, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], key.KeyType)

	b, _ = hex.DecodeString(testdata.KEYTAB_SYSHTTP_RESDOM_GOKRB5)
	skt := keytab.New()
	require.NoError(t, skt.Unmarshal(b))

	assert.NoError(t, tkt.DecryptEncPart(skt, nil))
}

// Login to the SUB.TEST.GOKRB5 domain and request service ticket for resource in the RESDOM.GOKRB5 domain.
// There is only trust between parent domain (TEST.GOKRB5) and the service domain (RESDOM.GOKRB5).
func TestClient_GetServiceTicket_Trusted_Resource_SubDomain(t *testing.T) {
	test.Integration(t)

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	for i, r := range c.Realms {
		switch r.Realm {
		case "TEST.GOKRB5":
			c.Realms[i].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
		case "SUB.TEST.GOKRB5":
			c.Realms[i].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_SUB}
		case "RESDOM.GOKRB5":
			c.Realms[i].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_RESDOM}
		}
	}

	c.LibDefaults.DefaultRealm = "SUB.TEST.GOKRB5"
	c.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}

	cl := client.NewWithPassword("testuser1", "SUB.TEST.GOKRB5", "passwordvalue", c)

	require.NoError(t, cl.Login())

	spn := "HTTP/host.resdom.gokrb5"

	tkt, key, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], key.KeyType)
}

const (
	kinitCmd = "kinit"
	kvnoCmd  = "kvno"
	spn      = "HTTP/host.test.gokrb5"
)

func login() error {
	file, err := os.Create("/etc/krb5.conf")
	if err != nil {
		return fmt.Errorf("cannot open krb5.conf: %v", err)
	}
	defer file.Close()

	fmt.Fprintf(file, testdata.KRB5_CONF)

	cmd := exec.Command(kinitCmd, "testuser1@TEST.GOKRB5")

	stdinR, stdinW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	cmd.Stdin = stdinR
	cmd.Stderr = stderrW

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("could not start %s command: %v", kinitCmd, err)
	}

	go func() {
		_, _ = io.WriteString(stdinW, "passwordvalue")
		_ = stdinW.Close()
	}()

	errBuf := new(bytes.Buffer)

	go func() {
		_, _ = io.Copy(errBuf, stderrR)
		_ = stderrR.Close()
	}()

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("%s did not run successfully: %v stderr: %s", kinitCmd, err, errBuf.String())
	}

	return nil
}

func getServiceTkt() error {
	cmd := exec.Command(kvnoCmd, spn)

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("could not start %s command: %v", kvnoCmd, err)
	}

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("%s did not run successfully: %v", kvnoCmd, err)
	}

	return nil
}

func loadCCache() (*credentials.CCache, error) {
	usr, _ := user.Current()
	cpath := "/tmp/krb5cc_" + usr.Uid

	return credentials.LoadCCache(cpath)
}

func TestGetServiceTicketFromCCacheTGT(t *testing.T) {
	test.Privileged(t)

	require.NoError(t, login())

	c, err := loadCCache()
	require.NoError(t, err)

	cfg, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	cfg.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}

	cl, err := client.NewFromCCache(c, cfg)
	require.NoError(t, err)

	tkt, key, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	tkt2, key2, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)

	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}

	r, err := http.NewRequest(http.MethodGet, url+"/modgssapi/index.html", nil)
	require.NoError(t, err)

	require.NoError(t, spnego.SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5"))

	httpResp, err := http.DefaultClient.Do(r)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, httpResp.StatusCode)
}

func TestGetServiceTicketFromCCacheWithoutKDC(t *testing.T) {
	test.Privileged(t)

	require.NoError(t, login())

	require.NoError(t, getServiceTkt())

	c, err := loadCCache()
	require.NoError(t, err)

	cfg, _ := config.NewFromString("...")

	cl, err := client.NewFromCCache(c, cfg)
	require.NoError(t, err)

	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}

	r, _ := http.NewRequest(http.MethodGet, url+"/modgssapi/index.html", nil)

	require.NoError(t, spnego.SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5"))

	httpResp, err := http.DefaultClient.Do(r)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, httpResp.StatusCode)
}

func TestClient_ChangePasswd(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()

	require.NoError(t, kt.Unmarshal(b))

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	c.Realms[0].KPasswdServer = []string{addr + ":464"}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	ok, err := cl.ChangePasswd("newpassword")
	require.NoError(t, err)

	assert.True(t, ok)

	cl = client.NewWithPassword("testuser1", "TEST.GOKRB5", "newpassword", c)

	ok, err = cl.ChangePasswd(testdata.TESTUSER_PASSWORD)
	require.NoError(t, err)

	assert.True(t, ok)

	cl = client.NewWithPassword("testuser1", "TEST.GOKRB5", testdata.TESTUSER_PASSWORD, c)

	require.NoError(t, cl.Login())
}

func TestClient_Destroy(t *testing.T) {
	test.Integration(t)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_SHORTTICKETS}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	require.NoError(t, cl.Login())

	_, _, err := cl.GetServiceTicket(spn)
	require.NoError(t, err)

	n := runtime.NumGoroutine()

	time.Sleep(time.Second * 60)
	cl.Destroy()
	time.Sleep(time.Second * 5)
	assert.True(t, runtime.NumGoroutine() < n)

	is, _ := cl.IsConfigured()
	assert.False(t, is)
}
