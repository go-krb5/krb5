package config

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/test/testdata"
)

// TestConfig_GetKDCsUsesConfiguredKDC is meant to cover the fix for https://github.com/jcmturner/gokrb5/issues/332,
func TestConfig_GetKDCsUsesConfiguredKDC(t *testing.T) {
	t.Parallel()

	krb5ConfWithKDCAndDNSLookupKDC := `
[libdefaults]
 dns_lookup_kdc = true

[realms]
 TEST.GOKRB5 = {
  kdc = kdc2b.test.krb5:88
 }
`

	c, err := NewFromString(krb5ConfWithKDCAndDNSLookupKDC)
	require.NoError(t, err)

	count, kdcs, err := c.GetKDCs("TEST.GOKRB5", false)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, "kdc2b.test.krb5:88", kdcs[1])
}

func TestResolveKDC(t *testing.T) {
	test.Privileged(t)

	c, err := NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	// KDCs when they're not provided and we should be looking them up.
	c.LibDefaults.DNSLookupKDC = true
	c.Realms = make([]Realm, 0)

	count, res, err := c.GetKDCs(c.LibDefaults.DefaultRealm, true)
	assert.NoError(t, err)

	assert.Equal(t, 5, count, "Number of SRV records not as expected: %v", res)
	assert.Equal(t, count, len(res), "Map size does not match: %v", res)

	expected := []string{
		"kdc.test.krb5:88",
		"kdc1a.test.krb5:88",
		"kdc2a.test.krb5:88",
		"kdc1b.test.krb5:88",
		"kdc2b.test.krb5:88",
	}
	for _, s := range expected {
		var found bool

		for _, v := range res {
			if s == v {
				found = true
				break
			}
		}

		assert.True(t, found, "Record %s not found in results", s)
	}
}

func TestResolveKDCNoDNS(t *testing.T) {
	c, err := NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	c.LibDefaults.DNSLookupKDC = false

	_, res, err := c.GetKDCs(c.LibDefaults.DefaultRealm, true)
	assert.NoError(t, err)

	expected := []string{
		"127.0.0.1:88",
		"127.0.0.2:88",
	}

	for _, s := range expected {
		var found bool

		for _, v := range res {
			if s == v {
				found = true
				break
			}
		}

		assert.True(t, found, "Record %s not found in results", s)
	}
}

func TestConfig_GetKDCsShouldNotReorderTheConfiguredKDCs(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(multiKDCConf)
	require.NoError(t, err)

	before := append([]string(nil), c.Realms[0].KDC...)

	for range 5 {
		_, _, err = c.GetKDCs("TEST.GOKRB5", true)
		require.NoError(t, err)
	}

	assert.Equal(t, before, c.Realms[0].KDC, "the returned order is randomised per call, the configuration is not")
}

func TestConfig_GetKpasswdServersShouldNotReorderTheConfiguredServers(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(multiKDCConf)
	require.NoError(t, err)

	before := append([]string(nil), c.Realms[0].KPasswdServer...)

	for range 5 {
		_, _, err = c.GetKpasswdServers("TEST.GOKRB5", true)
		require.NoError(t, err)
	}

	assert.Equal(t, before, c.Realms[0].KPasswdServer)
}

func TestConfig_GetKDCsShouldBeSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(multiKDCConf)
	require.NoError(t, err)

	var wg sync.WaitGroup

	for range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for range 20 {
				if _, _, err := c.GetKDCs("TEST.GOKRB5", true); err != nil {
					panic(err)
				}
			}
		}()
	}

	wg.Wait()

	assert.Len(t, c.Realms[0].KDC, 4)
}

// multiKDCConf names four KDCs and four kpasswd servers so a shuffle has something to permute.
const multiKDCConf = `
[libdefaults]
 default_realm = TEST.GOKRB5

[realms]
 TEST.GOKRB5 = {
  kdc = kdc1.test.gokrb5:88
  kdc = kdc2.test.gokrb5:88
  kdc = kdc3.test.gokrb5:88
  kdc = kdc4.test.gokrb5:88
  kpasswd_server = kpasswd1.test.gokrb5:464
  kpasswd_server = kpasswd2.test.gokrb5:464
  kpasswd_server = kpasswd3.test.gokrb5:464
  kpasswd_server = kpasswd4.test.gokrb5:464
 }
`
