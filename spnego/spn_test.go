package spnego

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
)

// stubCNAME replaces the resolver for the duration of a test and reports which hosts it was asked about.
func stubCNAME(t *testing.T, canonical string) *[]string {
	t.Helper()

	var asked []string

	original := lookupCNAME
	lookupCNAME = func(host string) (string, error) {
		asked = append(asked, host)

		if canonical == "" {
			return "", &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}

		return canonical, nil
	}

	t.Cleanup(func() { lookupCNAME = original })

	return &asked
}

func TestSetRequestSPNDoesNotConsultDNSWhenCanonicalizationIsDisabled(t *testing.T) {
	// The SPN decides which service key the ticket is encrypted to, so canonicalizing through DNS trusts the
	// resolver to choose that principal. krb5.conf's dns_canonicalize_hostname exists to turn that off, and it
	// was parsed and then ignored.
	asked := stubCNAME(t, "elsewhere.attacker.example.")

	r, err := http.NewRequest(http.MethodGet, "http://host.test.gokrb5/path", nil)
	require.NoError(t, err)

	pn, err := setRequestSPN(r, false)
	require.NoError(t, err)

	assert.Empty(t, *asked, "the resolver must not be consulted when canonicalization is disabled")
	assert.Equal(t, "HTTP/host.test.gokrb5", pn.PrincipalNameString())
	assert.Equal(t, "host.test.gokrb5", r.Host)
}

func TestSetRequestSPNCanonicalizesWhenEnabled(t *testing.T) {
	asked := stubCNAME(t, "canonical.test.gokrb5.")

	r, err := http.NewRequest(http.MethodGet, "http://host.test.gokrb5/path", nil)
	require.NoError(t, err)

	pn, err := setRequestSPN(r, true)
	require.NoError(t, err)

	assert.Equal(t, []string{"host.test.gokrb5"}, *asked)
	assert.Equal(t, "HTTP/canonical.test.gokrb5", pn.PrincipalNameString())
	assert.Equal(t, "canonical.test.gokrb5", r.Host)
}

func TestSetRequestSPNWithAPortDoesNotConsultDNSWhenDisabled(t *testing.T) {
	asked := stubCNAME(t, "elsewhere.attacker.example.")

	r, err := http.NewRequest(http.MethodGet, "http://host.test.gokrb5:8080/path", nil)
	require.NoError(t, err)

	pn, err := setRequestSPN(r, false)
	require.NoError(t, err)

	assert.Empty(t, *asked, "the resolver must not be consulted when canonicalization is disabled")

	// The port is not part of the service principal name, but it is kept on the request Host.
	assert.Equal(t, "HTTP/host.test.gokrb5", pn.PrincipalNameString())
	assert.Equal(t, "host.test.gokrb5:8080", r.Host)
}

func TestSetRequestSPNKeepsTheHostWhenTheLookupFails(t *testing.T) {
	stubCNAME(t, "")

	r, err := http.NewRequest(http.MethodGet, "http://host.test.gokrb5/path", nil)
	require.NoError(t, err)

	pn, err := setRequestSPN(r, true)
	require.NoError(t, err)

	assert.Equal(t, "HTTP/host.test.gokrb5", pn.PrincipalNameString())
}

func TestCanonicalizeHostnameFollowsTheClientConfiguration(t *testing.T) {
	cfg := config.New()
	require.True(t, cfg.LibDefaults.DNSCanonicalizeHostname, "krb5.conf defaults the setting to true")

	cl := client.NewWithPassword("testuser", "TEST.GOKRB5", "password", cfg)
	assert.True(t, canonicalizeHostname(cl))

	cfg.LibDefaults.DNSCanonicalizeHostname = false
	assert.False(t, canonicalizeHostname(cl), "dns_canonicalize_hostname = false must be honoured")

	// A client carrying no configuration canonicalizes, as krb5.conf defaults to.
	assert.True(t, canonicalizeHostname(nil))
}

func TestSetSPNEGOHeaderDoesNotCanonicalizeWhenDisabled(t *testing.T) {
	asked := stubCNAME(t, "elsewhere.attacker.example.")

	cfg, err := config.NewFromString("[libdefaults]\n default_realm = TEST.GOKRB5\n dns_canonicalize_hostname = false\n")
	require.NoError(t, err)
	require.False(t, cfg.LibDefaults.DNSCanonicalizeHostname)

	cl := client.NewWithPassword("testuser", "TEST.GOKRB5", "password", cfg)

	r, err := http.NewRequest(http.MethodGet, "http://host.test.gokrb5/path", nil)
	require.NoError(t, err)

	// The exchange itself fails with no KDC to talk to; what matters is that the SPN was derived without DNS
	// before any of that happened.
	_ = SetSPNEGOHeader(cl, r, "")

	assert.Empty(t, *asked, "the resolver must not be consulted when the configuration disables it")
	assert.Equal(t, "host.test.gokrb5", r.Host)
}
