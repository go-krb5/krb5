package spnego

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/messages"
)

func TestRequestSPNFallbackKeepsTheNameTheKDCKnows(t *testing.T) {
	asked := stubCNAME(t, "canonical.test.gokrb5.")
	probed := stubProbe(t, nil)

	spn, r := fallbackRequestSPN(t)

	assert.Equal(t, fallbackAliasSPN, spn)
	assert.Equal(t, "alias.test.gokrb5", r.Host)
	assert.Equal(t, []string{fallbackAliasSPN}, *probed)
	assert.Empty(t, *asked)
}

func TestRequestSPNFallbackCanonicalizesAnUnknownPrincipal(t *testing.T) {
	asked := stubCNAME(t, "canonical.test.gokrb5.")
	probed := stubProbe(t, krberror.Errorf(messages.KRBError{ErrorCode: errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN}, krberror.KDCError, "TGS Exchange Error"))

	spn, r := fallbackRequestSPN(t)

	assert.Equal(t, "HTTP/canonical.test.gokrb5", spn)
	assert.Equal(t, "canonical.test.gokrb5", r.Host)
	assert.Equal(t, []string{fallbackAliasSPN}, *probed)
	assert.Equal(t, []string{"alias.test.gokrb5"}, *asked)
}

func TestRequestSPNFallbackDoesNotCanonicalizeForAnotherFailure(t *testing.T) {
	asked := stubCNAME(t, "canonical.test.gokrb5.")
	stubProbe(t, krberror.Errorf(messages.KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_FAILED}, krberror.KDCError, "TGS Exchange Error"))

	spn, _ := fallbackRequestSPN(t)

	assert.Equal(t, fallbackAliasSPN, spn)
	assert.Empty(t, *asked)

	stubProbe(t, errors.New("network unreachable"))

	spn, _ = fallbackRequestSPN(t)

	assert.Equal(t, fallbackAliasSPN, spn)
	assert.Empty(t, *asked)
}

func TestRequestSPNFallbackDoesNotAskTheKDCOnBehalfOfAnotherUser(t *testing.T) {
	stubCNAME(t, "canonical.test.gokrb5.")
	probed := stubProbe(t, nil)

	cl := client.NewWithPassword("testuser", "TEST.GOKRB5", "password", fallbackConfig(t))

	r, err := http.NewRequest(http.MethodGet, "http://alias.test.gokrb5/", nil)
	require.NoError(t, err)

	imp, _ := impersonation(t)

	spn, err := requestSPN(cl, r, "", OnBehalfOf(imp))
	require.NoError(t, err)

	assert.Equal(t, fallbackAliasSPN, spn)
	assert.Empty(t, *probed)
}

func fallbackConfig(t *testing.T) *config.Config {
	t.Helper()

	cfg, err := config.NewFromString("[libdefaults]\n default_realm = TEST.GOKRB5\n dns_canonicalize_hostname = fallback\n")
	require.NoError(t, err)

	return cfg
}

func fallbackRequestSPN(t *testing.T) (string, *http.Request) {
	t.Helper()

	cl := client.NewWithPassword("testuser", "TEST.GOKRB5", "password", fallbackConfig(t))

	r, err := http.NewRequest(http.MethodGet, "http://alias.test.gokrb5/", nil)
	require.NoError(t, err)

	spn, err := requestSPN(cl, r, "")
	require.NoError(t, err)

	return spn, r
}

func stubProbe(t *testing.T, result error) *[]string {
	t.Helper()

	var probed []string

	original := probeServiceTicket
	probeServiceTicket = func(_ *client.Client, spn string) error {
		probed = append(probed, spn)

		return result
	}

	t.Cleanup(func() { probeServiceTicket = original })

	return &probed
}

const fallbackAliasSPN = "HTTP/alias.test.gokrb5"
