package spnego

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

const (
	impersonationSPN   = "HTTP/host.test.gokrb5"
	impersonationRealm = "TEST.GOKRB5"
)

func TestOnBehalfOfIsAcceptedAsTheUser(t *testing.T) {
	t.Parallel()

	imp, acceptor := impersonation(t)

	init := SPNEGOClient(getClient(t), impersonationSPN, OnBehalfOf(imp), MutualAuthentication())

	st := initToken(t, init)

	ok, ctx, status := acceptor.AcceptSecContext(st)
	require.True(t, ok, "status was %d: %s", status.Code, status.Message)

	creds, isCreds := ctx.Value(CTXKey).(*credentials.Credentials)
	require.True(t, isCreds, "the accepted context carries no credentials")
	assert.Equal(t, imp.CName.PrincipalNameString(), creds.UserName())
	assert.Equal(t, impersonationRealm, creds.Domain())

	reply, err := st.ResponseToken()
	require.NoError(t, err)
	assert.NoError(t, init.VerifyMutual(reply))
}

func TestAnImpersonatedTicketWithTheClientsOwnAuthenticatorIsRefused(t *testing.T) {
	t.Parallel()

	imp, acceptor := impersonation(t)

	n, err := NewNegTokenInitKRB5(getClient(t), imp.Ticket, imp.SessionKey)
	require.NoError(t, err)

	st := &SPNEGOToken{Init: true, NegTokenInit: n}

	b, err := st.Marshal()
	require.NoError(t, err)

	var back SPNEGOToken
	require.NoError(t, back.Unmarshal(b))

	ok, _, status := acceptor.AcceptSecContext(&back)
	assert.False(t, ok)
	assert.NotEqual(t, gssapi.StatusComplete, status.Code)
}

func TestOnBehalfOfRefusesATicketForAnotherService(t *testing.T) {
	t.Parallel()

	imp, _ := impersonation(t)

	_, err := SPNEGOClient(getClient(t), "HTTP/other.test.gokrb5", OnBehalfOf(imp)).InitSecContext()
	require.Error(t, err)
	assert.ErrorContains(t, err, "HTTP/other.test.gokrb5")
}

func TestOnBehalfOfRefusesDelegation(t *testing.T) {
	t.Parallel()

	imp, _ := impersonation(t)

	_, err := NewKRB5TokenAPREQ(getClient(t), imp.Ticket, imp.SessionKey, []int{gssapi.ContextFlagInteg}, []int{},
		OnBehalfOf(imp), Delegation())
	require.Error(t, err)
	assert.ErrorContains(t, err, "delegated credential")
}

func TestOnlyAnInitiatorWithoutOnBehalfOfAsksTheKDC(t *testing.T) {
	t.Parallel()

	cl := kdclessClient(t)

	_, err := SPNEGOClient(cl, impersonationSPN).InitSecContext()
	require.Error(t, err, "an initiator with no ticket of its own and no KDC produced a token")

	imp, acceptor := impersonation(t)

	st := initToken(t, SPNEGOClient(cl, impersonationSPN, OnBehalfOf(imp)))

	ok, _, status := acceptor.AcceptSecContext(st)
	assert.True(t, ok, "status was %d: %s", status.Code, status.Message)
}

func TestOnBehalfOfContinuesANegotiationAsTheUser(t *testing.T) {
	t.Parallel()

	imp, acceptor := impersonation(t)
	r := httptest.NewRequest(http.MethodGet, "http://host.test.gokrb5/", nil)

	require.NoError(t, setSPNEGOContinuationHeader(kdclessClient(t), r, impersonationSPN, OnBehalfOf(imp)))

	var st SPNEGOToken
	require.NoError(t, st.Unmarshal(negotiationHeader(t, r)))

	ok, ctx, status := acceptor.AcceptSecContext(&st)
	require.True(t, ok, "status was %d: %s", status.Code, status.Message)

	creds, isCreds := ctx.Value(CTXKey).(*credentials.Credentials)
	require.True(t, isCreds, "the accepted context carries no credentials")
	assert.Equal(t, imp.CName.PrincipalNameString(), creds.UserName())
}

func TestOnBehalfOfAnswersAMechListMICWithTheImpersonatedKey(t *testing.T) {
	t.Parallel()

	imp, _ := impersonation(t)

	payload, err := mechListMICPayload(nil, initiatorMechTypes())
	require.NoError(t, err)

	targetMIC, err := newMechListMIC(payload, imp.SessionKey, true)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "http://host.test.gokrb5/", nil)

	require.NoError(t, setSPNEGOMechListMICHeader(kdclessClient(t), r, impersonationSPN, targetMIC, OnBehalfOf(imp)))

	_, nt, err := UnmarshalNegToken(negotiationHeader(t, r))
	require.NoError(t, err)

	resp, isResp := nt.(NegTokenResp)
	require.True(t, isResp, "the leg sent a %T, not a NegTokenResp", nt)
	assert.NoError(t, verifyMechListMIC(resp.MechListMIC, payload, imp.SessionKey, false))
}

func impersonation(t *testing.T) (client.Impersonation, *SPNEGO) {
	t.Helper()

	kt := testKeytab(t)
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "impersonated-"+fixtureClient().NameString[0])
	now := time.Now().UTC()

	tkt, key, err := messages.NewTicket(user, impersonationRealm,
		types.NewPrincipalName(nametype.KRB_NT_SRV_INST, impersonationSPN), impersonationRealm,
		types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		now, now, now.Add(time.Hour), now.Add(2*time.Hour))
	require.NoError(t, err)

	return client.Impersonation{Ticket: tkt, SessionKey: key, CName: user, CRealm: impersonationRealm, EndTime: now.Add(time.Hour)},
		SPNEGOService(kt)
}

func kdclessClient(t *testing.T) *client.Client {
	t.Helper()

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	for i := range c.Realms {
		c.Realms[i].KDC = nil
	}

	return client.NewWithPassword("testuser1", impersonationRealm, "passwordvalue", c)
}

func negotiationHeader(t *testing.T, r *http.Request) []byte {
	t.Helper()

	v, ok := strings.CutPrefix(r.Header.Get(HTTPHeaderAuthRequest), HTTPHeaderAuthResponseValueKey+" ")
	require.True(t, ok, "the leg set no Negotiate header")

	b, err := base64.StdEncoding.DecodeString(v)
	require.NoError(t, err)

	return b
}

func initToken(t *testing.T, s *SPNEGO) *SPNEGOToken {
	t.Helper()

	ct, err := s.InitSecContext()
	require.NoError(t, err)

	b, err := ct.Marshal()
	require.NoError(t, err)

	var st SPNEGOToken
	require.NoError(t, st.Unmarshal(b))

	return &st
}
