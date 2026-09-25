package spnego

import (
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

// impersonation is what client.Client.Impersonate returns, minted here the way a KDC would issue it: a ticket to the
// service in the user's name, sealed with the service's key. The client asking holds no such key and never sees
// inside the ticket; it only has the session key and the name the reply gave.
func impersonation(t *testing.T) (client.Impersonation, *SPNEGO) {
	t.Helper()

	kt := testKeytab(t)
	// Named apart from getClient's testuser1: fixtureClient can hand out that very name, and a user who is the client
	// itself would make every assertion below vacuous.
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

// TestOnBehalfOfIsAcceptedAsTheUser is the point of the option: the service sees the user, not the client that
// obtained the ticket, and the context completes with the mutual reply the initiator can check.
func TestOnBehalfOfIsAcceptedAsTheUser(t *testing.T) {
	t.Parallel()

	imp, acceptor := impersonation(t)

	// The initiator's own identity is the front end, testuser1; it must not leak into the authenticator.
	init := SPNEGOClient(getClient(t), impersonationSPN, OnBehalfOf(imp))

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

// TestAnImpersonatedTicketWithTheClientsOwnAuthenticatorIsRefused shows why the option exists rather than passing the
// ticket to NewNegTokenInitKRB5 directly: an authenticator in the client's own name does not match the ticket, and
// RFC 4120 Section 3.2.3 has the service refuse it.
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

// TestOnBehalfOfRefusesDelegation: a forwarded TGT is the client's own, so delegating it under the user's name
// would hand the service the front end's identity while claiming the user's.
func TestOnBehalfOfRefusesDelegation(t *testing.T) {
	t.Parallel()

	imp, _ := impersonation(t)

	_, err := NewKRB5TokenAPREQ(getClient(t), imp.Ticket, imp.SessionKey, []int{gssapi.ContextFlagInteg}, []int{},
		OnBehalfOf(imp), Delegation())
	require.Error(t, err)
	assert.ErrorContains(t, err, "delegated credential")
}

// TestOnlyAnInitiatorWithoutOnBehalfOfAsksTheKDC: without the option the initiator obtains its own ticket to the
// service, and with it the ticket it was given is used as it is. A client that cannot reach any KDC shows the
// difference: the first fails asking, the second never asks.
func TestOnlyAnInitiatorWithoutOnBehalfOfAsksTheKDC(t *testing.T) {
	t.Parallel()

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	for i := range c.Realms {
		c.Realms[i].KDC = nil
	}

	cl := client.NewWithPassword("testuser1", impersonationRealm, "passwordvalue", c)

	_, err = SPNEGOClient(cl, impersonationSPN).InitSecContext()
	require.Error(t, err, "an initiator with no ticket of its own and no KDC produced a token")

	imp, acceptor := impersonation(t)

	st := initToken(t, SPNEGOClient(cl, impersonationSPN, OnBehalfOf(imp)))

	ok, _, status := acceptor.AcceptSecContext(st)
	assert.True(t, ok, "status was %d: %s", status.Code, status.Message)
}
