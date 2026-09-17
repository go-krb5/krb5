package service

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"
	"github.com/go-krb5/x/rpc/mstypes"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/crypto/etype"
	"github.com/go-krb5/krb5/iana/asn1apptag"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/pac"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

// TestADCredentialsNameTheServiceADelegatedTicketCameThrough: a ticket issued by S4U2Proxy carries the
// services it was obtained through, and the acceptor has to say so; a ticket of the principal's own
// carries none and says nothing.
func TestADCredentialsNameTheServiceADelegatedTicketCameThrough(t *testing.T) {
	t.Parallel()

	const (
		user     = "alice"
		frontEnd = "HTTP/app.example.com@EXAMPLE.COM"
	)

	var own pac.PACType

	own.KerbValidationInfo = &pac.KerbValidationInfo{EffectiveName: mstypes.RPCUnicodeString{Value: user}}

	ad := adCredentials(own)
	assert.Equal(t, user, ad.EffectiveName)
	assert.Empty(t, ad.DelegatedThrough)

	delegated := own
	delegated.S4UDelegationInfo = &pac.S4UDelegationInfo{
		S4U2proxyTarget:   mstypes.RPCUnicodeString{Value: "HTTP/registry.example.com@EXAMPLE.COM"},
		TransitedListSize: 1,
		S4UTransitedServices: []mstypes.RPCUnicodeString{
			{Value: frontEnd},
		},
	}

	ad = adCredentials(delegated)
	assert.Equal(t, user, ad.EffectiveName, "the principal is still the one authorized")
	assert.Equal(t, []string{frontEnd}, ad.DelegatedThrough)
}

// TestVerifyAPREQCarriesThePACIntoTheCredentials runs a ticket holding a real PAC through the acceptor: the PAC is
// verified with the service key and what it says reaches the credentials. The PAC is the captured test vector, which
// is signed for sysHTTP, and nobody delegated this ticket, so it names no service it came through.
func TestVerifyAPREQCarriesThePACIntoTheCredentials(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"sysHTTP"}}
	key, kvno, err := kt.GetEncryptionKey(sname, testSRealm, 0, 18)
	require.NoError(t, err)

	b, err = hex.DecodeString(testdata.MarshaledPAC_AuthorizationData_GOKRB5)
	require.NoError(t, err)

	var ad types.AuthorizationData
	require.NoError(t, ad.Unmarshal(b))

	cl := getClient(t)
	sessionKey, err := types.GenerateEncryptionKey(mustEType(t, 18))
	require.NoError(t, err)

	now := time.Now().UTC()
	part, err := asn1.Marshal(messages.EncTicketPart{
		Flags:             types.NewKrbFlags(),
		Key:               sessionKey,
		CRealm:            cl.Credentials.Domain(),
		CName:             cl.Credentials.CName(),
		Transited:         messages.TransitedEncoding{},
		AuthTime:          now,
		StartTime:         now,
		EndTime:           now.Add(time.Hour),
		RenewTill:         now.Add(time.Hour),
		AuthorizationData: ad,
	}, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	encPart, err := crypto.GetEncryptedData(asn1tools.AddASNAppTag(part, asn1apptag.EncTicketPart), key, keyusage.KDC_REP_TICKET, kvno)
	require.NoError(t, err)

	tkt := messages.Ticket{TktVNO: 5, Realm: testSRealm, SName: sname, EncPart: encPart}

	apReq, err := messages.NewAPReq(tkt, sessionKey, newTestAuthenticator(t, *cl.Credentials))
	require.NoError(t, err)

	h, _ := types.GetHostAddress("127.0.0.1:1234")

	ok, creds, err := VerifyAPREQ(&apReq, NewSettings(kt, ClientAddress(h)))
	require.NoError(t, err)
	require.True(t, ok)

	got := creds.GetADCredentials()
	assert.NotEmpty(t, got.EffectiveName, "the PAC's account name did not reach the credentials")
	assert.NotEmpty(t, got.GroupMembershipSIDs)
	assert.Empty(t, got.DelegatedThrough)
}

func mustEType(t *testing.T, id int32) etype.EType {
	t.Helper()

	et, err := crypto.GetEType(id)
	require.NoError(t, err)

	return et
}
