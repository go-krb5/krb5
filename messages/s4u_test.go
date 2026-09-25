package messages

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/types"
)

func TestNewS4U2SelfTGSReqAsksForAForwardableTicketToItselfInTheUsersName(t *testing.T) {
	t.Parallel()

	c, service, tgt, key := s4uFixture(t)
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")

	req, err := NewS4U2SelfTGSReq(service, s4uRealm, s4uRealm, c, tgt, key, user, s4uRealm)
	require.NoError(t, err)

	assert.True(t, req.ReqBody.SName.Equal(service), "a protocol transition request names the service itself")
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Forwardable))
	assert.False(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.CNameInAddlTkt))
	assert.Empty(t, req.ReqBody.AdditionalTickets)

	auth := tgsAuthenticator(t, req, key)
	assert.True(t, auth.CName.Equal(service), "the authenticator is the service's, the user is only named in PA-FOR-USER")

	require.Len(t, req.PAData, 3)
	require.Equal(t, patype.PA_FOR_USER, req.PAData[1].PADataType)
	require.Equal(t, patype.PA_FOR_X509_USER, req.PAData[2].PADataType)

	var pfu types.PAForUser
	require.NoError(t, pfu.Unmarshal(req.PAData[1].PADataValue))
	assert.True(t, pfu.UserName.Equal(user))
	assert.Equal(t, s4uRealm, pfu.UserRealm)
	assert.NoError(t, pfu.Verify(key), "PA-FOR-USER is signed with the TGT session key")

	b, err := req.Marshal()
	require.NoError(t, err)

	var back TGSReq
	require.NoError(t, back.Unmarshal(b))
	assert.True(t, back.PAData.Contains(patype.PA_FOR_USER))
}

func TestNewS4U2ProxyTGSReqCarriesTheEvidenceUnderTheChecksum(t *testing.T) {
	t.Parallel()

	c, service, tgt, key := s4uFixture(t)
	target := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/registry.example.com")

	evidence := Ticket{
		TktVNO:  iana.PVNO,
		Realm:   s4uRealm,
		SName:   service,
		EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 3, Cipher: []byte("the protocol transition ticket")},
	}

	req, err := NewS4U2ProxyTGSReq(service, s4uRealm, s4uRealm, c, tgt, key, target, evidence)
	require.NoError(t, err)

	assert.True(t, req.ReqBody.SName.Equal(target))
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.CNameInAddlTkt))
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Forwardable))
	require.Len(t, req.ReqBody.AdditionalTickets, 1)
	assert.Equal(t, evidence.EncPart.Cipher, req.ReqBody.AdditionalTickets[0].EncPart.Cipher)
	assert.False(t, req.PAData.Contains(patype.PA_FOR_USER))

	tgsAuthenticator(t, req, key)

	assert.Equal(t, byte(0x02), req.ReqBody.KDCOptions.Bytes[1]&0x02)
}

func TestTGSRepVerifyOnBehalfOfAcceptsOnlyTheUsersName(t *testing.T) {
	t.Parallel()

	c, service, tgt, key := s4uFixture(t)
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")

	req, err := NewS4U2SelfTGSReq(service, s4uRealm, s4uRealm, c, tgt, key, user, s4uRealm)
	require.NoError(t, err)

	now := time.Now().UTC()
	rep := TGSRep{KDCRepFields{
		CRealm: s4uRealm,
		CName:  user,
		Ticket: Ticket{Realm: s4uRealm, SName: service},
		DecryptedEncPart: EncKDCRepPart{
			Nonce:     req.ReqBody.Nonce,
			AuthTime:  now,
			StartTime: now,
			EndTime:   now.Add(time.Hour),
			SRealm:    s4uRealm,
			SName:     service,
		},
	}}

	ok, err := rep.VerifyOnBehalfOf(c, req, user, s4uRealm)
	assert.True(t, ok, "%v", err)

	ok, _ = rep.Verify(c, req)
	assert.False(t, ok)

	asService := rep
	asService.CName = service
	ok, _ = asService.VerifyOnBehalfOf(c, req, user, s4uRealm)
	assert.False(t, ok)

	otherRealm := rep
	otherRealm.CRealm = "OTHER.COM"
	ok, _ = otherRealm.VerifyOnBehalfOf(c, req, user, s4uRealm)
	assert.False(t, ok)

	replayed := rep
	replayed.DecryptedEncPart.Nonce++
	ok, _ = replayed.VerifyOnBehalfOf(c, req, user, s4uRealm)
	assert.False(t, ok, "every check Verify makes still applies")
}

func TestTGSRepVerifyOnBehalfOfRefusesAReferral(t *testing.T) {
	t.Parallel()

	c, service, tgt, key := s4uFixture(t)
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")

	req, err := NewS4U2SelfTGSReq(service, s4uRealm, s4uRealm, c, tgt, key, user, s4uRealm)
	require.NoError(t, err)

	crossRealm := types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", "OTHER.EXAMPLE"}}
	now := time.Now().UTC()
	rep := TGSRep{KDCRepFields{
		CRealm: s4uRealm,
		CName:  user,
		Ticket: Ticket{Realm: s4uRealm, SName: crossRealm},
		DecryptedEncPart: EncKDCRepPart{
			Nonce:     req.ReqBody.Nonce,
			AuthTime:  now,
			StartTime: now,
			EndTime:   now.Add(time.Hour),
			SRealm:    s4uRealm,
			SName:     crossRealm,
		},
	}}

	ok, err := rep.VerifyOnBehalfOf(c, req, user, s4uRealm)
	assert.False(t, ok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "referral to krbtgt/OTHER.EXAMPLE")
}

func TestAnS4URequestIsNotBuiltWithAKeyThatCannotSignIt(t *testing.T) {
	t.Parallel()

	c, service, tgt, key := s4uFixture(t)
	unknown := types.EncryptionKey{KeyType: 0, KeyValue: []byte("no such encryption type")}
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")

	_, err := NewS4U2SelfTGSReq(service, s4uRealm, s4uRealm, c, tgt, unknown, user, s4uRealm)
	assert.Error(t, err)

	unnamable := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "\xffalice")
	_, err = NewS4U2SelfTGSReq(service, s4uRealm, s4uRealm, c, tgt, key, unnamable, s4uRealm)
	assert.ErrorContains(t, err, "PA-FOR-USER")

	_, err = NewS4U2ProxyTGSReq(service, s4uRealm, s4uRealm, c, tgt, unknown, types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/registry.example.com"), Ticket{})
	assert.Error(t, err)
}

const s4uRealm = "EXAMPLE.COM"

func s4uFixture(t *testing.T) (*config.Config, types.PrincipalName, Ticket, types.EncryptionKey) {
	t.Helper()

	c := config.New()
	c.LibDefaults.NoAddresses = true

	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	for i := range key.KeyValue {
		key.KeyValue[i] = byte(i)
	}

	tgt := Ticket{
		TktVNO:  iana.PVNO,
		Realm:   s4uRealm,
		SName:   types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{testKrbtgt, s4uRealm}},
		EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 1, Cipher: []byte("opaque to the client")},
	}

	return c, types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/app.example.com"), tgt, key
}

func tgsAuthenticator(t *testing.T, req TGSReq, key types.EncryptionKey) types.Authenticator {
	t.Helper()

	require.NotEmpty(t, req.PAData)
	require.Equal(t, patype.PA_TGS_REQ, req.PAData[0].PADataType)

	var ap APReq
	require.NoError(t, ap.Unmarshal(req.PAData[0].PADataValue))

	plain, err := crypto.DecryptEncPart(ap.EncryptedAuthenticator, key, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR)
	require.NoError(t, err)

	var auth types.Authenticator
	require.NoError(t, auth.Unmarshal(plain))

	body, err := req.ReqBody.Marshal()
	require.NoError(t, err)

	et, err := crypto.GetEType(key.KeyType)
	require.NoError(t, err)

	assert.True(t, et.VerifyChecksum(key.KeyValue, body, auth.Cksum.Checksum, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM),
		"the authenticator checksum does not cover the request body")

	return auth
}
