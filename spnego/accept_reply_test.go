package spnego

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestAPRepTokenAnswersAVerifiedAPREQ(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x11)
	mt, auth := verifiedAPREQ(t, key)

	b, err := mt.APRepToken()
	require.NoError(t, err)
	require.NotEmpty(t, b)

	var rep KRB5Token

	require.NoError(t, rep.Unmarshal(b))
	assert.Equal(t, []byte{2, 0}, rep.tokID)
	assert.Equal(t, msgtype.KRB_AP_REP, rep.APRep.MsgType)
	assert.Equal(t, iana.PVNO, rep.APRep.PVNO)
	assert.Equal(t, key.KeyType, rep.APRep.EncPart.EType)

	plain, err := crypto.DecryptEncPart(rep.APRep.EncPart, key, keyusage.AP_REP_ENCPART)
	require.NoError(t, err)

	var enc messages.EncAPRepPart

	require.NoError(t, enc.Unmarshal(plain))
	assert.Equal(t, auth.CTime.Unix(), enc.CTime.Unix())
	assert.Equal(t, auth.Cusec, enc.Cusec)
}

func TestAPRepTokenIsUnreadableWithoutTheSessionKey(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x22)
	mt, _ := verifiedAPREQ(t, key)

	b, err := mt.APRepToken()
	require.NoError(t, err)

	var rep KRB5Token

	require.NoError(t, rep.Unmarshal(b))

	_, err = crypto.DecryptEncPart(rep.APRep.EncPart, mutualSessionKey(0x33), keyusage.AP_REP_ENCPART)
	assert.Error(t, err, "the AP-REP decrypted under a key that never saw this ticket")
}

func TestAPRepTokenRefusesAnUndecryptedTicket(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x44)
	mt, _ := verifiedAPREQ(t, key)
	mt.APReq.Ticket.DecryptedEncPart.Key = types.EncryptionKey{}

	_, err := mt.APRepToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session key")
}

func TestAPRepTokenRefusesATokenThatIsNotAnAPREQ(t *testing.T) {
	t.Parallel()

	mt, _ := verifiedAPREQ(t, mutualSessionKey(0x55))
	mt.tokID, _ = hex.DecodeString(TOK_ID_KRB_AP_REP)

	_, err := mt.APRepToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AP-REQ")
}

func TestKRB5TokenMarshalsAnAPRep(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x66)
	ed, err := crypto.GetEncryptedData([]byte("payload"), key, keyusage.AP_REP_ENCPART, 0)
	require.NoError(t, err)

	rep := KRB5Token{
		OID:   gssapi.OIDKRB5.OID(),
		APRep: messages.APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: ed},
	}
	rep.tokID, _ = hex.DecodeString(TOK_ID_KRB_AP_REP)

	b, err := rep.Marshal()
	require.NoError(t, err)

	var back KRB5Token

	require.NoError(t, back.Unmarshal(b))
	assert.Equal(t, msgtype.KRB_AP_REP, back.APRep.MsgType)
}

func TestResponseTokenCarriesTheAPRep(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x77)
	mt, _ := verifiedAPREQ(t, key)

	st := &SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{mechToken: mt}}

	b, err := st.ResponseToken()
	require.NoError(t, err)

	var resp NegTokenResp

	require.NoError(t, resp.Unmarshal(b))
	assert.Equal(t, asn1.Enumerated(NegStateAcceptCompleted), resp.NegState)
	assert.True(t, resp.SupportedMech.Equal(gssapi.OIDKRB5.OID()))
	assert.NotEmpty(t, resp.ResponseToken, "the negotiation completed with no proof of who the acceptor is")
}

func TestResponseTokenRefusesWhatIsNotAnInitiatorsToken(t *testing.T) {
	t.Parallel()

	_, err := (&SPNEGOToken{Resp: true}).ResponseToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "initiator")

	_, err = (&SPNEGOToken{Init: true}).ResponseToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mech token")
}

func TestMutualRoundTrip(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x88)
	mt, auth := verifiedAPREQ(t, key)

	reply, err := (&SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{mechToken: mt}}).ResponseToken()
	require.NoError(t, err)

	init := initiator(key, mt)
	assert.Equal(t, key, init.sessionKey)
	assert.Equal(t, auth.CTime, init.sentCTime, "the initiator did not remember the ctime it sent")
	assert.Equal(t, auth.Cusec, init.sentCusec)

	assert.NoError(t, init.VerifyMutual(reply))
}

func TestVerifyMutualRefusesAReplyToAnotherExchange(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x99)
	mt, auth := verifiedAPREQ(t, key)

	reply, err := (&SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{mechToken: mt}}).ResponseToken()
	require.NoError(t, err)

	other := auth
	other.CTime = auth.CTime.Add(-time.Minute)

	err = initiatorOf(key, other).VerifyMutual(reply)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "another one")

	other = auth
	other.Cusec = auth.Cusec + 1

	require.Error(t, initiatorOf(key, other).VerifyMutual(reply))
}

func TestVerifyMutualRefusesAReplyFromAnImpostor(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0xaa)
	mt, _ := verifiedAPREQ(t, key)

	reply, err := (&SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{mechToken: mt}}).ResponseToken()
	require.NoError(t, err)

	err = initiator(mutualSessionKey(0xbb), mt).VerifyMutual(reply)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session key")
}

func TestVerifyMutualRefusesAnEmptyOrRejectedReply(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0xcc)
	_, auth := verifiedAPREQ(t, key)

	bare := NegTokenResp{NegState: asn1.Enumerated(NegStateAcceptCompleted), SupportedMech: gssapi.OIDKRB5.OID()}

	b, err := bare.Marshal()
	require.NoError(t, err)

	err = initiatorOf(key, auth).VerifyMutual(b)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no AP-REP")

	rejected := NegTokenResp{NegState: asn1.Enumerated(NegStateReject)}

	b, err = rejected.Marshal()
	require.NoError(t, err)

	err = initiatorOf(key, auth).VerifyMutual(b)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rejected")
}

func TestVerifyMutualRefusesWithoutAnInitiatedContext(t *testing.T) {
	t.Parallel()

	err := SPNEGOClient(&client.Client{}, "HTTP/host.test.gokrb5").VerifyMutual([]byte{0})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "never initiated")
}

func TestMutualRequestedReadsTheAPREQ(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		option   bool
		flagged  bool
		expected bool
	}{
		{"TheAPOptionAlone", true, false, true},
		{"TheChecksumFlagAlone", false, true, true},
		{"BothAsAnInitiatorSendsThem", true, true, true},
		{"NeitherIsNotARequest", false, false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, mutualRequested(mutualAPREQ(t, tc.option, tc.flagged)))
		})
	}
}

func TestMutualRequestedIgnoresReqFlags(t *testing.T) {
	t.Parallel()

	clear := asn1.BitString{Bytes: []byte{0x80}, BitLength: 8}
	set := asn1.BitString{Bytes: []byte{0x40}, BitLength: 8}

	asking := &SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{ReqFlags: clear, mechToken: mutualAPREQ(t, true, true)}}

	b, err := asking.ResponseToken()
	require.NoError(t, err)

	var resp NegTokenResp

	require.NoError(t, resp.Unmarshal(b))
	assert.NotEmpty(t, resp.ResponseToken, "an AP_REQ that asked was denied its AP_REP by a field RFC 4178 forbids reading")

	silent := &SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{ReqFlags: set, mechToken: mutualAPREQ(t, false, false)}}

	b, err = silent.ResponseToken()
	require.NoError(t, err)

	resp = NegTokenResp{}

	require.NoError(t, resp.Unmarshal(b))
	assert.Empty(t, resp.ResponseToken, "an AP_REQ that did not ask was answered on the strength of that same field")
}

func TestResponseTokenWithoutARequestCompletesWithoutAnAPRep(t *testing.T) {
	t.Parallel()

	st := &SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{mechToken: mutualAPREQ(t, false, false)}}

	b, err := st.ResponseToken()
	require.NoError(t, err)

	var resp NegTokenResp

	require.NoError(t, resp.Unmarshal(b))
	assert.Equal(t, asn1.Enumerated(NegStateAcceptCompleted), resp.NegState)
	assert.True(t, resp.SupportedMech.Equal(gssapi.OIDKRB5.OID()))
	assert.Empty(t, resp.ResponseToken)
}

func TestNewAPReqKeepsThePlaintextAuthenticatorOffTheWire(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0xdd)
	mt, _ := verifiedAPREQ(t, key)

	require.False(t, mt.APReq.Authenticator.CTime.IsZero())

	b, err := mt.APReq.Marshal()
	require.NoError(t, err)

	var wire messages.APReq

	require.NoError(t, wire.Unmarshal(b))
	assert.True(t, wire.Authenticator.CTime.IsZero(), "the plaintext authenticator reached the wire")
	assert.NotEmpty(t, wire.EncryptedAuthenticator.Cipher, "the encrypted authenticator did not")
}

func TestNewNegTokenInitKRB5KeepsTheMechToken(t *testing.T) {
	t.Parallel()

	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})

	cl := client.Client{Credentials: creds}

	var tkt messages.Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(b))

	n, err := NewNegTokenInitKRB5(&cl, tkt, mutualSessionKey(0xee))
	require.NoError(t, err)
	require.NotEmpty(t, n.MechTokenBytes)

	mt, ok := n.mechToken.(*KRB5Token)
	require.True(t, ok, "the built KRB5 token was dropped, leaving only its bytes")
	assert.False(t, mt.APReq.Authenticator.CTime.IsZero())
}

func TestVerifyMutualRefusesMalformedReplies(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x12)
	mt, auth := verifiedAPREQ(t, key)

	apRep, err := mt.APRepToken()
	require.NoError(t, err)

	notAReply := KRB5Token{OID: mt.OID, APReq: mt.APReq}
	notAReply.tokID, _ = hex.DecodeString(TOK_ID_KRB_AP_REQ)

	apReqBytes, err := notAReply.Marshal()
	require.NoError(t, err)

	wrap := func(t *testing.T, inner []byte) []byte {
		t.Helper()

		resp := NegTokenResp{
			NegState:      asn1.Enumerated(NegStateAcceptCompleted),
			SupportedMech: gssapi.OIDKRB5.OID(),
			ResponseToken: inner,
		}

		b, err := resp.Marshal()
		require.NoError(t, err)

		return b
	}

	for _, tc := range []struct {
		name  string
		reply []byte
		want  string
	}{
		{"not a NegTokenResp at all", []byte{0x30, 0x00, 0xff}, "NegTokenResp"},
		{"a response token that is not a KRB5 token", wrap(t, []byte("garbage")), "KRB5 token"},
		{"a KRB5 token that is an AP-REQ", wrap(t, apReqBytes), "not an AP-REP"},
		{"an AP-REP whose ciphertext is rubbish", wrap(t, corruptCipher(t, apRep)), "session key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := initiatorOf(key, auth).VerifyMutual(tc.reply)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestResponseTokenSurfacesAnUnanswerableToken(t *testing.T) {
	t.Parallel()

	mt, _ := verifiedAPREQ(t, mutualSessionKey(0x13))
	mt.APReq.Ticket.DecryptedEncPart.Key = types.EncryptionKey{}

	_, err := (&SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{mechToken: mt}}).ResponseToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session key")
}

func TestAPRepTokenRefusesAnUnsupportedEnctype(t *testing.T) {
	t.Parallel()

	mt, _ := verifiedAPREQ(t, mutualSessionKey(0x14))
	mt.APReq.Ticket.DecryptedEncPart.Key = types.EncryptionKey{KeyType: 9999, KeyValue: make([]byte, 32)}

	_, err := mt.APRepToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt")
}

func TestVerifyMutualRefusesAReplyThatDecryptsToRubbish(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x15)
	mt, auth := verifiedAPREQ(t, key)

	ed, err := crypto.GetEncryptedData([]byte("this is not an EncAPRepPart"), key, keyusage.AP_REP_ENCPART, 0)
	require.NoError(t, err)

	rep := KRB5Token{
		OID:   mt.OID,
		APRep: messages.APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: ed},
	}
	rep.tokID, _ = hex.DecodeString(TOK_ID_KRB_AP_REP)

	inner, err := rep.Marshal()
	require.NoError(t, err)

	resp := NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptCompleted),
		SupportedMech: gssapi.OIDKRB5.OID(),
		ResponseToken: inner,
	}

	b, err := resp.Marshal()
	require.NoError(t, err)

	err = initiatorOf(key, auth).VerifyMutual(b)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed")
}

func TestMutualAuthenticationOptionDecidesTheAPRep(t *testing.T) {
	t.Parallel()

	asked := acceptedToken(t, "mutual-asked", MutualAuthentication())
	assert.Equal(t, asn1.Enumerated(NegStateAcceptCompleted), asked.NegState)
	assert.NotEmpty(t, asked.ResponseToken, "MutualAuthentication() was given and no AP_REP came back")

	silent := acceptedToken(t, "mutual-silent")
	assert.Equal(t, asn1.Enumerated(NegStateAcceptCompleted), silent.NegState,
		"an initiator that did not ask must still complete the negotiation")
	assert.Empty(t, silent.ResponseToken, "an initiator that did not ask was answered anyway")
}

func mutualSessionKey(fill byte) types.EncryptionKey {
	v := make([]byte, 32)
	for i := range v {
		v[i] = fill
	}

	return types.EncryptionKey{KeyType: 18, KeyValue: v}
}

func verifiedAPREQ(t *testing.T, key types.EncryptionKey, contextFlags ...int) (*KRB5Token, types.Authenticator) {
	t.Helper()

	if len(contextFlags) == 0 {
		contextFlags = []int{gssapi.ContextFlagInteg, gssapi.ContextFlagMutual}
	}

	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})

	cl := client.Client{Credentials: creds}

	var tkt messages.Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(b))

	mt, err := NewKRB5TokenAPREQ(&cl, tkt, key, contextFlags, []int{})
	require.NoError(t, err)

	auth := mt.APReq.Authenticator
	require.False(t, auth.CTime.IsZero(), "NewAPReq must keep the plaintext authenticator; the initiator has no other way to remember what it sent")

	auth.CTime = auth.CTime.Add(123456 * time.Nanosecond)
	mt.APReq.Authenticator = auth
	mt.APReq.Ticket.DecryptedEncPart.Key = key

	return &mt, auth
}

func initiator(key types.EncryptionKey, mt *KRB5Token) *SPNEGO {
	s := SPNEGOClient(&client.Client{}, "HTTP/host.test.gokrb5")
	s.rememberExchange(key, NegTokenInit{mechToken: mt})

	return s
}

func initiatorOf(key types.EncryptionKey, auth types.Authenticator) *SPNEGO {
	mt := &KRB5Token{}
	mt.APReq.Authenticator = auth

	return initiator(key, mt)
}

func acceptedToken(t *testing.T, cname string, opts ...KRB5TokenOption) NegTokenResp {
	t.Helper()

	kt := testKeytab(t)
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.test.gokrb5")
	now := time.Now().UTC()

	tkt, key, err := messages.NewTicket(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, cname), "TEST.GOKRB5",
		sname, "TEST.GOKRB5", types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		now, now, now.Add(time.Hour), now.Add(2*time.Hour))
	require.NoError(t, err)

	creds := credentials.New(cname, "TEST.GOKRB5")
	creds.SetCName(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, cname))

	n, err := NewNegTokenInitKRB5(&client.Client{Credentials: creds}, tkt, key, opts...)
	require.NoError(t, err)

	b, err := (&SPNEGOToken{Init: true, NegTokenInit: n}).Marshal()
	require.NoError(t, err)

	var st SPNEGOToken

	require.NoError(t, st.Unmarshal(b))

	ok, _, status := SPNEGOService(kt).AcceptSecContext(&st)
	require.True(t, ok, "status was %d: %s", status.Code, status.Message)

	reply, err := st.ResponseToken()
	require.NoError(t, err)

	var resp NegTokenResp

	require.NoError(t, resp.Unmarshal(reply))

	return resp
}

func corruptCipher(t *testing.T, apRep []byte) []byte {
	t.Helper()

	var rep KRB5Token

	require.NoError(t, rep.Unmarshal(apRep))
	require.NotEmpty(t, rep.APRep.EncPart.Cipher)

	rep.APRep.EncPart.Cipher[len(rep.APRep.EncPart.Cipher)-1] ^= 0xff

	b, err := rep.Marshal()
	require.NoError(t, err)

	return b
}

func mutualAPREQ(t *testing.T, option, flagged bool) *KRB5Token {
	t.Helper()

	contextFlags := []int{gssapi.ContextFlagInteg}
	if flagged {
		contextFlags = append(contextFlags, gssapi.ContextFlagMutual)
	}

	mt, _ := verifiedAPREQ(t, mutualSessionKey(0x31), contextFlags...)

	mt.APReq.APOptions = types.NewKrbFlags()
	if option {
		types.SetFlag(&mt.APReq.APOptions, flags.APOptionMutualRequired)
	}

	return mt
}
