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
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

// Mutual authentication, both halves.
//
// The acceptor's proof is that it could decrypt the ticket: an AP-REP encrypted under the session
// key, echoing the initiator's own ctime and cusec. So every test here turns on which key encrypts
// and which time is echoed, and the negative cases are the two ways a reply can be wrong — it came
// from something that did not hold the service key, or it answers a different exchange.
//
// The session key is set on the token directly rather than by accepting a real AP-REQ: what these
// exercise is what is done WITH a decrypted ticket, and acceptance is covered on its own elsewhere.

// mutualSessionKey is the key an exchange's ticket carries. Fixed rather than random so a failure
// names a behaviour instead of a seed.
func mutualSessionKey(fill byte) types.EncryptionKey {
	v := make([]byte, 32)
	for i := range v {
		v[i] = fill
	}

	return types.EncryptionKey{KeyType: 18, KeyValue: v}
}

// verifiedAPREQ is a KRB5Token in the state acceptance leaves it in: the ticket decrypted, so its
// session key is readable, and the authenticator in the clear.
//
// The ctime deliberately carries nanoseconds. They never reach the wire — ctime travels as a
// GeneralizedTime and is truncated to the second, with the sub-second part carried by cusec — and
// a comparison that forgets this rejects every reply it should accept.
func verifiedAPREQ(t *testing.T, key types.EncryptionKey) (*KRB5Token, types.Authenticator) {
	t.Helper()

	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})

	cl := client.Client{Credentials: creds}

	var tkt messages.Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(b))

	mt, err := NewKRB5TokenAPREQ(&cl, tkt, key, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagMutual}, []int{})
	require.NoError(t, err)

	auth := mt.APReq.Authenticator
	require.False(t, auth.CTime.IsZero(), "NewAPReq must keep the plaintext authenticator; the initiator has no other way to remember what it sent")

	auth.CTime = auth.CTime.Add(123456 * time.Nanosecond)
	mt.APReq.Authenticator = auth
	mt.APReq.Ticket.DecryptedEncPart.Key = key

	return &mt, auth
}

// initiator is an SPNEGO context in the state InitSecContext leaves it in, reached through the same
// call InitSecContext makes rather than by assigning the fields here — a test that set them itself
// would be checking its own assignment.
//
// The KRB5Token carries the authenticator, so wrapping it in a NegTokenInit is all the capture
// needs; the KDC round trip InitSecContext does first is what this avoids.
func initiator(key types.EncryptionKey, mt *KRB5Token) *SPNEGO {
	s := SPNEGOClient(&client.Client{}, "HTTP/host.test.gokrb5")
	s.rememberExchange(key, NegTokenInit{mechToken: mt})

	return s
}

// initiatorOf is the same, for the cases that need the remembered values to DIFFER from what was
// sent — a reply to another exchange.
func initiatorOf(key types.EncryptionKey, auth types.Authenticator) *SPNEGO {
	mt := &KRB5Token{}
	mt.APReq.Authenticator = auth

	return initiator(key, mt)
}

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

	// The whole claim, checked directly: it decrypts under the session key, and it echoes what the
	// initiator sent — at the precision the protocol carries.
	plain, err := crypto.DecryptEncPart(rep.APRep.EncPart, key, keyusage.AP_REP_ENCPART)
	require.NoError(t, err)

	var enc messages.EncAPRepPart

	require.NoError(t, enc.Unmarshal(plain))
	assert.Equal(t, auth.CTime.Unix(), enc.CTime.Unix())
	assert.Equal(t, auth.Cusec, enc.Cusec)
}

// TestAPRepTokenIsUnreadableWithoutTheSessionKey is the property the reply exists for: only
// something that decrypted the ticket could have produced it.
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

// TestKRB5TokenMarshalsAnAPRep pins the change underneath APRepToken: Marshal used to refuse this
// token id outright, so an acceptor had nothing to send even once it could build one.
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

// TestMutualRoundTrip is the loop the feature exists for: the acceptor answers, and the initiator
// that sent the AP-REQ accepts the answer.
func TestMutualRoundTrip(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x88)
	mt, auth := verifiedAPREQ(t, key)

	reply, err := (&SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{mechToken: mt}}).ResponseToken()
	require.NoError(t, err)

	// The capture is asserted here rather than taken on trust: it is the one link that decides what
	// the reply is compared against, and everything below it would still pass if it remembered the
	// wrong exchange but remembered it consistently.
	init := initiator(key, mt)
	assert.Equal(t, key, init.sessionKey)
	assert.Equal(t, auth.CTime, init.sentCTime, "the initiator did not remember the ctime it sent")
	assert.Equal(t, auth.Cusec, init.sentCusec)

	assert.NoError(t, init.VerifyMutual(reply))
}

// TestVerifyMutualRefusesAReplyToAnotherExchange: an AP-REP captured from an earlier exchange with
// the SAME service decrypts perfectly — the session key is the only thing that changed hands — so
// the echoed time is what tells the two apart.
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

	// And the same for cusec alone, which is the sub-second half of the comparison.
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

	// Accepted, but proving nothing: this is what "the server said something" looks like, and it is
	// exactly what a presence check would have let through.
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

// TestMutualRequested: the flag is optional and NewNegTokenInitKRB5 does not set it, so an absent
// ReqFlags is answered anyway — the reply costs one encryption, an initiator that does not check it
// is unaffected, and for an authentication feature the conservative direction proves more.
func TestMutualRequested(t *testing.T) {
	t.Parallel()

	assert.True(t, mutualRequested(NegTokenInit{}), "an absent ReqFlags must be answered, not skipped")

	set := asn1.BitString{Bytes: []byte{0x40}, BitLength: 8} // delegFlag(0), mutualFlag(1)
	assert.True(t, mutualRequested(NegTokenInit{ReqFlags: set}))

	clear := asn1.BitString{Bytes: []byte{0x80}, BitLength: 8} // delegFlag only
	assert.False(t, mutualRequested(NegTokenInit{ReqFlags: clear}))
}

// TestNewAPReqKeepsThePlaintextAuthenticatorOffTheWire covers the supporting change and its one
// risk: the initiator needs the authenticator it sent, and the wire must not carry it.
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

// TestNewNegTokenInitKRB5KeepsTheMechToken covers the other supporting change: without it the
// initiator cannot read back what it just sent, and ResponseToken has nothing to answer.
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

// TestVerifyMutualRefusesMalformedReplies walks the shapes a broken or hostile peer can send. None
// of them is exotic: the reply arrives over the same channel as everything else, and a verifier that
// panics or accepts on garbage is worse than one that does not exist.
func TestVerifyMutualRefusesMalformedReplies(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x12)
	mt, auth := verifiedAPREQ(t, key)

	apRep, err := mt.APRepToken()
	require.NoError(t, err)

	// A KRB5 token that is an AP-REQ rather than an AP-REP: well-formed, wrong direction.
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

// corruptCipher flips the last byte of an AP-REP's ciphertext, which the integrity check catches.
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

// TestResponseTokenSurfacesAnUnanswerableToken: an acceptor asked to answer a token whose ticket was
// never decrypted must say so rather than send a NegTokenResp with nothing in it, which a client
// checking only for presence would have accepted.
func TestResponseTokenSurfacesAnUnanswerableToken(t *testing.T) {
	t.Parallel()

	mt, _ := verifiedAPREQ(t, mutualSessionKey(0x13))
	mt.APReq.Ticket.DecryptedEncPart.Key = types.EncryptionKey{}

	_, err := (&SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{mechToken: mt}}).ResponseToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session key")
}

// TestAPRepTokenRefusesAnUnsupportedEnctype: the ticket decides the enctype, and a build that does
// not implement it cannot answer. Better a named refusal than a NegTokenResp with nothing in it,
// which is indistinguishable from an acceptor that does not do mutual authentication at all.
func TestAPRepTokenRefusesAnUnsupportedEnctype(t *testing.T) {
	t.Parallel()

	mt, _ := verifiedAPREQ(t, mutualSessionKey(0x14))
	mt.APReq.Ticket.DecryptedEncPart.Key = types.EncryptionKey{KeyType: 9999, KeyValue: make([]byte, 32)}

	_, err := mt.APRepToken()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt")
}

// TestVerifyMutualRefusesAReplyThatDecryptsToRubbish is the boundary between "decrypts" and "means
// something". A peer holding the session key can still send the wrong payload — through a bug, or
// deliberately, to see what the verifier does with it — and the answer must be a refusal rather
// than whatever a half-parsed EncAPRepPart happens to contain.
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
