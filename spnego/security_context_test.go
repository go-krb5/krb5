package spnego

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

func TestSecurityLayerSessionRequiresAnInitiatedContext(t *testing.T) {
	t.Parallel()

	_, err := SPNEGOClient(&client.Client{}, "HTTP/host.test.gokrb5").NewSecurityLayerSession(gssapi.SecurityLayerConfidentiality, 0)
	assert.EqualError(t, err, "spnego: this context never initiated, so there is no established context to protect messages with")
}

func TestSecurityLayerSessionWithoutAnAPRepUsesTheSessionKey(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x51)
	mt, auth := verifiedAPREQ(t, key)

	session, err := initiator(key, mt).NewSecurityLayerSession(gssapi.SecurityLayerConfidentiality, 0)
	require.NoError(t, err)

	seq := seqNum(auth.SeqNumber)
	acceptor := acceptorSession(t, gssapi.SecurityLayerConfidentiality, key, false, seq, seq)

	assertSessionsInteroperate(t, session, acceptor)
}

func TestSecurityLayerSessionUsesTheAcceptorSubkey(t *testing.T) {
	t.Parallel()

	key, subkey := mutualSessionKey(0x52), mutualSessionKey(0x53)
	mt, auth := verifiedAPREQ(t, key, gssapi.ContextFlagMutual)

	init := initiator(key, mt)
	require.NoError(t, init.VerifyMutual(apRepReply(t, key, auth, subkey, 4242)))

	session, err := init.NewSecurityLayerSession(gssapi.SecurityLayerConfidentiality, 0, gssapi.RotateTrailer())
	require.NoError(t, err)

	acceptor := acceptorSession(t, gssapi.SecurityLayerConfidentiality, subkey, true, 4242, seqNum(auth.SeqNumber))

	assertSessionsInteroperate(t, session, acceptor)

	token, err := session.Wrap([]byte("flagged"))
	require.NoError(t, err)
	assert.Equal(t, gssapi.FlagAcceptorSubkey, token[2]&gssapi.FlagAcceptorSubkey)
}

func TestSecurityLayerSessionReadsASignedAPRepSequenceNumber(t *testing.T) {
	t.Parallel()

	key := mutualSessionKey(0x54)
	mt, auth := verifiedAPREQ(t, key, gssapi.ContextFlagMutual)

	init := initiator(key, mt)
	require.NoError(t, init.VerifyMutual(apRepReply(t, key, auth, types.EncryptionKey{}, -1)))

	session, err := init.NewSecurityLayerSession(gssapi.SecurityLayerIntegrity, 0)
	require.NoError(t, err)

	acceptor := acceptorSession(t, gssapi.SecurityLayerIntegrity, key, false, 0xFFFFFFFF, seqNum(auth.SeqNumber))

	assertSessionsInteroperate(t, session, acceptor)
}

func TestSecurityLayerSessionUsesTheInitiatorSubkey(t *testing.T) {
	t.Parallel()

	key, subkey := mutualSessionKey(0x55), mutualSessionKey(0x56)
	mt, auth := verifiedAPREQ(t, key)
	mt.APReq.Authenticator.SubKey = subkey

	session, err := initiator(key, mt).NewSecurityLayerSession(gssapi.SecurityLayerConfidentiality, 0)
	require.NoError(t, err)

	seq := seqNum(auth.SeqNumber)
	acceptor := acceptorSession(t, gssapi.SecurityLayerConfidentiality, subkey, false, seq, seq)

	assertSessionsInteroperate(t, session, acceptor)
}

func TestClientSecurityLayerSessionRequiresAnEstablishedContext(t *testing.T) {
	t.Parallel()

	c := NewClient(mutualClient(t), nil, impersonationSPN)

	_, err := c.NewSecurityLayerSession(gssapi.SecurityLayerConfidentiality, 0)
	assert.EqualError(t, err, "spnego: the client has not established a context with the target")
}

func TestClientSecurityLayerSessionUsesTheAcceptorSubkey(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(subkeyAcceptor(t))
	t.Cleanup(srv.Close)

	c := NewClient(mutualClient(t), nil, impersonationSPN, TokenOptions(MutualAuthentication()))

	resp, err := c.Get(srv.URL)
	require.NoError(t, err)

	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	session, err := c.NewSecurityLayerSession(gssapi.SecurityLayerConfidentiality, 0, gssapi.RotateTrailer())
	require.NoError(t, err)

	got, err := session.Unwrap(body)
	require.NoError(t, err)
	assert.Equal(t, []byte("served"), got)
}

func TestClientSecurityLayerSessionWithoutMutualAuthentication(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(SPNEGOKRB5Authenticate(servedHandler(), testKeytab(t)))
	t.Cleanup(srv.Close)

	c := NewClient(mutualClient(t), nil, impersonationSPN)

	resp, err := c.Get(srv.URL)
	require.NoError(t, err)

	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	session, err := c.NewSecurityLayerSession(gssapi.SecurityLayerConfidentiality, 0)
	require.NoError(t, err)

	key, acceptorSubkey, err := c.established.protocolKey()
	require.NoError(t, err)
	assert.False(t, acceptorSubkey)

	seq := seqNum(c.established.sentSeqNum)
	assertSessionsInteroperate(t, session, acceptorSession(t, gssapi.SecurityLayerConfidentiality, key, false, seq, seq))
}

func acceptorSession(t *testing.T, layer gssapi.SecurityLayer, key types.EncryptionKey, acceptorSubkey bool, send, recv uint64) *gssapi.SecurityLayerSession {
	t.Helper()

	opts := []gssapi.SecurityLayerOption{gssapi.InitialSendSequenceNumber(send), gssapi.InitialReceiveSequenceNumber(recv)}
	if acceptorSubkey {
		opts = append(opts, gssapi.AcceptorSubkey())
	}

	s, err := gssapi.NewSecurityLayerSession(key, layer, false, 0, opts...)
	require.NoError(t, err)

	return s
}

func assertSessionsInteroperate(t *testing.T, initiator, acceptor *gssapi.SecurityLayerSession) {
	t.Helper()

	for _, message := range [][]byte{[]byte("first"), []byte("second")} {
		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		got, err := acceptor.Unwrap(token)
		require.NoError(t, err)
		assert.Equal(t, message, got)

		reply, err := acceptor.Wrap(message)
		require.NoError(t, err)

		got, err = initiator.Unwrap(reply)
		require.NoError(t, err)
		assert.Equal(t, message, got)
	}
}

func apRepReply(t *testing.T, key types.EncryptionKey, auth types.Authenticator, subkey types.EncryptionKey, seq int64) []byte {
	t.Helper()

	rep, err := subkeyAPRep(key, auth, subkey, seq)
	require.NoError(t, err)

	b, err := (&NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptCompleted),
		SupportedMech: gssapi.OIDKRB5.OID(),
		ResponseToken: rep,
	}).Marshal()
	require.NoError(t, err)

	return b
}

func subkeyAPRep(key types.EncryptionKey, auth types.Authenticator, subkey types.EncryptionKey, seq int64) ([]byte, error) {
	enc := messages.EncAPRepPart{CTime: auth.CTime, Cusec: auth.Cusec, Subkey: subkey, SequenceNumber: seq}

	plain, err := enc.Marshal()
	if err != nil {
		return nil, err
	}

	ed, err := crypto.GetEncryptedData(plain, key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, err
	}

	rep := KRB5Token{
		OID:   gssapi.OIDKRB5.OID(),
		APRep: messages.APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: ed},
	}
	rep.tokID, _ = hex.DecodeString(TOK_ID_KRB_AP_REP)

	return rep.Marshal()
}

func subkeyAcceptor(t *testing.T) http.Handler {
	t.Helper()

	const acceptorSeq = 777

	kt := testKeytab(t)
	subkey := mutualSessionKey(0x57)
	payload, err := mechListMICPayload(nil, initiatorMechTypes())
	require.NoError(t, err)

	var initiatorSeq int64

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := strings.CutPrefix(r.Header.Get(HTTPHeaderAuthRequest), HTTPHeaderAuthResponseValueKey+" ")
		if !ok {
			w.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var st SPNEGOToken
		if err = st.Unmarshal(b); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if st.Resp {
			if err = verifyMechListMIC(st.NegTokenResp.MechListMIC, payload, subkey, false, true); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			s, err := gssapi.NewSecurityLayerSession(subkey, gssapi.SecurityLayerConfidentiality, false, 0,
				gssapi.AcceptorSubkey(), gssapi.RotateTrailer(), gssapi.InitialSendSequenceNumber(acceptorSeq),
				gssapi.InitialReceiveSequenceNumber(seqNum(initiatorSeq)))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			token, err := s.Wrap([]byte("served"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespKRBAcceptCompleted)
			_, _ = w.Write(token)

			return
		}

		if ok, _, status := SPNEGOService(kt).AcceptSecContext(&st); !ok {
			http.Error(w, status.Message, http.StatusUnauthorized)
			return
		}

		mt := st.verifiedMechToken()
		initiatorSeq = mt.APReq.Authenticator.SeqNumber

		rep, err := subkeyAPRep(mt.APReq.Ticket.DecryptedEncPart.Key, mt.APReq.Authenticator, subkey, acceptorSeq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		mic, err := newMechListMIC(payload, subkey, true, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		nb, err := (&NegTokenResp{
			NegState:      asn1.Enumerated(NegStateRequestMIC),
			SupportedMech: gssapi.OIDKRB5.OID(),
			ResponseToken: rep,
			MechListMIC:   mic,
		}).Marshal()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey+" "+base64.StdEncoding.EncodeToString(nb))
		w.WriteHeader(http.StatusUnauthorized)
	})
}
