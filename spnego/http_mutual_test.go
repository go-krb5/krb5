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

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestSPNEGOKRB5AuthenticateAnswersMutualAuthenticationWithAnAPRep(t *testing.T) {
	t.Parallel()

	imp, _ := impersonation(t)
	init := SPNEGOClient(kdclessClient(t), impersonationSPN, OnBehalfOf(imp), MutualAuthentication())

	ct, err := init.InitSecContext()
	require.NoError(t, err)

	resp := negotiateOverHTTP(t, testKeytab(t), ct.(*SPNEGOToken).NegTokenInit)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp.Body.String())

	nt := negTokenRespFromHeader(t, resp.Header().Get(HTTPHeaderAuthResponse))
	require.NotEmpty(t, nt.ResponseToken, "the acceptor was asked to prove itself and sent no AP-REP")

	b, err := nt.Marshal()
	require.NoError(t, err)
	assert.NoError(t, init.VerifyMutual(b))
}

func TestSPNEGOKRB5AuthenticateAnswersMutualAuthenticationAlongsideAMechListMIC(t *testing.T) {
	t.Parallel()

	imp, _ := impersonation(t)
	init := SPNEGOClient(kdclessClient(t), impersonationSPN, OnBehalfOf(imp), MutualAuthentication())

	ct, err := init.InitSecContext()
	require.NoError(t, err)

	n := ct.(*SPNEGOToken).NegTokenInit
	n.MechTypes = append(n.MechTypes, oidNTLMSSP)

	payload, err := mechListMICPayload(nil, n.MechTypes)
	require.NoError(t, err)

	n.MechListMIC, err = newMechListMIC(payload, imp.SessionKey, false)
	require.NoError(t, err)

	resp := negotiateOverHTTP(t, testKeytab(t), n)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp.Body.String())

	nt := negTokenRespFromHeader(t, resp.Header().Get(HTTPHeaderAuthResponse))
	require.NotEmpty(t, nt.MechListMIC)
	assert.NoError(t, verifyMechListMIC(nt.MechListMIC, payload, imp.SessionKey, true))

	b, err := nt.Marshal()
	require.NoError(t, err)
	assert.NoError(t, init.VerifyMutual(b))
}

func TestClientVerifiesTheAcceptorWhenMutualAuthenticationIsRequested(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(SPNEGOKRB5Authenticate(servedHandler(), testKeytab(t)))
	t.Cleanup(srv.Close)

	c := NewClient(mutualClient(t), nil, impersonationSPN, TokenOptions(MutualAuthentication()))

	resp, err := c.Get(srv.URL)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestClientRefusesAnAcceptorThatDoesNotProveItself(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HTTPHeaderAuthRequest) == "" {
			w.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespKRBAcceptCompleted)
		_, _ = w.Write([]byte("served"))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(mutualClient(t), nil, impersonationSPN, TokenOptions(MutualAuthentication()))

	resp, err := c.Get(srv.URL)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "AP-REP")
}

func TestClientWithoutMutualAuthenticationDoesNotRequireAnAPRep(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HTTPHeaderAuthRequest) == "" {
			w.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		_, _ = w.Write([]byte("served"))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(mutualClient(t), nil, impersonationSPN)

	resp, err := c.Get(srv.URL)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestClientVerifiesTheAcceptorOnARedirectThatEndsTheNegotiation(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.Handle("/protected", SPNEGOKRB5Authenticate(http.RedirectHandler("/public", http.StatusFound), testKeytab(t)))
	mux.Handle("/public", servedHandler())

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := NewClient(mutualClient(t), nil, impersonationSPN, TokenOptions(MutualAuthentication()))

	resp, err := c.Get(srv.URL + "/protected")
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestClientVerifiesTheAcceptorAfterAContinuedNegotiation(t *testing.T) {
	t.Parallel()

	acceptor := SPNEGOKRB5Authenticate(servedHandler(), testKeytab(t))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := strings.CutPrefix(r.Header.Get(HTTPHeaderAuthRequest), HTTPHeaderAuthResponseValueKey+" ")
		if ok {
			var st SPNEGOToken
			if b, err := base64.StdEncoding.DecodeString(v); err == nil && st.Unmarshal(b) == nil && st.Init {
				w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespIncompleteKRB5)
				w.WriteHeader(http.StatusUnauthorized)

				return
			}
		}

		acceptor.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(mutualClient(t), nil, impersonationSPN, TokenOptions(MutualAuthentication()))

	resp, err := c.Get(srv.URL)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestClientVerifiesAnAPRepSentWithARequestForTheMechListMIC(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(requestMICAcceptor(t, func(rep []byte) []byte { return rep }))
	t.Cleanup(srv.Close)

	c := NewClient(mutualClient(t), nil, impersonationSPN, TokenOptions(MutualAuthentication()))

	resp, err := c.Get(srv.URL)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestClientRefusesAForgedAPRepSentWithARequestForTheMechListMIC(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(requestMICAcceptor(t, func(rep []byte) []byte { return corruptCipher(t, rep) }))
	t.Cleanup(srv.Close)

	c := NewClient(mutualClient(t), nil, impersonationSPN, TokenOptions(MutualAuthentication()))

	resp, err := c.Get(srv.URL)
	require.Error(t, err)
	assert.ErrorContains(t, err, "session key")

	if resp != nil {
		resp.Body.Close()
	}
}

func servedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("served"))
	})
}

func requestMICAcceptor(t *testing.T, apRep func([]byte) []byte) http.Handler {
	t.Helper()

	kt := testKeytab(t)

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
			w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespKRBAcceptCompleted)
			_, _ = w.Write([]byte("served"))

			return
		}

		if ok, _, status := SPNEGOService(kt).AcceptSecContext(&st); !ok {
			http.Error(w, status.Message, http.StatusUnauthorized)
			return
		}

		mt := st.verifiedMechToken()

		rep, err := mt.APRepToken()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		payload, err := mechListMICPayload(nil, initiatorMechTypes())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		mic, err := newMechListMIC(payload, mt.APReq.Ticket.DecryptedEncPart.Key, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		nt := NegTokenResp{
			NegState:      asn1.Enumerated(NegStateRequestMIC),
			SupportedMech: gssapi.OIDKRB5.OID(),
			ResponseToken: apRep(rep),
			MechListMIC:   mic,
		}

		nb, err := nt.Marshal()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey+" "+base64.StdEncoding.EncodeToString(nb))
		w.WriteHeader(http.StatusUnauthorized)
	})
}

func mutualClient(t *testing.T) *client.Client {
	t.Helper()

	cname := fixtureClient()
	now := time.Now().UTC()

	tgt := messages.Ticket{
		TktVNO:  iana.PVNO,
		Realm:   impersonationRealm,
		SName:   types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+impersonationRealm),
		EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 1, Cipher: []byte("opaque to the client")},
	}
	tgtb, err := tgt.Marshal()
	require.NoError(t, err)

	tkt, key, err := messages.NewTicket(cname, impersonationRealm,
		types.NewPrincipalName(nametype.KRB_NT_SRV_INST, impersonationSPN), impersonationRealm,
		types.NewKrbFlags(), testKeytab(t), etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		now, now, now.Add(time.Hour), now.Add(2*time.Hour))
	require.NoError(t, err)

	tktb, err := tkt.Marshal()
	require.NoError(t, err)

	cc := credentials.NewV4CCache()
	cc.SetDefaultPrincipal(credentials.NewPrincipal(cname, impersonationRealm))
	cc.AddCredential(&credentials.Credential{
		Client:      credentials.NewPrincipal(cname, impersonationRealm),
		Server:      credentials.NewPrincipal(tgt.SName, impersonationRealm),
		Key:         mutualSessionKey(0x5a),
		AuthTime:    now,
		StartTime:   now,
		EndTime:     now.Add(time.Hour),
		RenewTill:   now.Add(2 * time.Hour),
		TicketFlags: types.NewKrbFlags(),
		Ticket:      tgtb,
	})
	cc.AddCredential(&credentials.Credential{
		Client:      credentials.NewPrincipal(cname, impersonationRealm),
		Server:      credentials.NewPrincipal(tkt.SName, impersonationRealm),
		Key:         key,
		AuthTime:    now,
		StartTime:   now,
		EndTime:     now.Add(time.Hour),
		RenewTill:   now.Add(2 * time.Hour),
		TicketFlags: types.NewKrbFlags(),
		Ticket:      tktb,
	})

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	for i := range c.Realms {
		c.Realms[i].KDC = nil
	}

	c.LibDefaults.NoAddresses = true

	cl, err := client.NewFromCCache(cc, c)
	require.NoError(t, err)

	return cl
}
