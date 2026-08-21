package spnego

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/keytab"
)

func TestSPNEGOKRB5AuthenticateReturnsAMechListMIC(t *testing.T) {
	t.Parallel()

	init, kt, key := negTokenInitWithMIC(t)

	resp := negotiateOverHTTP(t, kt, init)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp.Body.String())

	nt := negTokenRespFromHeader(t, resp.Header().Get(HTTPHeaderAuthResponse))

	assert.EqualValues(t, NegStateAcceptCompleted, nt.NegState)
	require.NotEmpty(t, nt.MechListMIC, "the acceptor must return a mechListMIC when the initiator sent one")

	payload, err := mechListMICPayload(nil, init.MechTypes)
	require.NoError(t, err)

	assert.NoError(t, verifyMechListMIC(nt.MechListMIC, payload, key, true))
}

func TestSPNEGOKRB5AuthenticateRejectsAnIncorrectMechListMIC(t *testing.T) {
	t.Parallel()

	init, kt, _ := negTokenInitWithMIC(t)
	init.MechListMIC[len(init.MechListMIC)-1] ^= 0xff

	resp := negotiateOverHTTP(t, kt, init)

	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Equal(t, spnegoNegTokenRespReject, resp.Header().Get(HTTPHeaderAuthResponse))
}

func TestSPNEGOKRB5AuthenticateNegotiatesWhenKerberosIsNotFirst(t *testing.T) {
	t.Parallel()

	init := NegTokenInit{
		MechTypes:      []asn1.ObjectIdentifier{oidNTLMSSP, gssapi.OIDKRB5.OID()},
		MechTokenBytes: []byte("NTLMSSP\x00\x01\x00\x00\x00"),
	}

	resp := negotiateOverHTTP(t, testKeytab(t), init)

	assert.Equal(t, http.StatusUnauthorized, resp.Code)

	nt := negTokenRespFromHeader(t, resp.Header().Get(HTTPHeaderAuthResponse))

	assert.EqualValues(t, NegStateAcceptIncomplete, nt.NegState)
	assert.True(t, isKerberosMech(nt.SupportedMech), "the acceptor must name the mechanism it selected")
}

func TestSPNEGOKRB5AuthenticateStillCompletesWithoutAMechListMIC(t *testing.T) {
	t.Parallel()

	mtb, _, kt := krb5MechToken(t)

	init := NegTokenInit{MechTypes: []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}, MechTokenBytes: mtb}

	resp := negotiateOverHTTP(t, kt, init)

	assert.Equal(t, http.StatusOK, resp.Code, "body: %s", resp.Body.String())
	assert.Equal(t, spnegoNegTokenRespKRBAcceptCompleted, resp.Header().Get(HTTPHeaderAuthResponse))
}

func negotiateOverHTTP(t *testing.T, kt *keytab.Keytab, init NegTokenInit) *httptest.ResponseRecorder {
	t.Helper()

	b, err := (&SPNEGOToken{Init: true, NegTokenInit: init}).Marshal()
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "http://host.test.gokrb5/", nil)
	r.Header.Set(HTTPHeaderAuthRequest, "Negotiate "+base64.StdEncoding.EncodeToString(b))

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("served"))
	})

	w := httptest.NewRecorder()
	SPNEGOKRB5Authenticate(inner, kt).ServeHTTP(w, r)

	return w
}

func negTokenRespFromHeader(t *testing.T, header string) NegTokenResp {
	t.Helper()

	name, token, found := strings.Cut(header, " ")
	require.True(t, found, "header %q carries no token", header)
	require.Equal(t, HTTPHeaderAuthResponseValueKey, name)

	b, err := base64.StdEncoding.DecodeString(token)
	require.NoError(t, err)

	init, nt, err := UnmarshalNegToken(b)
	require.NoError(t, err)
	require.False(t, init, "the target replies with a NegTokenResp")

	return nt.(NegTokenResp)
}
