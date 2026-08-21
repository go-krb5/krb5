package spnego

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestNegotiateChallenge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int
		headers []string
		token   []byte
		ok      bool
		err     string
	}{
		{name: "no header", status: http.StatusUnauthorized},
		{name: "not a challenge", status: http.StatusOK, headers: []string{"Negotiate"}},
		{name: "bare", status: http.StatusUnauthorized, headers: []string{"Negotiate"}, ok: true},
		{name: "trailing space", status: http.StatusUnauthorized, headers: []string{"Negotiate "}, ok: true},
		{
			// RFC 7235 Section 2.1 makes the auth-scheme case insensitive.
			name: "lower case scheme", status: http.StatusUnauthorized,
			headers: []string{"negotiate " + base64.StdEncoding.EncodeToString([]byte{0xa1, 0x00})},
			token:   []byte{0xa1, 0x00}, ok: true,
		},
		{
			name: "with a token", status: http.StatusUnauthorized,
			headers: []string{"Negotiate " + base64.StdEncoding.EncodeToString([]byte{0xa1, 0x00})},
			token:   []byte{0xa1, 0x00}, ok: true,
		},
		{
			name: "alongside another scheme", status: http.StatusUnauthorized,
			headers: []string{"Basic realm=\"test\"", "Negotiate " + base64.StdEncoding.EncodeToString([]byte{0xa1, 0x00})},
			token:   []byte{0xa1, 0x00}, ok: true,
		},
		{name: "another scheme only", status: http.StatusUnauthorized, headers: []string{"Basic realm=\"test\""}},
		{
			name: "undecodable token", status: http.StatusUnauthorized,
			headers: []string{"Negotiate !!!not base64!!!"}, err: "base64",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := &http.Response{StatusCode: tc.status, Header: http.Header{}}
			for _, h := range tc.headers {
				resp.Header.Add(HTTPHeaderAuthResponse, h)
			}

			token, ok, err := negotiateChallenge(resp)

			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.token, token)
		})
	}
}

func TestNegotiationNext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		token  func(t *testing.T) []byte
		action negotiationAction
		err    string
	}{
		{
			name:   "bare challenge starts the exchange",
			token:  func(*testing.T) []byte { return nil },
			action: negotiationInitiate,
		},
		{
			name: "accept-incomplete asks for another leg",
			token: func(t *testing.T) []byte {
				return negTokenRespBytes(t, NegTokenResp{
					NegState:      asn1.Enumerated(NegStateAcceptIncomplete),
					SupportedMech: gssapi.OIDKRB5.OID(),
				})
			},
			action: negotiationContinue,
		},
		{
			name: "the MS legacy Kerberos OID is Kerberos too",
			token: func(t *testing.T) []byte {
				return negTokenRespBytes(t, NegTokenResp{
					NegState:      asn1.Enumerated(NegStateAcceptIncomplete),
					SupportedMech: gssapi.OIDMSLegacyKRB5.OID(),
				})
			},
			action: negotiationContinue,
		},
		{
			name: "reject ends the exchange",
			token: func(t *testing.T) []byte {
				return negTokenRespBytes(t, NegTokenResp{NegState: asn1.Enumerated(NegStateReject)})
			},
			action: negotiationStop,
		},
		{
			name: "accept-completed ends the exchange",
			token: func(t *testing.T) []byte {
				return negTokenRespBytes(t, NegTokenResp{NegState: asn1.Enumerated(NegStateAcceptCompleted)})
			},
			action: negotiationStop,
		},
		{
			name: "a mechanism this client does not speak ends the exchange",
			token: func(t *testing.T) []byte {
				return negTokenRespBytes(t, NegTokenResp{
					NegState:      asn1.Enumerated(NegStateAcceptIncomplete),
					SupportedMech: oidNTLMSSP,
				})
			},
			action: negotiationStop,
		},
		{
			name: "request-mic asks for the MIC exchange",
			token: func(t *testing.T) []byte {
				return negTokenRespBytes(t, NegTokenResp{
					NegState:      asn1.Enumerated(NegStateRequestMIC),
					SupportedMech: gssapi.OIDKRB5.OID(),
					MechListMIC:   []byte{0x04, 0x04},
				})
			},
			action: negotiationAnswerMIC,
		},
		{
			// RFC 4178 Section 5(c)(IV) makes the target's own MIC mandatory here, so there is nothing to verify
			// and the exchange cannot proceed correctly.
			name: "request-mic without a MIC cannot be answered",
			token: func(t *testing.T) []byte {
				return negTokenRespBytes(t, NegTokenResp{
					NegState:      asn1.Enumerated(NegStateRequestMIC),
					SupportedMech: gssapi.OIDKRB5.OID(),
				})
			},
			err: "no mechListMIC",
		},
		{
			name:  "a NegTokenInit is not a reply from a target",
			token: func(t *testing.T) []byte { return negTokenInitBytes(t) },
			err:   "not a negotiation response",
		},
		{
			name:  "unreadable token",
			token: func(*testing.T) []byte { return []byte{0xff, 0xff, 0xff} },
			err:   "could not read",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			action, _, err := negotiationNext(tc.token(t))

			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.action, action)
		})
	}
}

func negTokenRespBytes(t *testing.T, nr NegTokenResp) []byte {
	t.Helper()

	b, err := nr.Marshal()
	require.NoError(t, err)

	return b
}

func negTokenInitBytes(t *testing.T) []byte {
	t.Helper()

	init := NegTokenInit{MechTypes: []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}}

	b, err := init.Marshal()
	require.NoError(t, err)

	return b
}

func TestClientBoundsTheNumberOfNegotiationLegs(t *testing.T) {
	t.Parallel()

	c := NewClient(nil, nil, "HTTP/localhost")
	c.legs = MaxNegotiationLegs

	send, err := c.nextNegotiationLeg(httptest.NewRequest(http.MethodGet, "http://host.test.gokrb5/", nil),
		&http.Response{Header: http.Header{}}, nil)

	assert.False(t, send)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not complete within")
}

func TestClientContinuesANegotiation(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.HTTP_KEYTAB)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	var legs atomic.Int32

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	authenticated := SPNEGOKRB5Authenticate(inner, kt)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HTTPHeaderAuthRequest) != "" && legs.Add(1) == 1 {
			w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespIncompleteKRB5)
			http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)

			return
		}

		authenticated.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	r, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := NewClient(integrationClient(t), srv.Client(), "HTTP/host.test.gokrb5").Do(r)
	require.NoError(t, err)

	t.Cleanup(func() { _ = resp.Body.Close() })

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.EqualValues(t, 2, legs.Load(), "the client must send a second token")
}

func TestClientReadsTheTokenInAChallenge(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(HTTPHeaderAuthResponse, "Negotiate !!!not base64!!!")
		http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	resp, err := NewClient(nil, srv.Client(), "HTTP/host.test.gokrb5").Get(srv.URL)
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}

	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64")
}

func TestClientStopsOnAReject(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespReject)
		http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	resp, err := NewClient(nil, srv.Client(), "HTTP/host.test.gokrb5").Get(srv.URL)
	require.NoError(t, err)

	t.Cleanup(func() { _ = resp.Body.Close() })

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.EqualValues(t, 1, requests.Load(), "a rejected negotiation must not be retried")
}

func integrationClient(t *testing.T) *client.Client {
	t.Helper()

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}

	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	require.NoError(t, cl.Login())

	return cl
}
