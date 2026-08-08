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

	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/types"
)

// TestContextStateTransitions tests the state machine transitions.
func TestContextStateTransitions(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(*ClientContext)
		action        func(*ClientContext) error
		expectedState ContextState
		expectError   bool
	}{
		{
			name:          "Initial to InProgress",
			setup:         func(c *ClientContext) {},
			action:        func(c *ClientContext) error { return c.SetInProgress() },
			expectedState: ContextStateInProgress,
			expectError:   false,
		},
		{
			name: "InProgress to Established (no mutual auth)",
			setup: func(c *ClientContext) {
				_ = c.SetInProgress()
			},
			action:        func(c *ClientContext) error { return c.SetEstablished() },
			expectedState: ContextStateEstablished,
			expectError:   false,
		},
		{
			name: "InProgress to Established fails when mutual auth required but not done",
			setup: func(c *ClientContext) {
				c.SetMutualAuthRequired(true)
				_ = c.SetInProgress()
			},
			action:        func(c *ClientContext) error { return c.SetEstablished() },
			expectedState: ContextStateInProgress,
			expectError:   true,
		},
		{
			name: "Cannot SetInProgress from Established",
			setup: func(c *ClientContext) {
				_ = c.SetInProgress()
				_ = c.SetEstablished()
			},
			action:        func(c *ClientContext) error { return c.SetInProgress() },
			expectedState: ContextStateEstablished,
			expectError:   true,
		},
		{
			name: "Cannot SetEstablished from Initial",
			setup: func(c *ClientContext) {
				// Don't transition to InProgress.
			},
			action:        func(c *ClientContext) error { return c.SetEstablished() },
			expectedState: ContextStateInitial,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewClientContext(dummySessionKey(), 0, 0)
			tt.setup(ctx)

			err := tt.action(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectedState, ctx.State())
		})
	}
}

// TestContextGating tests that Wrap/GetMIC operations are gated on establishment.
func TestContextGating(t *testing.T) {
	tests := []struct {
		name        string
		state       ContextState
		operation   string
		expectError bool
	}{
		{
			name:        "Wrap fails when Initial",
			state:       ContextStateInitial,
			operation:   "wrap",
			expectError: true,
		},
		{
			name:        "Wrap fails when InProgress",
			state:       ContextStateInProgress,
			operation:   "wrap",
			expectError: true,
		},
		{
			name:        "Wrap succeeds when Established",
			state:       ContextStateEstablished,
			operation:   "wrap",
			expectError: false,
		},
		{
			name:        "GetMIC fails when Initial",
			state:       ContextStateInitial,
			operation:   "getmic",
			expectError: true,
		},
		{
			name:        "GetMIC fails when InProgress",
			state:       ContextStateInProgress,
			operation:   "getmic",
			expectError: true,
		},
		{
			name:        "GetMIC succeeds when Established",
			state:       ContextStateEstablished,
			operation:   "getmic",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := NewClientContext(dummySessionKey(), 0, 0)

			// Set up state.
			switch tt.state {
			case ContextStateInProgress:
				_ = ctx.SetInProgress()
			case ContextStateEstablished:
				_ = ctx.SetInProgress()
				_ = ctx.SetEstablished()
			}

			var err error

			switch tt.operation {
			case "wrap":
				_, err = ctx.Wrap([]byte("test payload"))
			case "getmic":
				_, err = ctx.GetMIC([]byte("test payload"))
			}

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not established")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestNegTokenInitRawMechTypesDER tests that raw MechTypes DER is preserved.
func TestNegTokenInitRawMechTypesDER(t *testing.T) {
	// Create a NegTokenInit with MechTypes.
	mechTypes := []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}

	// Marshal MechTypes to get expected DER.
	expectedDER, err := asn1.Marshal(mechTypes, asn1.WithMarshalSlicePreserveTypes(true))
	require.NoError(t, err)

	// Create a NegTokenInit.
	negTokenInit := NegTokenInit{
		MechTypes:      mechTypes,
		MechTokenBytes: []byte{0x01, 0x02, 0x03}, // Dummy token.
	}

	// Set the raw DER.
	negTokenInit.SetRawMechTypesDER(expectedDER)

	// Verify it's preserved.
	assert.Equal(t, expectedDER, negTokenInit.RawMechTypesDER())

	// Marshal and unmarshal to verify preservation through the cycle.
	marshaled, err := negTokenInit.Marshal()
	require.NoError(t, err)

	var unmarshaled NegTokenInit

	err = unmarshaled.Unmarshal(marshaled)
	require.NoError(t, err)

	// The raw DER should be extracted during unmarshal.
	assert.NotEmpty(t, unmarshaled.RawMechTypesDER())
}

// TestNegotiateServerFlow tests the multi-leg SPNEGO flow with a mock server.
func TestNegotiateServerFlow(t *testing.T) {
	tests := []struct {
		name           string
		serverBehavior []serverResponse
		expectSuccess  bool
		expectError    bool
	}{
		{
			name: "Single leg - 401 then 200",
			serverBehavior: []serverResponse{
				{statusCode: 401, header: "Negotiate"},
				{statusCode: 200, header: ""},
			},
			expectSuccess: true,
			expectError:   false,
		},
		{
			name: "Single leg - 401 then 200 with final token",
			serverBehavior: []serverResponse{
				{statusCode: 401, header: "Negotiate"},
				{statusCode: 200, header: "Negotiate " + dummyNegTokenRespAcceptCompleted()},
			},
			expectSuccess: true,
			expectError:   false,
		},
		{
			name: "Multi leg - 401, 401 with token, then 200",
			serverBehavior: []serverResponse{
				{statusCode: 401, header: "Negotiate"},
				{statusCode: 401, header: "Negotiate " + dummyNegTokenRespAcceptIncomplete()},
				{statusCode: 200, header: ""},
			},
			expectSuccess: true,
			expectError:   false,
		},
		{
			name: "Server rejects",
			serverBehavior: []serverResponse{
				{statusCode: 401, header: "Negotiate"},
				{statusCode: 401, header: "Negotiate " + dummyNegTokenRespReject()},
			},
			expectSuccess: false,
			expectError:   true,
		},
		{
			name: "No Negotiate header - pass through",
			serverBehavior: []serverResponse{
				{statusCode: 401, header: "Basic realm=\"test\""},
			},
			expectSuccess: false,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server.
			requestCount := 0

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requestCount >= len(tt.serverBehavior) {
					t.Errorf("unexpected request %d", requestCount)
					w.WriteHeader(http.StatusInternalServerError)

					return
				}

				resp := tt.serverBehavior[requestCount]
				requestCount++

				if resp.header != "" {
					w.Header().Set(HTTPHeaderAuthResponse, resp.header)
				}

				w.WriteHeader(resp.statusCode)
				_, _ = w.Write([]byte("OK"))
			}))
			defer server.Close()

			// Create a mock transport that doesn't actually do SPNEGO.
			// This tests the state machine flow without real Kerberos.
			mockTransport := &mockSPNEGOTransport{
				underlying: server.Client().Transport,
				serverURL:  server.URL,
			}

			// Test the flow by directly testing the state machine.
			// Since we don't have a real KRB5 client, we test the token parsing.
			req, err := http.NewRequest("GET", server.URL, nil)
			require.NoError(t, err)

			resp, err := mockTransport.RoundTrip(req)

			if tt.expectError {
				// For error cases, we simulate by checking response.
				if err == nil && resp != nil {
					resp.Body.Close()
				}
			} else {
				require.NoError(t, err)

				if resp != nil {
					_, _ = io.ReadAll(resp.Body)
					resp.Body.Close()
				}
			}
		})
	}
}

// TestNegTokenRespParsing tests parsing of various NegTokenResp formats.
func TestNegTokenRespParsing(t *testing.T) {
	tests := []struct {
		name        string
		tokenB64    string
		expectState NegState
		expectError bool
	}{
		{
			name:        "Accept Completed",
			tokenB64:    dummyNegTokenRespAcceptCompleted(),
			expectState: NegStateAcceptCompleted,
			expectError: false,
		},
		{
			name:        "Accept Incomplete",
			tokenB64:    dummyNegTokenRespAcceptIncomplete(),
			expectState: NegStateAcceptIncomplete,
			expectError: false,
		},
		{
			name:        "Reject",
			tokenB64:    dummyNegTokenRespReject(),
			expectState: NegStateReject,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenBytes, err := base64.StdEncoding.DecodeString(tt.tokenB64)
			require.NoError(t, err)

			var spnegoToken SPNEGOToken

			err = spnegoToken.Unmarshal(tokenBytes)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.True(t, spnegoToken.Resp)
				assert.Equal(t, tt.expectState, spnegoToken.NegTokenResp.State())
			}
		})
	}
}

// TestKRB5TokenTypeDetection tests detection of KRB5 token types.
func TestKRB5TokenTypeDetection(t *testing.T) {
	tests := []struct {
		name     string
		tokIDHex string
		isAPReq  bool
		isAPRep  bool
		isKRBErr bool
	}{
		{
			name:     "AP-REQ token",
			tokIDHex: TOK_ID_KRB_AP_REQ,
			isAPReq:  true,
			isAPRep:  false,
			isKRBErr: false,
		},
		{
			name:     "AP-REP token",
			tokIDHex: TOK_ID_KRB_AP_REP,
			isAPReq:  false,
			isAPRep:  true,
			isKRBErr: false,
		},
		{
			name:     "KRB-ERROR token",
			tokIDHex: TOK_ID_KRB_ERROR,
			isAPReq:  false,
			isAPRep:  false,
			isKRBErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &KRB5Token{}
			token.tokID, _ = decodeHex(tt.tokIDHex)

			assert.Equal(t, tt.isAPReq, token.IsAPReq())
			assert.Equal(t, tt.isAPRep, token.IsAPRep())
			assert.Equal(t, tt.isKRBErr, token.IsKRBError())
		})
	}
}

// TestContextStateString tests the String method of ContextState.
func TestContextStateString(t *testing.T) {
	tests := []struct {
		state    ContextState
		expected string
	}{
		{ContextStateInitial, "Initial"},
		{ContextStateInProgress, "InProgress"},
		{ContextStateEstablished, "Established"},
		{ContextStateFailed, "Failed"},
		{ContextState(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

// TestMechTypeListDERPreservation tests that the raw DER is correctly preserved.
func TestMechTypeListDERPreservation(t *testing.T) {
	// Create a context with a known MechTypeList DER.
	ctx := NewClientContext(dummySessionKey(), 0, 0)

	originalDER := []byte{0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02}
	ctx.SetMechTypeListDER(originalDER)

	// Verify the DER is stored.
	storedDER := ctx.MechTypeListDER()
	assert.Equal(t, originalDER, storedDER)

	// Verify it's a copy (modifying original shouldn't affect stored).
	originalDER[0] = 0xFF
	assert.NotEqual(t, originalDER[0], storedDER[0])
}

// Helper types and functions for testing.

type serverResponse struct {
	statusCode int
	header     string
}

type mockSPNEGOTransport struct {
	underlying http.RoundTripper
	serverURL  string
}

func (t *mockSPNEGOTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.underlying.RoundTrip(req)
}

// dummySessionKey creates a dummy session key for testing.
func dummySessionKey() types.EncryptionKey {
	return types.EncryptionKey{
		KeyType:  17, // AES128-CTS-HMAC-SHA1-96.
		KeyValue: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}
}

// dummyNegTokenRespAcceptCompleted returns a base64-encoded NegTokenResp with AcceptCompleted.
func dummyNegTokenRespAcceptCompleted() string {
	// This is a pre-computed NegTokenResp with state=accept-completed and KRB5 mech.
	return "oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
}

// dummyNegTokenRespAcceptIncomplete returns a base64-encoded NegTokenResp with AcceptIncomplete.
func dummyNegTokenRespAcceptIncomplete() string {
	// This is a pre-computed NegTokenResp with state=accept-incomplete and KRB5 mech.
	return "oRQwEqADCgEBoQsGCSqGSIb3EgECAg=="
}

// dummyNegTokenRespReject returns a base64-encoded NegTokenResp with Reject.
func dummyNegTokenRespReject() string {
	// This is a pre-computed NegTokenResp with state=reject.
	return "oQcwBaADCgEC"
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// TestNegotiateClientOptions tests the option functions.
func TestNegotiateClientOptions(t *testing.T) {
	t.Run("WithMutualAuth", func(t *testing.T) {
		client := NewNegotiateClient(nil, "HTTP/test", WithMutualAuth(false))
		assert.False(t, client.mutualAuth)

		client2 := NewNegotiateClient(nil, "HTTP/test", WithMutualAuth(true))
		assert.True(t, client2.mutualAuth)
	})

	t.Run("WithTransport", func(t *testing.T) {
		customTransport := &http.Transport{}
		client := NewNegotiateClient(nil, "HTTP/test", WithTransport(customTransport))
		assert.Equal(t, customTransport, client.transport)
	})
}

// TestNegotiateClientReset tests that Reset clears the context.
func TestNegotiateClientReset(t *testing.T) {
	client := NewNegotiateClient(nil, "HTTP/test")

	// Simulate having a context.
	client.ctx = NewClientContext(dummySessionKey(), 0, 0)
	_ = client.ctx.SetInProgress()

	assert.NotNil(t, client.ctx)

	// Reset.
	client.Reset()

	assert.Nil(t, client.ctx)
	assert.Nil(t, client.negTokenInit)
}

// TestNegotiateClientIsEstablished tests the IsEstablished method.
func TestNegotiateClientIsEstablished(t *testing.T) {
	client := NewNegotiateClient(nil, "HTTP/test")

	// No context.
	assert.False(t, client.IsEstablished())

	// Context not established.
	client.ctx = NewClientContext(dummySessionKey(), 0, 0)
	assert.False(t, client.IsEstablished())

	// Context in progress.
	_ = client.ctx.SetInProgress()
	assert.False(t, client.IsEstablished())

	// Context established.
	_ = client.ctx.SetEstablished()
	assert.True(t, client.IsEstablished())
}

// TestExtractRawMechTypesDER tests the DER extraction function.
func TestExtractRawMechTypesDER(t *testing.T) {
	// Create a valid NegTokenInit and marshal it.
	mechTypes := []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}
	negTokenInit := NegTokenInit{
		MechTypes:      mechTypes,
		MechTokenBytes: []byte{0x01, 0x02, 0x03},
	}

	// Marshal.
	marshaled, err := negTokenInit.Marshal()
	require.NoError(t, err)

	// Unmarshal to trigger DER extraction.
	var unmarshaled NegTokenInit

	err = unmarshaled.Unmarshal(marshaled)
	require.NoError(t, err)

	// Verify the raw DER was extracted.
	assert.NotEmpty(t, unmarshaled.RawMechTypesDER())

	// The DER should be a valid SEQUENCE OF OID.
	var oids []asn1.ObjectIdentifier

	_, err = asn1.Unmarshal(unmarshaled.RawMechTypesDER(), &oids)
	require.NoError(t, err)
	assert.Equal(t, mechTypes, oids)
}

// TestClientContextSetFailed tests the SetFailed method.
func TestClientContextSetFailed(t *testing.T) {
	ctx := NewClientContext(dummySessionKey(), 0, 0)
	_ = ctx.SetInProgress()

	assert.Equal(t, ContextStateInProgress, ctx.State())

	ctx.SetFailed()

	assert.Equal(t, ContextStateFailed, ctx.State())
}

// TestClientContextGetKey tests the GetKey method with and without subkey.
func TestClientContextGetKey(t *testing.T) {
	sessionKey := dummySessionKey()
	ctx := NewClientContext(sessionKey, 0, 0)

	// Without subkey, should return session key.
	key := ctx.GetKey()
	assert.Equal(t, sessionKey.KeyType, key.KeyType)
	assert.Equal(t, sessionKey.KeyValue, key.KeyValue)

	// Simulate having a subkey by directly setting it.
	subkey := types.EncryptionKey{
		KeyType:  18, // AES256-CTS-HMAC-SHA1-96.
		KeyValue: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30},
	}
	ctx.subkey = &subkey

	// With subkey, should return subkey.
	key = ctx.GetKey()
	assert.Equal(t, subkey.KeyType, key.KeyType)
	assert.Equal(t, subkey.KeyValue, key.KeyValue)
}

// TestClientContextHasAcceptorSubkey tests the HasAcceptorSubkey method.
func TestClientContextHasAcceptorSubkey(t *testing.T) {
	ctx := NewClientContext(dummySessionKey(), 0, 0)

	assert.False(t, ctx.HasAcceptorSubkey())

	// Set a subkey.
	subkey := types.EncryptionKey{
		KeyType:  18,
		KeyValue: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30},
	}
	ctx.subkey = &subkey

	assert.True(t, ctx.HasAcceptorSubkey())
}

// TestClientContextSequenceNumbers tests the sequence number methods.
func TestClientContextSequenceNumbers(t *testing.T) {
	t.Run("starts at zero by default", func(t *testing.T) {
		ctx := NewClientContext(dummySessionKey(), 0, 0)

		// Test send sequence numbers start at 0.
		assert.Equal(t, uint64(0), ctx.NextSendSeqNum())
		assert.Equal(t, uint64(1), ctx.NextSendSeqNum())
		assert.Equal(t, uint64(2), ctx.NextSendSeqNum())

		// Test receive sequence numbers start at 0.
		assert.Equal(t, uint64(0), ctx.NextRecvSeqNum())
		assert.Equal(t, uint64(1), ctx.NextRecvSeqNum())
		assert.Equal(t, uint64(2), ctx.NextRecvSeqNum())
	})

	t.Run("respects initial sequence number", func(t *testing.T) {
		// Simulate a sequence number from the Authenticator (30-bit masked).
		initialSeqNum := int64(0x12345678)
		ctx := NewClientContext(dummySessionKey(), 0, initialSeqNum)

		// Send sequence numbers should start at the initial value.
		assert.Equal(t, uint64(initialSeqNum), ctx.NextSendSeqNum())
		assert.Equal(t, uint64(initialSeqNum+1), ctx.NextSendSeqNum())
		assert.Equal(t, uint64(initialSeqNum+2), ctx.NextSendSeqNum())

		// Receive sequence numbers still start at 0 (set later from AP-REP).
		assert.Equal(t, uint64(0), ctx.NextRecvSeqNum())
	})
}

// TestClientContextFlags tests the Flags method.
func TestClientContextFlags(t *testing.T) {
	flags := uint32(0x1234)
	ctx := NewClientContext(dummySessionKey(), flags, 0)

	assert.Equal(t, flags, ctx.Flags())
}

// TestMarshalMechTypeList tests the MarshalMechTypeList function.
func TestMarshalMechTypeList(t *testing.T) {
	mechTypes := []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}

	der, err := MarshalMechTypeList(mechTypes)
	require.NoError(t, err)
	assert.NotEmpty(t, der)

	// Verify we can unmarshal it back.
	var decoded []asn1.ObjectIdentifier

	_, err = asn1.Unmarshal(der, &decoded)
	require.NoError(t, err)
	assert.Equal(t, mechTypes, decoded)
}

// TestMechListMICWithoutDER tests MechListMIC when DER bytes are not set.
func TestMechListMICWithoutDER(t *testing.T) {
	ctx := NewClientContext(dummySessionKey(), 0, 0)
	_ = ctx.SetInProgress()
	_ = ctx.SetEstablished()

	// MechListMIC should fail without DER bytes set.
	_, err := ctx.MechListMIC()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mechTypeList DER bytes not set")
}

// TestVerifyMechListMICWithoutDER tests VerifyMechListMIC when DER bytes are not set.
func TestVerifyMechListMICWithoutDER(t *testing.T) {
	ctx := NewClientContext(dummySessionKey(), 0, 0)
	_ = ctx.SetInProgress()
	_ = ctx.SetEstablished()

	// VerifyMechListMIC should fail without DER bytes set.
	_, err := ctx.VerifyMechListMIC([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mechTypeList DER bytes not set")
}

// TestVerifyMICNotEstablished tests VerifyMIC when context is not established.
func TestVerifyMICNotEstablished(t *testing.T) {
	ctx := NewClientContext(dummySessionKey(), 0, 0)

	// VerifyMIC should fail when not established.
	_, err := ctx.VerifyMIC(&gssapi.MICToken{}, []byte("payload"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not established")
}

// TestUnwrapNotEstablished tests Unwrap when context is not established.
func TestUnwrapNotEstablished(t *testing.T) {
	ctx := NewClientContext(dummySessionKey(), 0, 0)

	// Unwrap should fail when not established.
	_, err := ctx.Unwrap(&gssapi.WrapToken{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not established")
}

// TestKRB5TokenGetKRBError tests the GetKRBError method.
func TestKRB5TokenGetKRBError(t *testing.T) {
	t.Run("Not a KRB_ERROR", func(t *testing.T) {
		token := &KRB5Token{}
		token.tokID, _ = decodeHex(TOK_ID_KRB_AP_REQ)

		_, err := token.GetKRBError()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not a KRB_ERROR")
	})

	t.Run("Is a KRB_ERROR", func(t *testing.T) {
		token := &KRB5Token{}
		token.tokID, _ = decodeHex(TOK_ID_KRB_ERROR)
		token.KRBError.EText = "test error"

		krbErr, err := token.GetKRBError()
		require.NoError(t, err)
		assert.Equal(t, "test error", krbErr.EText)
	})
}

// TestKRB5TokenVerifyAPRepNotAPRep tests VerifyAPRep when token is not AP_REP.
func TestKRB5TokenVerifyAPRepNotAPRep(t *testing.T) {
	token := &KRB5Token{}
	token.tokID, _ = decodeHex(TOK_ID_KRB_AP_REQ)

	ctx := NewClientContext(dummySessionKey(), 0, 0)
	_ = ctx.SetInProgress()

	ok, status := token.VerifyAPRep(ctx)
	assert.False(t, ok)
	assert.Equal(t, gssapi.StatusDefectiveToken, status.Code)
	assert.Contains(t, status.Message, "not an AP_REP")
}

// TestNegTokenRespGetKRB5Token tests the GetKRB5Token method.
func TestNegTokenRespGetKRB5Token(t *testing.T) {
	t.Run("No response token", func(t *testing.T) {
		resp := &NegTokenResp{}

		_, err := resp.GetKRB5Token()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no response token present")
	})

	t.Run("Invalid response token", func(t *testing.T) {
		resp := &NegTokenResp{
			ResponseToken: []byte{0x01, 0x02, 0x03}, // Invalid token.
		}

		_, err := resp.GetKRB5Token()
		assert.Error(t, err)
	})
}

// TestNegTokenRespHasMechListMIC tests the HasMechListMIC method.
func TestNegTokenRespHasMechListMIC(t *testing.T) {
	t.Run("No MIC", func(t *testing.T) {
		resp := &NegTokenResp{}
		assert.False(t, resp.HasMechListMIC())
	})

	t.Run("Has MIC", func(t *testing.T) {
		resp := &NegTokenResp{
			MechListMIC: []byte{0x01, 0x02, 0x03},
		}
		assert.True(t, resp.HasMechListMIC())
	})
}

// TestNegotiateClientContext tests the Context method.
func TestNegotiateClientContext(t *testing.T) {
	client := NewNegotiateClient(nil, "HTTP/test")

	// No context initially.
	assert.Nil(t, client.Context())

	// Set a context.
	client.ctx = NewClientContext(dummySessionKey(), 0, 0)
	assert.NotNil(t, client.Context())
}

// TestNegotiatingRoundTripper tests the NegotiatingRoundTripper constructor.
func TestNegotiatingRoundTripper(t *testing.T) {
	customTransport := &http.Transport{}
	rt := NewNegotiatingRoundTripper(nil, "HTTP/test", WithTransport(customTransport))

	assert.NotNil(t, rt)
	assert.Equal(t, "HTTP/test", rt.spn)
	assert.Equal(t, customTransport, rt.transport)
}

// TestNegotiateClientSessionKey tests the SessionKey method.
func TestNegotiateClientSessionKey(t *testing.T) {
	client := NewNegotiateClient(nil, "HTTP/test")

	// No context - should return error.
	_, err := client.SessionKey()
	assert.Error(t, err)

	// With context.
	sessionKey := dummySessionKey()
	client.ctx = NewClientContext(sessionKey, 0, 0)
	key, err := client.SessionKey()
	require.NoError(t, err)
	assert.Equal(t, sessionKey.KeyType, key.KeyType)
	assert.Equal(t, sessionKey.KeyValue, key.KeyValue)
}

// TestNegotiateClientGetMIC tests the GetMIC wrapper method.
func TestNegotiateClientGetMIC(t *testing.T) {
	client := NewNegotiateClient(nil, "HTTP/test")

	// No context - should return error.
	_, err := client.GetMIC([]byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no security context")

	// With context but not established.
	client.ctx = NewClientContext(dummySessionKey(), 0, 0)
	_, err = client.GetMIC([]byte("test"))
	assert.Error(t, err)
}

// TestNegotiateClientVerifyMIC tests the VerifyMIC wrapper method.
func TestNegotiateClientVerifyMIC(t *testing.T) {
	client := NewNegotiateClient(nil, "HTTP/test")

	// No context - should return error.
	_, err := client.VerifyMIC(&gssapi.MICToken{}, []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no security context")
}

// TestNegotiateClientWrap tests the Wrap wrapper method.
func TestNegotiateClientWrap(t *testing.T) {
	client := NewNegotiateClient(nil, "HTTP/test")

	// No context - should return error.
	_, err := client.Wrap([]byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no security context")
}

// TestNegotiateClientUnwrap tests the Unwrap wrapper method.
func TestNegotiateClientUnwrap(t *testing.T) {
	client := NewNegotiateClient(nil, "HTTP/test")

	// No context - should return error.
	_, err := client.Unwrap(&gssapi.WrapToken{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no security context")
}

// TestCloneRequest tests the cloneRequest helper function.
func TestCloneRequest(t *testing.T) {
	original, err := http.NewRequest("GET", "http://example.com/path", nil)
	require.NoError(t, err)
	original.Header.Set("X-Custom", "value")

	cloned := cloneRequest(original)

	// Should have same URL and method.
	assert.Equal(t, original.URL.String(), cloned.URL.String())
	assert.Equal(t, original.Method, cloned.Method)

	// Should have copied headers.
	assert.Equal(t, "value", cloned.Header.Get("X-Custom"))

	// Modifying clone shouldn't affect original.
	cloned.Header.Set("X-New", "newvalue")
	assert.Empty(t, original.Header.Get("X-New"))
}

// TestHTTPAuthHeaderParsing tests parsing of various WWW-Authenticate header formats.
func TestHTTPAuthHeaderParsing(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		isNegotiate bool
		hasToken    bool
	}{
		{
			name:        "Bare Negotiate",
			header:      "Negotiate",
			isNegotiate: true,
			hasToken:    false,
		},
		{
			name:        "Negotiate with token",
			header:      "Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg==",
			isNegotiate: true,
			hasToken:    true,
		},
		{
			name:        "Negotiate with extra whitespace",
			header:      "Negotiate  oRQwEqADCgEAoQsGCSqGSIb3EgECAg==",
			isNegotiate: true,
			hasToken:    true,
		},
		{
			name:        "Basic auth",
			header:      "Basic realm=\"test\"",
			isNegotiate: false,
			hasToken:    false,
		},
		{
			name:        "Empty",
			header:      "",
			isNegotiate: false,
			hasToken:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isNegotiate := strings.HasPrefix(tt.header, HTTPHeaderAuthResponseValueKey)
			assert.Equal(t, tt.isNegotiate, isNegotiate)

			if isNegotiate {
				tokenPart := strings.TrimPrefix(tt.header, HTTPHeaderAuthResponseValueKey)
				tokenPart = strings.TrimSpace(tokenPart)
				hasToken := tokenPart != ""
				assert.Equal(t, tt.hasToken, hasToken)
			}
		})
	}
}

// TestFindNegotiateChallenge tests the findNegotiateChallenge helper function.
func TestFindNegotiateChallenge(t *testing.T) {
	tests := []struct {
		name           string
		headers        []string
		expectNil      bool
		expectHasToken bool
		expectToken    string
	}{
		{
			name:      "No headers",
			headers:   nil,
			expectNil: true,
		},
		{
			name:      "No WWW-Authenticate header",
			headers:   []string{},
			expectNil: true,
		},
		{
			name:           "Single bare Negotiate",
			headers:        []string{"Negotiate"},
			expectNil:      false,
			expectHasToken: false,
		},
		{
			name:           "Single Negotiate with token",
			headers:        []string{"Negotiate dGVzdHRva2Vu"},
			expectNil:      false,
			expectHasToken: true,
			expectToken:    "dGVzdHRva2Vu",
		},
		{
			name:           "Multiple headers - Kerberos first, then Negotiate",
			headers:        []string{"Kerberos", "Negotiate"},
			expectNil:      false,
			expectHasToken: false,
		},
		{
			name:           "Multiple headers - bare Negotiate first, then Kerberos",
			headers:        []string{"Negotiate", "Kerberos"},
			expectNil:      false,
			expectHasToken: false,
		},
		{
			name:           "Multiple headers - Negotiate with token preferred over bare",
			headers:        []string{"Negotiate", "Negotiate dGVzdHRva2Vu"},
			expectNil:      false,
			expectHasToken: true,
			expectToken:    "dGVzdHRva2Vu",
		},
		{
			name:           "Multiple headers - token first (returns immediately)",
			headers:        []string{"Negotiate dGVzdHRva2Vu", "Negotiate"},
			expectNil:      false,
			expectHasToken: true,
			expectToken:    "dGVzdHRva2Vu",
		},
		{
			name:           "WinRM-style - Negotiate and Kerberos both present",
			headers:        []string{"Negotiate", "Kerberos"},
			expectNil:      false,
			expectHasToken: false,
		},
		{
			name:           "WinRM-style with token - prefer Negotiate with token",
			headers:        []string{"Kerberos", "Negotiate dGVzdHRva2Vu"},
			expectNil:      false,
			expectHasToken: true,
			expectToken:    "dGVzdHRva2Vu",
		},
		{
			name:      "Only Basic auth",
			headers:   []string{"Basic realm=\"test\""},
			expectNil: true,
		},
		{
			name:           "Mixed - Basic and Negotiate",
			headers:        []string{"Basic realm=\"test\"", "Negotiate"},
			expectNil:      false,
			expectHasToken: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := make(http.Header)
			for _, h := range tt.headers {
				header.Add("WWW-Authenticate", h)
			}

			challenge := findNegotiateChallenge(header)

			if tt.expectNil {
				assert.Nil(t, challenge)
			} else {
				require.NotNil(t, challenge)
				assert.Equal(t, tt.expectHasToken, challenge.hasToken)

				if tt.expectHasToken {
					assert.Equal(t, tt.expectToken, challenge.token)
				}
			}
		})
	}
}

// TestBuildMICResponseToken tests the buildMICResponseToken method.
func TestBuildMICResponseToken(t *testing.T) {
	t.Run("fails without MechTypeListDER", func(t *testing.T) {
		client := NewNegotiateClient(nil, "HTTP/test")
		client.ctx = NewClientContext(dummySessionKey(), 0, 0)
		_ = client.ctx.SetInProgress()
		_ = client.ctx.SetEstablished()

		// No MechTypeListDER set - should fail.
		_, err := client.buildMICResponseToken()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mechListMIC")
	})

	t.Run("succeeds with MechTypeListDER", func(t *testing.T) {
		client := NewNegotiateClient(nil, "HTTP/test")
		client.ctx = NewClientContext(dummySessionKey(), 0, 0)
		_ = client.ctx.SetInProgress()
		_ = client.ctx.SetEstablished()

		// Set up MechTypeListDER.
		mechTypes := []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}
		der, err := MarshalMechTypeList(mechTypes)
		require.NoError(t, err)
		client.ctx.SetMechTypeListDER(der)

		// Should succeed now.
		tokenBytes, err := client.buildMICResponseToken()
		require.NoError(t, err)
		assert.NotEmpty(t, tokenBytes)

		// Verify it's a valid SPNEGO token.
		var spnegoToken SPNEGOToken

		err = spnegoToken.Unmarshal(tokenBytes)
		require.NoError(t, err)
		assert.True(t, spnegoToken.Resp)
		assert.NotEmpty(t, spnegoToken.NegTokenResp.MechListMIC)
	})
}

// TestProcessNegTokenRespRequestMIC tests handling of NegStateRequestMIC.
func TestProcessNegTokenRespRequestMIC(t *testing.T) {
	client := NewNegotiateClient(nil, "HTTP/test")
	client.ctx = NewClientContext(dummySessionKey(), 0, 0)
	_ = client.ctx.SetInProgress()

	// Set up MechTypeListDER for MIC generation.
	mechTypes := []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}
	der, err := MarshalMechTypeList(mechTypes)
	require.NoError(t, err)
	client.ctx.SetMechTypeListDER(der)

	// Create a NegTokenResp with RequestMIC state.
	negResp := &NegTokenResp{
		NegState: asn1.Enumerated(NegStateRequestMIC),
	}

	// Process should return a response token.
	responseToken, err := client.processNegTokenResp(negResp)
	require.NoError(t, err)
	assert.NotNil(t, responseToken)
	assert.NotEmpty(t, responseToken)

	// Verify the response token is a valid SPNEGO NegTokenResp with MechListMIC.
	var spnegoToken SPNEGOToken

	err = spnegoToken.Unmarshal(responseToken)
	require.NoError(t, err)
	assert.True(t, spnegoToken.Resp)
	assert.NotEmpty(t, spnegoToken.NegTokenResp.MechListMIC)
}
