package spnego

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/types"
)

// NegotiateClient is a stateful HTTP client that handles multi-leg SPNEGO authentication.
// It implements the client-side SPNEGO state machine per RFC 4178.
type NegotiateClient struct {
	// krb5Client is the underlying Kerberos client.
	krb5Client *client.Client

	// spn is the service principal name for the target service.
	spn string

	// transport is the underlying HTTP transport.
	transport http.RoundTripper

	// mu protects the context and state.
	mu sync.Mutex

	// ctx is the security context for the current negotiation.
	ctx *ClientContext

	// negTokenInit stores the initial NegTokenInit for mechListMIC verification.
	negTokenInit *NegTokenInit

	// mutualAuth indicates whether mutual authentication is required.
	mutualAuth bool
}

// NegotiateClientOption is a function that configures a NegotiateClient.
type NegotiateClientOption func(*NegotiateClient)

// WithTransport sets the underlying HTTP transport.
func WithTransport(t http.RoundTripper) NegotiateClientOption {
	return func(c *NegotiateClient) {
		c.transport = t
	}
}

// WithMutualAuth enables mutual authentication requirement.
func WithMutualAuth(enabled bool) NegotiateClientOption {
	return func(c *NegotiateClient) {
		c.mutualAuth = enabled
	}
}

// NewNegotiateClient creates a new NegotiateClient for multi-leg SPNEGO authentication.
func NewNegotiateClient(krb5Client *client.Client, spn string, opts ...NegotiateClientOption) *NegotiateClient {
	c := &NegotiateClient{
		krb5Client: krb5Client,
		spn:        spn,
		transport:  http.DefaultTransport,
		mutualAuth: true, // Default to requiring mutual auth for security.
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// RoundTrip implements http.RoundTripper and handles the SPNEGO state machine.
func (c *NegotiateClient) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Make the initial request.
	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Check if we need to authenticate.
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// Check for WWW-Authenticate: Negotiate header(s).
	// HTTP allows multiple WWW-Authenticate headers (e.g., Negotiate and Kerberos).
	challenge := findNegotiateChallenge(resp.Header)
	if challenge == nil {
		return resp, nil
	}

	// Drain and close the response body to reuse the connection.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if !challenge.hasToken {
		// Bare Negotiate header - start authentication.
		return c.handleInitialChallenge(req)
	}

	// Handle "Negotiate <token>" - process server response.
	return c.handleServerToken(req, challenge.token)
}

// handleInitialChallenge processes the initial 401 with bare "Negotiate" header.
func (c *NegotiateClient) handleInitialChallenge(req *http.Request) (*http.Response, error) {
	// Ensure we have a valid TGT.
	if err := c.krb5Client.AffirmLogin(); err != nil {
		return nil, fmt.Errorf("failed to affirm login: %w", err)
	}

	// Get service ticket.
	tkt, sessionKey, err := c.krb5Client.GetServiceTicket(c.spn)
	if err != nil {
		return nil, fmt.Errorf("failed to get service ticket: %w", err)
	}

	// Build GSSAPI flags.
	gssFlags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}
	if c.mutualAuth {
		gssFlags = append(gssFlags, gssapi.ContextFlagMutual)
	}

	// Build AP options.
	apOptions := []int{}
	if c.mutualAuth {
		apOptions = append(apOptions, flags.APOptionMutualRequired)
	}

	// Create NegTokenInit.
	negTokenInit, err := NewNegTokenInitKRB5WithFlags(c.krb5Client, tkt, sessionKey, gssFlags, apOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create NegTokenInit: %w", err)
	}

	// Store the NegTokenInit for later mechListMIC verification.
	c.negTokenInit = &negTokenInit

	// Create security context.
	flagsUint := uint32(0)
	for _, f := range gssFlags {
		flagsUint |= uint32(f)
	}

	c.ctx = NewClientContext(sessionKey, flagsUint, negTokenInit.InitialSeqNum())

	// Store the raw MechTypes DER for MIC computation.
	c.ctx.SetMechTypeListDER(negTokenInit.RawMechTypesDER())
	c.ctx.SetMutualAuthRequired(c.mutualAuth)

	// Transition context to InProgress.
	if err := c.ctx.SetInProgress(); err != nil {
		return nil, fmt.Errorf("failed to set context in progress: %w", err)
	}

	// Marshal and encode the token.
	spnegoToken := &SPNEGOToken{
		Init:         true,
		NegTokenInit: negTokenInit,
	}

	tokenBytes, err := spnegoToken.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPNEGO token: %w", err)
	}

	// Clone the request and add the Authorization header.
	newReq := cloneRequest(req)
	newReq.Header.Set(HTTPHeaderAuthRequest, HTTPHeaderAuthResponseValueKey+" "+base64.StdEncoding.EncodeToString(tokenBytes))

	// Send the request with the token.
	resp, err := c.transport.RoundTrip(newReq)
	if err != nil {
		c.ctx.SetFailed()
		return nil, err
	}

	// Check if we got a success (2xx) or another challenge (401).
	if resp.StatusCode == http.StatusUnauthorized {
		// Check for another Negotiate challenge with a token.
		challenge := findNegotiateChallenge(resp.Header)
		if challenge != nil && challenge.hasToken {
			// Drain and close response body.
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			// Process server's response token.
			return c.handleServerToken(newReq, challenge.token)
		}
	}

	// Check for success with potential final token.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return c.handleSuccessResponse(resp)
	}

	return resp, nil
}

// handleServerToken processes a server's NegTokenResp.
func (c *NegotiateClient) handleServerToken(req *http.Request, tokenB64 string) (*http.Response, error) {
	if c.ctx == nil {
		return nil, errors.New("received server token without active context")
	}

	negResp, err := c.decodeNegTokenResp(tokenB64)
	if err != nil {
		return nil, err
	}

	responseToken, err := c.processNegTokenResp(negResp)
	if err != nil {
		return nil, err
	}

	return c.sendFinalRequest(req, responseToken)
}

// decodeNegTokenResp decodes a base64 token and returns the NegTokenResp.
func (c *NegotiateClient) decodeNegTokenResp(tokenB64 string) (*NegTokenResp, error) {
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		c.ctx.SetFailed()
		return nil, fmt.Errorf("failed to decode server token: %w", err)
	}

	var spnegoToken SPNEGOToken
	if err := spnegoToken.Unmarshal(tokenBytes); err != nil {
		c.ctx.SetFailed()
		return nil, fmt.Errorf("failed to unmarshal server token: %w", err)
	}

	if !spnegoToken.Resp {
		c.ctx.SetFailed()
		return nil, errors.New("expected NegTokenResp from server")
	}

	return &spnegoToken.NegTokenResp, nil
}

// processNegTokenResp processes the negotiation response state and tokens.
// Returns a client response token (may be nil) to send back to the server.
func (c *NegotiateClient) processNegTokenResp(negResp *NegTokenResp) ([]byte, error) {
	switch negResp.State() {
	case NegStateReject:
		c.ctx.SetFailed()
		return nil, errors.New("server rejected authentication")

	case NegStateAcceptCompleted, NegStateAcceptIncomplete:
		if err := c.verifyResponseToken(negResp); err != nil {
			return nil, err
		}

		if err := c.verifyMechListMIC(negResp); err != nil {
			return nil, err
		}

		if negResp.State() == NegStateAcceptCompleted {
			if err := c.ctx.SetEstablished(); err != nil {
				c.ctx.SetFailed()
				return nil, fmt.Errorf("failed to establish context: %w", err)
			}
		}

	case NegStateRequestMIC:
		// Server requested mechListMIC - generate and return a response token.
		if err := c.verifyResponseToken(negResp); err != nil {
			return nil, err
		}

		responseToken, err := c.buildMICResponseToken()
		if err != nil {
			c.ctx.SetFailed()
			return nil, fmt.Errorf("failed to build MIC response: %w", err)
		}

		return responseToken, nil
	}

	return nil, nil
}

// buildMICResponseToken creates a NegTokenResp containing only the mechListMIC.
// This is sent in response to NegStateRequestMIC from the server.
func (c *NegotiateClient) buildMICResponseToken() ([]byte, error) {
	mic, err := c.ctx.MechListMIC()
	if err != nil {
		return nil, fmt.Errorf("failed to generate mechListMIC: %w", err)
	}

	// Build a NegTokenResp with just the mechListMIC.
	clientResp := NegTokenResp{
		MechListMIC: mic,
	}

	// Wrap in SPNEGOToken for marshaling.
	spnegoToken := &SPNEGOToken{
		Resp:         true,
		NegTokenResp: clientResp,
	}

	tokenBytes, err := spnegoToken.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response token: %w", err)
	}

	return tokenBytes, nil
}

// verifyResponseToken verifies the KRB5 token in the response.
func (c *NegotiateClient) verifyResponseToken(negResp *NegTokenResp) error {
	if len(negResp.ResponseToken) == 0 {
		return nil
	}

	krb5Token, err := negResp.GetKRB5Token()
	if err != nil {
		c.ctx.SetFailed()
		return fmt.Errorf("failed to get KRB5 token: %w", err)
	}

	if krb5Token.IsAPRep() {
		ok, status := krb5Token.VerifyAPRep(c.ctx)
		if !ok {
			c.ctx.SetFailed()
			return fmt.Errorf("failed to verify AP-REP: %s", status.Message)
		}
	} else if krb5Token.IsKRBError() {
		c.ctx.SetFailed()

		krbErr, err := krb5Token.GetKRBError()
		if err != nil || krbErr == nil {
			if err == nil {
				err = errors.New("missing KRB_ERROR payload")
			}
			return fmt.Errorf("server returned KRB_ERROR: %w", err)
		}

		return fmt.Errorf("server returned KRB_ERROR: %s", krbErr.EText)
	}

	return nil
}

// verifyMechListMIC verifies the mechListMIC if present.
func (c *NegotiateClient) verifyMechListMIC(negResp *NegTokenResp) error {
	if !negResp.HasMechListMIC() {
		return nil
	}

	ok, err := c.ctx.VerifyMechListMIC(negResp.MechListMIC)
	if err != nil {
		c.ctx.SetFailed()
		return fmt.Errorf("failed to verify mechListMIC: %w", err)
	}

	if !ok {
		c.ctx.SetFailed()
		return errors.New("mechListMIC verification failed")
	}

	return nil
}

// sendFinalRequest sends the final request after processing the server token.
// If responseToken is non-nil, it is included in the Authorization header.
func (c *NegotiateClient) sendFinalRequest(req *http.Request, responseToken []byte) (*http.Response, error) {
	newReq := cloneRequest(req)

	// Include response token in Authorization header if provided.
	if len(responseToken) > 0 {
		newReq.Header.Set(HTTPHeaderAuthRequest, HTTPHeaderAuthResponseValueKey+" "+base64.StdEncoding.EncodeToString(responseToken))
	}

	resp, err := c.transport.RoundTrip(newReq)
	if err != nil {
		c.ctx.SetFailed()
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return c.handleSuccessResponse(resp)
	}

	return resp, nil
}

// handleSuccessResponse processes a successful response, potentially with a final token.
func (c *NegotiateClient) handleSuccessResponse(resp *http.Response) (*http.Response, error) {
	if err := c.processFinalAuthToken(resp); err != nil {
		if resp.Body != nil {
			resp.Body.Close()
		}
		return nil, err
	}

	// Mark context as established if it's still in progress.
	if c.ctx != nil && c.ctx.State() == ContextStateInProgress {
		if err := c.ctx.SetEstablished(); err != nil {
			// Log but don't fail - we got a success response.
			c.ctx.SetFailed()
		}
	}

	return resp, nil
}

// processFinalAuthToken processes a final Negotiate token in the response header.
func (c *NegotiateClient) processFinalAuthToken(resp *http.Response) error {
	challenge := findNegotiateChallenge(resp.Header)
	if challenge == nil || !challenge.hasToken {
		return nil
	}

	if c.ctx == nil || c.ctx.State() != ContextStateInProgress {
		return nil
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(challenge.token)
	if err != nil {
		c.ctx.SetFailed()
		return fmt.Errorf("failed to decode final token: %w", err)
	}

	var spnegoToken SPNEGOToken
	if err := spnegoToken.Unmarshal(tokenBytes); err != nil {
		c.ctx.SetFailed()
		return fmt.Errorf("failed to unmarshal final token: %w", err)
	}

	if !spnegoToken.Resp {
		return nil
	}

	return c.verifyFinalNegTokenResp(&spnegoToken.NegTokenResp)
}

// verifyFinalNegTokenResp verifies the final NegTokenResp from a success response.
func (c *NegotiateClient) verifyFinalNegTokenResp(negResp *NegTokenResp) error {
	if len(negResp.ResponseToken) > 0 {
		krb5Token, err := negResp.GetKRB5Token()
		if err != nil {
			c.ctx.SetFailed()
			return fmt.Errorf("failed to get final KRB5 token: %w", err)
		}

		if krb5Token.IsAPRep() {
			ok, status := krb5Token.VerifyAPRep(c.ctx)
			if !ok {
				c.ctx.SetFailed()
				return fmt.Errorf("failed to verify final AP-REP: %s", status.Message)
			}
		}
	}

	if negResp.HasMechListMIC() {
		ok, err := c.ctx.VerifyMechListMIC(negResp.MechListMIC)
		if err != nil {
			c.ctx.SetFailed()
			return fmt.Errorf("failed to verify final mechListMIC: %w", err)
		}

		if !ok {
			c.ctx.SetFailed()
			return errors.New("final mechListMIC verification failed")
		}
	}

	return nil
}

// Context returns the security context if established.
func (c *NegotiateClient) Context() *ClientContext {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.ctx
}

// IsEstablished returns true if the security context is established.
func (c *NegotiateClient) IsEstablished() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.ctx != nil && c.ctx.IsEstablished()
}

// Reset clears the current context, allowing a fresh authentication.
func (c *NegotiateClient) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ctx = nil
	c.negTokenInit = nil
}

// cloneRequest creates a shallow copy of a request for retry purposes.
func cloneRequest(req *http.Request) *http.Request {
	newReq := req.Clone(req.Context())
	if req.Body != nil {
		// Note: Body reuse is handled by the caller setting GetBody on the original request.
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err == nil {
				newReq.Body = body
			}
		}
	}

	return newReq
}

// negotiateChallenge represents a parsed Negotiate challenge from WWW-Authenticate.
type negotiateChallenge struct {
	// hasToken indicates whether the challenge includes a token.
	hasToken bool
	// token is the base64-encoded token (empty if hasToken is false).
	token string
}

// findNegotiateChallenge searches through all WWW-Authenticate headers to find
// the best Negotiate challenge. It prefers "Negotiate <token>" over bare "Negotiate".
// Returns nil if no Negotiate challenge is found.
func findNegotiateChallenge(headers http.Header) *negotiateChallenge {
	values := headers.Values(HTTPHeaderAuthResponse)
	if len(values) == 0 {
		return nil
	}

	var bareNegotiate *negotiateChallenge

	for _, value := range values {
		if !strings.HasPrefix(value, HTTPHeaderAuthResponseValueKey) {
			continue
		}

		token := strings.TrimPrefix(value, HTTPHeaderAuthResponseValueKey)
		token = strings.TrimSpace(token)

		if token != "" {
			// Prefer "Negotiate <token>" - return immediately.
			return &negotiateChallenge{hasToken: true, token: token}
		}

		// Remember bare "Negotiate" in case we don't find one with a token.
		if bareNegotiate == nil {
			bareNegotiate = &negotiateChallenge{hasToken: false, token: ""}
		}
	}

	return bareNegotiate
}

// NegotiatingRoundTripper is an http.RoundTripper that handles SPNEGO authentication.
// It is an alias for NegotiateClient to match the naming in the requirements.
type NegotiatingRoundTripper = NegotiateClient

// NewNegotiatingRoundTripper creates a new NegotiatingRoundTripper.
// This is an alias for NewNegotiateClient.
func NewNegotiatingRoundTripper(krb5Client *client.Client, spn string, opts ...NegotiateClientOption) *NegotiatingRoundTripper {
	return NewNegotiateClient(krb5Client, spn, opts...)
}

// GetMIC creates a MIC token for message integrity.
// Returns an error if the context is not established.
func (c *NegotiateClient) GetMIC(payload []byte) (*gssapi.MICToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx == nil {
		return nil, errors.New("no security context")
	}

	return c.ctx.GetMIC(payload)
}

// VerifyMIC verifies a MIC token.
// Returns an error if the context is not established.
func (c *NegotiateClient) VerifyMIC(token *gssapi.MICToken, payload []byte) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx == nil {
		return false, errors.New("no security context")
	}

	return c.ctx.VerifyMIC(token, payload)
}

// Wrap encrypts and signs the payload.
// Returns an error if the context is not established.
func (c *NegotiateClient) Wrap(payload []byte) (*gssapi.WrapToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx == nil {
		return nil, errors.New("no security context")
	}

	return c.ctx.Wrap(payload)
}

// Unwrap verifies a sign-only wrapped payload and returns the plaintext.
// Returns an error if the context is not established.
// For encrypted (sealed) tokens, use UnwrapSealed or UnwrapAuto instead.
func (c *NegotiateClient) Unwrap(token *gssapi.WrapToken) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx == nil {
		return nil, errors.New("no security context")
	}

	return c.ctx.Unwrap(token)
}

// WrapSealed creates an encrypted (sealed) wrap token for the given payload.
// This provides confidentiality in addition to integrity per RFC 4121.
// Returns an error if the context is not established.
func (c *NegotiateClient) WrapSealed(payload []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx == nil {
		return nil, errors.New("no security context")
	}

	return c.ctx.WrapSealed(payload)
}

// UnwrapSealed decrypts a sealed wrap token and returns the plaintext.
// Returns an error if the context is not established.
func (c *NegotiateClient) UnwrapSealed(tokenBytes []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx == nil {
		return nil, errors.New("no security context")
	}

	return c.ctx.UnwrapSealed(tokenBytes)
}

// UnwrapAuto automatically detects whether a token is sealed or sign-only and processes it.
// This provides a unified API similar to SSPI's DecryptMessage.
// Returns an error if the context is not established.
func (c *NegotiateClient) UnwrapAuto(tokenBytes []byte) (*gssapi.UnwrapResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx == nil {
		return nil, errors.New("no security context")
	}

	return c.ctx.UnwrapAuto(tokenBytes)
}

// SessionKey returns the session key from the security context.
// This is useful for protocols that need the raw key (like WinRM).
func (c *NegotiateClient) SessionKey() (types.EncryptionKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx == nil {
		return types.EncryptionKey{}, errors.New("no security context")
	}

	return c.ctx.GetKey(), nil
}
