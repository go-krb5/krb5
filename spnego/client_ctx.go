package spnego

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// ContextState represents the state of a SPNEGO security context.
type ContextState int

const (
	// ContextStateInitial indicates the context has not yet been initialized.
	ContextStateInitial ContextState = iota
	// ContextStateInProgress indicates the context establishment is in progress.
	ContextStateInProgress
	// ContextStateEstablished indicates the context has been fully established.
	ContextStateEstablished
	// ContextStateFailed indicates the context establishment failed.
	ContextStateFailed
)

// String returns a human-readable representation of the context state.
func (s ContextState) String() string {
	switch s {
	case ContextStateInitial:
		return "Initial"
	case ContextStateInProgress:
		return "InProgress"
	case ContextStateEstablished:
		return "Established"
	case ContextStateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// ClientContext represents a client-side SPNEGO/GSS-API security context.
// It tracks the state machine for multi-leg authentication and provides
// the keys and sequence numbers needed for per-message security (MIC/Wrap).
type ClientContext struct {
	mu sync.RWMutex

	// state tracks the current context establishment state.
	state ContextState

	// flags holds the negotiated GSS-API context flags.
	flags uint32

	// sessionKey is the Kerberos session key from the service ticket.
	sessionKey types.EncryptionKey

	// subkey is the acceptor subkey from AP-REP (if provided).
	// Per RFC 4121, if acceptor provides a subkey, it takes precedence.
	subkey *types.EncryptionKey

	// sendSeqNum is the sequence number for outgoing messages.
	sendSeqNum uint64

	// recvSeqNum is the sequence number for incoming messages.
	recvSeqNum uint64

	// isInitiator indicates this is the initiator (client) side.
	isInitiator bool

	// rawMechTypeListDER stores the raw DER bytes of the initial MechTypeList.
	// This MUST be preserved exactly for mechListMIC computation per RFC 4178.
	rawMechTypeListDER []byte

	// mutualAuthRequired indicates whether mutual authentication was requested.
	mutualAuthRequired bool

	// mutualAuthComplete indicates whether mutual authentication succeeded.
	mutualAuthComplete bool

	// wrapTokenEC controls the EC (filler length) for sealed wrap tokens.
	// - 0: No filler (Windows WinRM mode, RRC=28 for AES-SHA1)
	// - 16: One AES block padding (MS-KILE mode, RRC=44 for AES-SHA1)
	// Default is 0 for maximum compatibility with Windows WinRM.
	wrapTokenEC uint16

	// wrapTokenDCE enables DCE-style token rotation (RFC 4121 Section 4.2.4).
	// This is required for WSMan/PSRP over HTTP.
	wrapTokenDCE bool
}

// NewClientContext creates a new client-side security context.
// The initialSeqNum should be the sequence number from the Authenticator in the AP-REQ.
// Per RFC 4121, this is used as the starting sequence number for outgoing messages.
func NewClientContext(sessionKey types.EncryptionKey, flags uint32, initialSeqNum int64) *ClientContext {
	return &ClientContext{
		state:       ContextStateInitial,
		sessionKey:  sessionKey,
		isInitiator: true,
		flags:       flags,
		sendSeqNum:  uint64(initialSeqNum),
		wrapTokenEC: 0, // Default to EC=0 for Windows WinRM compatibility.
	}
}

// SetWrapTokenEC sets the EC (filler length) for sealed wrap tokens.
// - EC=0: No filler bytes (Windows WinRM mode, default)
// - EC=16: One AES block padding (MS-KILE mode)
func (c *ClientContext) SetWrapTokenEC(ec uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wrapTokenEC = ec
}

// SetWrapTokenDCE enables or disables DCE-style wrap token rotation.
// DCE-style tokens are required for WSMan/PSRP over HTTP.
func (c *ClientContext) SetWrapTokenDCE(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wrapTokenDCE = enabled
}

// State returns the current context state.
func (c *ClientContext) State() ContextState {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.state
}

// IsEstablished returns true if the context is fully established.
func (c *ClientContext) IsEstablished() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.state == ContextStateEstablished
}

// SetMechTypeListDER stores the raw DER bytes of the MechTypeList for MIC computation.
// This MUST be called with the exact bytes from the initial NegTokenInit.
func (c *ClientContext) SetMechTypeListDER(der []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Make a copy to ensure we own the bytes.
	c.rawMechTypeListDER = make([]byte, len(der))
	copy(c.rawMechTypeListDER, der)
}

// MechTypeListDER returns the stored raw DER bytes of the MechTypeList.
func (c *ClientContext) MechTypeListDER() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.rawMechTypeListDER
}

// SetMutualAuthRequired sets whether mutual authentication is required.
func (c *ClientContext) SetMutualAuthRequired(required bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mutualAuthRequired = required
}

// SetInProgress transitions the context to the InProgress state.
func (c *ClientContext) SetInProgress() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != ContextStateInitial && c.state != ContextStateInProgress {
		return fmt.Errorf("cannot transition to InProgress from state %s", c.state)
	}

	c.state = ContextStateInProgress

	return nil
}

// ProcessAPRep processes an AP-REP message from the server, completing mutual authentication.
// It extracts the subkey and sequence number for subsequent per-message operations.
func (c *ClientContext) ProcessAPRep(apRep *messages.APRep) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != ContextStateInProgress {
		return fmt.Errorf("cannot process AP-REP in state %s", c.state)
	}

	// Decrypt the EncAPRepPart using the session key.
	encType, err := crypto.GetEtype(c.sessionKey.KeyType)
	if err != nil {
		c.state = ContextStateFailed
		return fmt.Errorf("error getting encryption type: %w", err)
	}

	decrypted, err := encType.DecryptMessage(c.sessionKey.KeyValue, apRep.EncPart.Cipher, keyusage.AP_REP_ENCPART)
	if err != nil {
		c.state = ContextStateFailed
		return fmt.Errorf("error decrypting AP-REP: %w", err)
	}

	var encPart messages.EncAPRepPart
	if err := encPart.Unmarshal(decrypted); err != nil {
		c.state = ContextStateFailed
		return fmt.Errorf("error unmarshalling EncAPRepPart: %w", err)
	}

	// Store the subkey if provided.
	if encPart.Subkey.KeyType != 0 {
		c.subkey = &encPart.Subkey
	}

	// Store the sequence number if provided.
	if encPart.SequenceNumber != 0 {
		c.recvSeqNum = uint64(encPart.SequenceNumber)
	}

	c.mutualAuthComplete = true

	return nil
}

// SetEstablished transitions the context to the Established state.
// This should only be called after mutual authentication completes (if required).
func (c *ClientContext) SetEstablished() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != ContextStateInProgress {
		return fmt.Errorf("cannot transition to Established from state %s", c.state)
	}

	// If mutual auth was required, verify it completed.
	if c.mutualAuthRequired && !c.mutualAuthComplete {
		return errors.New("mutual authentication required but not completed")
	}

	c.state = ContextStateEstablished

	return nil
}

// SetFailed transitions the context to the Failed state.
func (c *ClientContext) SetFailed() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.state = ContextStateFailed
}

// GetKey returns the key to use for per-message operations.
// Per RFC 4121, if the acceptor provided a subkey, it takes precedence.
func (c *ClientContext) GetKey() types.EncryptionKey {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.subkey != nil {
		return *c.subkey
	}

	return c.sessionKey
}

// HasAcceptorSubkey returns true if the acceptor provided a subkey.
func (c *ClientContext) HasAcceptorSubkey() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.subkey != nil
}

// NextSendSeqNum returns and increments the send sequence number.
func (c *ClientContext) NextSendSeqNum() uint64 {
	return atomic.AddUint64(&c.sendSeqNum, 1) - 1
}

// NextRecvSeqNum returns and increments the receive sequence number.
func (c *ClientContext) NextRecvSeqNum() uint64 {
	return atomic.AddUint64(&c.recvSeqNum, 1) - 1
}

// GetMIC creates a MIC token for the given payload.
// This method gates on context establishment - it will return an error if
// the context is not fully established.
func (c *ClientContext) GetMIC(payload []byte) (*gssapi.MICToken, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.state != ContextStateEstablished {
		return nil, fmt.Errorf("cannot create MIC: context not established (state: %s)", c.state)
	}

	key := c.sessionKey
	if c.subkey != nil {
		key = *c.subkey
	}

	// Determine flags based on role.
	var flags byte
	if !c.isInitiator {
		flags |= gssapi.MICTokenFlagSentByAcceptor
	}

	if c.subkey != nil {
		flags |= gssapi.MICTokenFlagAcceptorSubkey
	}

	token := &gssapi.MICToken{
		Flags:     flags,
		SndSeqNum: c.nextSendSeqNumLocked(),
		Payload:   payload,
	}

	// Initiator uses GSSAPI_INITIATOR_SIGN, acceptor uses GSSAPI_ACCEPTOR_SIGN.
	keyUsage := uint32(keyusage.GSSAPI_INITIATOR_SIGN)
	if !c.isInitiator {
		keyUsage = keyusage.GSSAPI_ACCEPTOR_SIGN
	}

	if err := token.SetChecksum(key, keyUsage); err != nil {
		return nil, fmt.Errorf("error computing MIC checksum: %w", err)
	}

	return token, nil
}

// VerifyMIC verifies a MIC token for the given payload.
// This method gates on context establishment.
func (c *ClientContext) VerifyMIC(token *gssapi.MICToken, payload []byte) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.state != ContextStateEstablished {
		return false, fmt.Errorf("cannot verify MIC: context not established (state: %s)", c.state)
	}

	key := c.sessionKey
	if c.subkey != nil {
		key = *c.subkey
	}

	// Set the payload for verification.
	token.Payload = payload

	// Determine key usage based on who sent the token.
	// If sent by acceptor (server), use GSSAPI_ACCEPTOR_SIGN.
	keyUsage := uint32(keyusage.GSSAPI_ACCEPTOR_SIGN)
	if token.Flags&gssapi.MICTokenFlagSentByAcceptor == 0 {
		keyUsage = keyusage.GSSAPI_INITIATOR_SIGN
	}

	return token.Verify(key, keyUsage)
}

// Wrap creates a sign-only (integrity) wrap token for the given payload.
// This method gates on context establishment.
// For encrypted (sealed) tokens, use WrapSealed instead.
func (c *ClientContext) Wrap(payload []byte) (*gssapi.WrapToken, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.state != ContextStateEstablished {
		return nil, fmt.Errorf("cannot wrap: context not established (state: %s)", c.state)
	}

	key := c.sessionKey
	if c.subkey != nil {
		key = *c.subkey
	}

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("error getting encryption type: %w", err)
	}

	// Determine flags based on role.
	var flags byte
	if !c.isInitiator {
		flags |= gssapi.WrapTokenFlagSentByAcceptor
	}

	if c.subkey != nil {
		flags |= gssapi.WrapTokenFlagAcceptorSubkey
	}

	token := &gssapi.WrapToken{
		Flags:     flags,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: c.nextSendSeqNumLocked(),
		Payload:   payload,
	}

	// Initiator uses GSSAPI_INITIATOR_SEAL, acceptor uses GSSAPI_ACCEPTOR_SEAL.
	keyUsage := uint32(keyusage.GSSAPI_INITIATOR_SEAL)
	if !c.isInitiator {
		keyUsage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}

	if err := token.SetCheckSum(key, keyUsage); err != nil {
		return nil, fmt.Errorf("error computing wrap checksum: %w", err)
	}

	return token, nil
}

// WrapSealed creates an encrypted (sealed) wrap token for the given payload.
// This provides confidentiality in addition to integrity per RFC 4121.
// This method gates on context establishment.
func (c *ClientContext) WrapSealed(payload []byte) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.state != ContextStateEstablished {
		return nil, fmt.Errorf("cannot wrap: context not established (state: %s)", c.state)
	}

	key := c.sessionKey
	if c.subkey != nil {
		key = *c.subkey
	}

	// Determine flags based on role.
	var flags byte
	if !c.isInitiator {
		flags |= gssapi.WrapTokenFlagSentByAcceptor
	}

	if c.subkey != nil {
		flags |= gssapi.WrapTokenFlagAcceptorSubkey
	}

	// Initiator uses GSSAPI_INITIATOR_SEAL, acceptor uses GSSAPI_ACCEPTOR_SEAL.
	keyUsage := uint32(keyusage.GSSAPI_INITIATOR_SEAL)
	if !c.isInitiator {
		keyUsage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}

	if c.wrapTokenDCE {
		return gssapi.NewSealedWrapTokenDCE(payload, key, keyUsage, flags, c.nextSendSeqNumLocked(), c.wrapTokenEC)
	}

	return gssapi.NewSealedWrapToken(payload, key, keyUsage, flags, c.nextSendSeqNumLocked(), c.wrapTokenEC)
}

// Unwrap verifies a sign-only wrapped payload and returns the plaintext.
// This method gates on context establishment.
// For encrypted (sealed) tokens, use UnwrapSealed instead.
func (c *ClientContext) Unwrap(token *gssapi.WrapToken) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.state != ContextStateEstablished {
		return nil, fmt.Errorf("cannot unwrap: context not established (state: %s)", c.state)
	}

	// Check if this is a sealed token - if so, return an error.
	if token.IsSealed() {
		return nil, errors.New("token is sealed (use UnwrapSealed for encrypted tokens)")
	}

	key := c.sessionKey
	if c.subkey != nil {
		key = *c.subkey
	}

	// Determine key usage based on who sent the token.
	// If sent by acceptor (server), use GSSAPI_ACCEPTOR_SEAL.
	keyUsage := uint32(keyusage.GSSAPI_ACCEPTOR_SEAL)
	if token.Flags&gssapi.WrapTokenFlagSentByAcceptor == 0 {
		keyUsage = keyusage.GSSAPI_INITIATOR_SEAL
	}

	ok, err := token.Verify(key, keyUsage)
	if err != nil {
		return nil, fmt.Errorf("error verifying wrap token: %w", err)
	}

	if !ok {
		return nil, errors.New("wrap token verification failed")
	}

	return token.Payload, nil
}

// UnwrapSealed decrypts a sealed wrap token and returns the plaintext.
// This method gates on context establishment.
func (c *ClientContext) UnwrapSealed(tokenBytes []byte) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.state != ContextStateEstablished {
		return nil, fmt.Errorf("cannot unwrap: context not established (state: %s)", c.state)
	}

	key := c.sessionKey
	if c.subkey != nil {
		key = *c.subkey
	}

	// Determine if we expect the token from acceptor.
	// As initiator, we expect tokens from acceptor. As acceptor, we expect from initiator.
	expectFromAcceptor := c.isInitiator

	// Determine key usage based on who sent the token.
	keyUsage := uint32(keyusage.GSSAPI_ACCEPTOR_SEAL)
	if !expectFromAcceptor {
		keyUsage = keyusage.GSSAPI_INITIATOR_SEAL
	}

	return gssapi.UnwrapSealed(tokenBytes, key, keyUsage, expectFromAcceptor)
}

// UnwrapAuto automatically detects whether a token is sealed or sign-only and processes it.
// This provides a unified API similar to SSPI's DecryptMessage.
// This method gates on context establishment.
func (c *ClientContext) UnwrapAuto(tokenBytes []byte) (*gssapi.UnwrapResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.state != ContextStateEstablished {
		return nil, fmt.Errorf("cannot unwrap: context not established (state: %s)", c.state)
	}

	key := c.sessionKey
	if c.subkey != nil {
		key = *c.subkey
	}

	// Determine if we expect the token from acceptor.
	// As initiator, we expect tokens from acceptor. As acceptor, we expect from initiator.
	expectFromAcceptor := c.isInitiator

	// Determine key usage based on who sent the token.
	keyUsage := uint32(keyusage.GSSAPI_ACCEPTOR_SEAL)
	if !expectFromAcceptor {
		keyUsage = keyusage.GSSAPI_INITIATOR_SEAL
	}

	return gssapi.Unwrap(tokenBytes, key, keyUsage, expectFromAcceptor)
}

// nextSendSeqNumLocked returns and increments the send sequence number.
// Caller must hold at least a read lock.
func (c *ClientContext) nextSendSeqNumLocked() uint64 {
	return atomic.AddUint64(&c.sendSeqNum, 1) - 1
}

// Flags returns the negotiated context flags.
func (c *ClientContext) Flags() uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.flags
}

// MechListMIC generates a MIC over the mechTypeList for SPNEGO.
// Per RFC 4178, this MIC is computed over the raw DER bytes of the mechTypeList.
func (c *ClientContext) MechListMIC() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.rawMechTypeListDER == nil {
		return nil, errors.New("mechTypeList DER bytes not set")
	}

	key := c.sessionKey
	if c.subkey != nil {
		key = *c.subkey
	}

	// Create a MIC token over the mechTypeList DER bytes.
	token := &gssapi.MICToken{
		Flags:     0, // Initiator.
		SndSeqNum: 0, // MechListMIC doesn't use sequence numbers.
		Payload:   c.rawMechTypeListDER,
	}

	keyUsage := uint32(keyusage.GSSAPI_INITIATOR_SIGN)

	if err := token.SetChecksum(key, keyUsage); err != nil {
		return nil, fmt.Errorf("error computing mechListMIC: %w", err)
	}

	// Return just the checksum bytes, not the full MIC token.
	return token.Checksum, nil
}

// VerifyMechListMIC verifies the mechListMIC from the server.
func (c *ClientContext) VerifyMechListMIC(mic []byte) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.rawMechTypeListDER == nil {
		return false, errors.New("mechTypeList DER bytes not set")
	}

	key := c.sessionKey
	if c.subkey != nil {
		key = *c.subkey
	}

	// Build a MIC token with the received checksum for verification.
	token := &gssapi.MICToken{
		Flags:     gssapi.MICTokenFlagSentByAcceptor, // From acceptor.
		SndSeqNum: 0,
		Payload:   c.rawMechTypeListDER,
		Checksum:  mic,
	}

	keyUsage := uint32(keyusage.GSSAPI_ACCEPTOR_SIGN)

	return token.Verify(key, keyUsage)
}

// MarshalMechTypeList marshals the given OIDs into the DER format for MIC computation.
// This is exported for use when creating the initial NegTokenInit.
func MarshalMechTypeList(mechTypes []asn1.ObjectIdentifier) ([]byte, error) {
	return asn1.Marshal(mechTypes, asn1.WithMarshalSlicePreserveTypes(true))
}
