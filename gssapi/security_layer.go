package gssapi

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/crypto/etype"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

// SecurityLayer is a SASL security layer as defined in RFC 4752 section 3.1.
// The values are the individual bits of the security layer bit-mask exchanged during the second leg of the
// GSSAPI SASL mechanism, so they can be used directly when reading or writing that bit-mask.
type SecurityLayer byte

const (
	// SecurityLayerNone provides authentication only. Messages are passed through unprotected.
	SecurityLayerNone SecurityLayer = 1 << iota
	// SecurityLayerIntegrity provides integrity protection. Messages are signed with a checksum but not encrypted.
	SecurityLayerIntegrity
	// SecurityLayerConfidentiality provides confidentiality and integrity protection. Messages are encrypted.
	SecurityLayerConfidentiality
)

// String returns the name of the security layer.
func (l SecurityLayer) String() string {
	switch l {
	case SecurityLayerNone:
		return "none"
	case SecurityLayerIntegrity:
		return "integrity"
	case SecurityLayerConfidentiality:
		return "confidentiality"
	}

	return fmt.Sprintf("unknown security layer (%d)", byte(l))
}

const (
	// SASLFrameHeaderLen is the length of the length prefix that precedes each buffer of protected data as
	// described in RFC 4422 section 3.7.
	SASLFrameHeaderLen = 4
	// MaxSASLBufferSize is the largest buffer of protected data that will be read from the network by a session
	// that has no maximum buffer size of its own.
	MaxSASLBufferSize = 1 << 24
)

// SecurityLayerSession applies a negotiated SASL security layer to the messages of an established GSS-API context.
//
// Messages are protected as RFC 4121 Wrap tokens using the context's session key, and the sequence numbers of the
// tokens sent and received are tracked so that reordered, replayed and dropped messages are rejected.
//
// A session is safe for concurrent use. Callers that wrap messages from more than one goroutine must, however, put
// the resulting tokens on the wire in the order they were produced, otherwise the receiver rejects them as out of
// sequence. SecureConn does this for its callers.
type SecurityLayerSession struct {
	key           types.EncryptionKey
	encType       etype.EType
	layer         SecurityLayer
	isInitiator   bool
	maxBufferSize int

	mu         sync.Mutex
	sendSeqNum uint64
	recvSeqNum uint64
	recvSeqSet bool
}

// SecurityLayerOption configures a SecurityLayerSession.
type SecurityLayerOption func(*SecurityLayerSession)

// InitialSendSequenceNumber sets the sequence number carried by the first token the session emits.
// RFC 4121 section 4.2.6.2 takes this from the sequence number of the authenticator of the AP_REQ for an initiator
// and from the AP_REP for an acceptor. It defaults to zero.
func InitialSendSequenceNumber(n uint64) SecurityLayerOption {
	return func(s *SecurityLayerSession) {
		s.sendSeqNum = n
	}
}

// InitialReceiveSequenceNumber sets the sequence number expected on the first token the session receives.
// When it is not set the session accepts whatever sequence number the first token carries and requires every
// subsequent token to continue from it.
func InitialReceiveSequenceNumber(n uint64) SecurityLayerOption {
	return func(s *SecurityLayerSession) {
		s.recvSeqNum = n
		s.recvSeqSet = true
	}
}

// NewSecurityLayerSession returns a session that protects messages with the security layer provided using the
// session key of an established GSS-API context.
//
// isInitiator must be true on the side that initiated the context, which for SASL is the client, and false on the
// side that accepted it. It selects the key usage values and the token direction flag of RFC 4121 section 4.2.2, so
// the two ends of a context must not agree on the same value.
//
// maxBufferSize is the largest buffer of protected data either end will handle, as negotiated per RFC 4752
// section 3.1. It bounds the size of the tokens the session produces and of those it accepts, and excludes the
// length prefix of RFC 4422 section 3.7. Zero means unlimited.
func NewSecurityLayerSession(key types.EncryptionKey, layer SecurityLayer, isInitiator bool, maxBufferSize int, opts ...SecurityLayerOption) (*SecurityLayerSession, error) {
	switch layer {
	case SecurityLayerNone, SecurityLayerIntegrity, SecurityLayerConfidentiality:
	default:
		return nil, fmt.Errorf("invalid security layer: %d", byte(layer))
	}

	if maxBufferSize < 0 {
		return nil, fmt.Errorf("invalid maximum buffer size: %d", maxBufferSize)
	}

	et, err := crypto.GetEType(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("could not get the encryption type of the session key: %w", err)
	}

	s := &SecurityLayerSession{
		key:           key,
		encType:       et,
		layer:         layer,
		isInitiator:   isInitiator,
		maxBufferSize: maxBufferSize,
	}

	for _, opt := range opts {
		opt(s)
	}

	if o := s.tokenOverhead(); maxBufferSize > 0 && maxBufferSize <= o {
		return nil, fmt.Errorf("maximum buffer size %d is too small: a %s token of encryption type %d has an overhead of %d bytes", maxBufferSize, layer, key.KeyType, o)
	}

	return s, nil
}

// Layer returns the security layer the session applies.
func (s *SecurityLayerSession) Layer() SecurityLayer {
	return s.layer
}

// MaxBufferSize returns the largest buffer of protected data the session produces and accepts, excluding the length
// prefix of RFC 4422 section 3.7. Zero means unlimited.
func (s *SecurityLayerSession) MaxBufferSize() int {
	return s.maxBufferSize
}

// WrapSizeLimit returns the largest message Wrap will accept without exceeding the session's maximum buffer size.
// It returns zero when the session has no maximum buffer size.
func (s *SecurityLayerSession) WrapSizeLimit() int {
	if s.maxBufferSize <= 0 {
		return 0
	}

	return s.maxBufferSize - s.tokenOverhead()
}

// tokenOverhead returns the largest number of octets Wrap adds to a message.
func (s *SecurityLayerSession) tokenOverhead() int {
	if s.layer == SecurityLayerNone {
		return 0
	}

	// The token header and the checksum or integrity hash of the encryption type.
	o := HdrLen + s.encType.GetHMACBitLength()/8

	if s.layer == SecurityLayerConfidentiality {
		// The confounder of the encryption type, the copy of the header appended to the plaintext and the largest
		// filler that may be needed to align the plaintext to the message block size.
		o += s.encType.GetConfounderByteSize() + HdrLen

		if m := s.encType.GetMessageBlockByteSize(); m > 1 {
			o += m - 1
		}
	}

	return o
}

// Wrap protects a message with the session's security layer and returns it as an RFC 4121 Wrap token.
//
// For SecurityLayerNone the message is returned unchanged. For SecurityLayerIntegrity the token carries the message
// in plaintext followed by a checksum over the message and the token header. For SecurityLayerConfidentiality the
// token carries the message, filler and a copy of the token header encrypted with the session key, which the
// encryption type of RFC 3961 integrity protects as well.
func (s *SecurityLayerSession) Wrap(message []byte) ([]byte, error) {
	if s.layer == SecurityLayerNone {
		return message, nil
	}

	if message == nil {
		message = []byte{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	flags := byte(0)
	if !s.isInitiator {
		flags |= FlagSentByAcceptor
	}

	var (
		token []byte
		err   error
	)

	if s.layer == SecurityLayerConfidentiality {
		flags |= FlagSealed
		token, err = s.wrapSealed(flags, message)
	} else {
		token, err = s.wrapSigned(flags, message)
	}

	if err != nil {
		return nil, err
	}

	if s.maxBufferSize > 0 && len(token) > s.maxBufferSize {
		return nil, fmt.Errorf("wrap token of %d bytes exceeds the maximum buffer size of %d bytes", len(token), s.maxBufferSize)
	}

	s.sendSeqNum++

	return token, nil
}

// wrapSigned builds the integrity protected Wrap token of RFC 4121 section 4.2.4, {header | message | checksum},
// where the EC field of the header holds the length of the checksum.
func (s *SecurityLayerSession) wrapSigned(flags byte, message []byte) ([]byte, error) {
	token := WrapToken{
		Flags:     flags,
		EC:        uint16(s.encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: s.sendSeqNum,
		Payload:   message,
	}

	if err := token.SetCheckSum(s.key, s.keyUsage(true)); err != nil {
		return nil, fmt.Errorf("could not compute the wrap token checksum: %w", err)
	}

	return token.Marshal()
}

// wrapSealed builds the confidentiality protected Wrap token of RFC 4121 section 4.2.4,
// {header | encrypt(message | filler | header)}, where the EC field of the header holds the length of the filler and
// the RRC field of the encrypted copy of the header is zeroed.
func (s *SecurityLayerSession) wrapSealed(flags byte, message []byte) ([]byte, error) {
	ec := s.fillerLen(len(message))
	header := wrapTokenHeader(flags, uint16(ec), 0, s.sendSeqNum)

	// The filler octets are left as the zero value of the slice.
	plaintext := make([]byte, len(message)+ec+HdrLen)
	copy(plaintext, message)
	copy(plaintext[len(message)+ec:], header)

	_, ciphertext, err := s.encType.EncryptMessage(s.key.KeyValue, plaintext, s.keyUsage(true))
	if err != nil {
		return nil, fmt.Errorf("could not encrypt the wrap token payload: %w", err)
	}

	token := make([]byte, HdrLen+len(ciphertext))
	copy(token, header)
	copy(token[HdrLen:], ciphertext)

	return token, nil
}

// fillerLen returns the number of filler octets to insert between the message and the copy of the header of a
// confidentiality protected Wrap token so that no crypto-system residue remains after decryption, as required by
// RFC 4121 section 4.2.4.
//
// RFC 3961 encryption zero pads the confounder and the plaintext up to a multiple of the message block size of the
// encryption type and decryption does not remove that padding. Aligning the plaintext to the message block size
// therefore stops any padding from being added. Encryption types whose message block size is a single octet, which
// is every type using ciphertext stealing along with RC4, never pad and need no filler.
func (s *SecurityLayerSession) fillerLen(messageLen int) int {
	m := s.encType.GetMessageBlockByteSize()
	if m <= 1 {
		return 0
	}

	return (m - (s.encType.GetConfounderByteSize()+messageLen+HdrLen)%m) % m
}

// Unwrap verifies an RFC 4121 Wrap token received from the peer and returns the message it protects.
//
// For SecurityLayerNone the token is returned unchanged. Otherwise the token must match the security layer and the
// direction of the session, its checksum must verify or its payload must decrypt, and its sequence number must be
// the one that follows the sequence number of the previous token.
func (s *SecurityLayerSession) Unwrap(token []byte) ([]byte, error) {
	if s.layer == SecurityLayerNone {
		return token, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.maxBufferSize > 0 && len(token) > s.maxBufferSize {
		return nil, fmt.Errorf("wrap token of %d bytes exceeds the maximum buffer size of %d bytes", len(token), s.maxBufferSize)
	}

	if len(token) < HdrLen {
		return nil, fmt.Errorf("wrap token of %d bytes is shorter than the %d byte header", len(token), HdrLen)
	}

	if !bytes.Equal(token[0:2], getGssWrapTokenId()[:]) {
		return nil, fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(getGssWrapTokenId()[:]), hex.EncodeToString(token[0:2]))
	}

	if token[3] != FillerByte {
		return nil, fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s", hex.EncodeToString(token[3:4]))
	}

	flags := token[2]

	// Each end of the context only ever receives tokens emitted by the other end.
	if fromAcceptor := flags&FlagSentByAcceptor != 0; fromAcceptor != s.isInitiator {
		if s.isInitiator {
			return nil, errors.New("expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
		}

		return nil, errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}

	// A peer must not downgrade to a weaker protection than the layer that was negotiated, nor use a stronger one
	// that the negotiated layer gives no way to interpret.
	if sealed := flags&FlagSealed != 0; sealed != (s.layer == SecurityLayerConfidentiality) {
		return nil, fmt.Errorf("wrap token does not match the negotiated %s security layer: sealed flag is %t", s.layer, sealed)
	}

	ec := binary.BigEndian.Uint16(token[4:6])
	rrc := binary.BigEndian.Uint16(token[6:8])
	seq := binary.BigEndian.Uint64(token[8:16])

	if s.recvSeqSet && seq != s.recvSeqNum {
		return nil, fmt.Errorf("wrap token sequence number %d is out of sequence, expected %d", seq, s.recvSeqNum)
	}

	data := unrotate(token[HdrLen:], rrc)

	var (
		message []byte
		err     error
	)

	if s.layer == SecurityLayerConfidentiality {
		message, err = s.unwrapSealed(flags, ec, seq, data)
	} else {
		message, err = s.unwrapSigned(flags, ec, seq, data)
	}

	if err != nil {
		return nil, err
	}

	s.recvSeqNum = seq + 1
	s.recvSeqSet = true

	return message, nil
}

// unwrapSigned splits {message | checksum} apart and verifies the checksum over the message and the token header.
func (s *SecurityLayerSession) unwrapSigned(flags byte, ec uint16, seq uint64, data []byte) ([]byte, error) {
	if int(ec) > len(data) {
		return nil, fmt.Errorf("inconsistent checksum length: %d bytes of token data, checksum length is %d", len(data), ec)
	}

	token := WrapToken{
		Flags:     flags,
		EC:        ec,
		RRC:       0,
		SndSeqNum: seq,
		Payload:   data[:len(data)-int(ec)],
		CheckSum:  data[len(data)-int(ec):],
	}

	if ok, err := token.Verify(s.key, s.keyUsage(false)); err != nil {
		return nil, fmt.Errorf("could not verify the wrap token checksum: %w", err)
	} else if !ok {
		return nil, errors.New("wrap token checksum verification failed")
	}

	return token.Payload, nil
}

// unwrapSealed decrypts the token payload and strips the filler and the copy of the header that RFC 4121
// section 4.2.4 appends to the message before encryption.
func (s *SecurityLayerSession) unwrapSealed(flags byte, ec uint16, seq uint64, data []byte) ([]byte, error) {
	// The encryption types read the confounder and the integrity hash off the ciphertext without checking that
	// there is enough of it to read.
	if n := s.encType.GetConfounderByteSize() + s.encType.GetHMACBitLength()/8; len(data) <= n {
		return nil, fmt.Errorf("wrap token payload of %d bytes is too short to be decrypted, expected more than %d", len(data), n)
	}

	plaintext, err := s.encType.DecryptMessage(s.key.KeyValue, data, s.keyUsage(false))
	if err != nil {
		return nil, fmt.Errorf("could not decrypt the wrap token payload: %w", err)
	}

	trailer := int(ec) + HdrLen
	if len(plaintext) < trailer {
		return nil, fmt.Errorf("decrypted wrap token payload of %d bytes is shorter than its %d bytes of filler and header", len(plaintext), trailer)
	}

	// The copy of the header encrypted with the message binds the message to the header the token was sent with.
	if !hmac.Equal(plaintext[len(plaintext)-HdrLen:], wrapTokenHeader(flags, ec, 0, seq)) {
		return nil, errors.New("wrap token header does not match the copy of it encrypted with the payload")
	}

	return plaintext[:len(plaintext)-trailer], nil
}

// keyUsage returns the key usage of RFC 4121 section 2 for a Wrap token being sent or received.
func (s *SecurityLayerSession) keyUsage(sending bool) uint32 {
	if sending == s.isInitiator {
		return keyusage.GSSAPI_INITIATOR_SEAL
	}

	return keyusage.GSSAPI_ACCEPTOR_SEAL
}

// rotate performs the right rotation the RRC field of a Wrap token records, as described in RFC 4121
// Section 4.2.5. A sender may choose any count, including one longer than the data itself.
func rotate(data []byte, rrc uint16) []byte {
	if len(data) == 0 {
		return data
	}

	n := int(rrc) % len(data)
	if n == 0 {
		return data
	}

	rotated := make([]byte, len(data))
	copy(rotated[n:], data[:len(data)-n])
	copy(rotated[:n], data[len(data)-n:])

	return rotated
}

// unrotate reverses the right rotation the RRC field of a Wrap token records, as described in RFC 4121
// section 4.2.5. A receiver has to cope with any rotation count, including one longer than the data itself.
func unrotate(data []byte, rrc uint16) []byte {
	if len(data) == 0 {
		return data
	}

	n := int(rrc) % len(data)
	if n == 0 {
		return data
	}

	unrotated := make([]byte, len(data))
	copy(unrotated, data[n:])
	copy(unrotated[len(data)-n:], data[:n])

	return unrotated
}

// WrapWithSASLFraming protects a message with the session's security layer and prefixes the resulting token with
// its length as a four octet integer in network byte order, which is the framing RFC 4422 section 3.7 defines for
// buffers of protected data.
//
// A security layer of SecurityLayerNone applies no framing at all, so it is an error to call this.
func (s *SecurityLayerSession) WrapWithSASLFraming(message []byte) ([]byte, error) {
	if s.layer == SecurityLayerNone {
		return nil, errors.New("SASL framing is not applied when no security layer has been negotiated")
	}

	token, err := s.Wrap(message)
	if err != nil {
		return nil, err
	}

	frame := make([]byte, SASLFrameHeaderLen+len(token))
	binary.BigEndian.PutUint32(frame[:SASLFrameHeaderLen], uint32(len(token)))
	copy(frame[SASLFrameHeaderLen:], token)

	return frame, nil
}

// UnwrapFromSASLFraming reads one buffer of protected data framed as described in RFC 4422 section 3.7 from the
// reader and returns the message it protects. The reader must be positioned at the start of the length prefix and
// is read up to the end of the buffer it announces.
//
// A security layer of SecurityLayerNone applies no framing at all, so it is an error to call this.
func (s *SecurityLayerSession) UnwrapFromSASLFraming(r io.Reader) ([]byte, error) {
	if s.layer == SecurityLayerNone {
		return nil, errors.New("SASL framing is not applied when no security layer has been negotiated")
	}

	var header [SASLFrameHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("could not read the SASL buffer length: %w", err)
	}

	n := binary.BigEndian.Uint32(header[:])

	limit := uint32(MaxSASLBufferSize)
	if s.maxBufferSize > 0 {
		limit = uint32(s.maxBufferSize)
	}

	if n > limit {
		return nil, fmt.Errorf("SASL buffer of %d bytes exceeds the maximum buffer size of %d bytes", n, limit)
	}

	token := make([]byte, n)
	if _, err := io.ReadFull(r, token); err != nil {
		return nil, fmt.Errorf("could not read the SASL buffer: %w", err)
	}

	return s.Unwrap(token)
}

// SecureConn is a net.Conn that applies a SASL security layer to everything written to and read from the
// connection it wraps. Data written is protected and framed as described in RFC 4422 section 3.7, and data read is
// unframed and verified.
//
// A connection is safe for concurrent use to the extent net.Conn is: one reader and one writer at a time.
type SecureConn struct {
	conn    net.Conn
	session *SecurityLayerSession

	rmu     sync.Mutex
	readBuf []byte

	wmu sync.Mutex
}

var _ net.Conn = (*SecureConn)(nil)

// NewSecureConn returns a connection that protects the traffic of the connection provided with the security layer
// of the session provided. The session must have been created for the end of the GSS-API context this side of the
// connection holds.
//
// A session with a security layer of SecurityLayerNone passes the traffic of the connection straight through, so a
// caller does not need to know which layer was negotiated to use this.
//
// Note that MS-ADTS section 5.1.1.1 forbids a SASL security layer on a connection that is already protected by TLS
// and an Active Directory domain controller rejects such a connection, even though RFC 4513 section 3.1 permits the
// combination and other directory servers accept it.
func NewSecureConn(conn net.Conn, session *SecurityLayerSession) *SecureConn {
	return &SecureConn{
		conn:    conn,
		session: session,
	}
}

// Read reads the next of the data protected by the peer into b.
func (c *SecureConn) Read(b []byte) (int, error) {
	if c.session.Layer() == SecurityLayerNone {
		return c.conn.Read(b)
	}

	c.rmu.Lock()
	defer c.rmu.Unlock()

	for len(c.readBuf) == 0 {
		message, err := c.session.UnwrapFromSASLFraming(c.conn)
		if err != nil {
			return 0, err
		}

		c.readBuf = message
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]

	return n, nil
}

// Write protects b and writes it to the connection. Data longer than the maximum buffer size the session was
// negotiated with is written as several buffers of protected data.
func (c *SecureConn) Write(b []byte) (int, error) {
	if c.session.Layer() == SecurityLayerNone {
		return c.conn.Write(b)
	}

	if len(b) == 0 {
		return 0, nil
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()

	limit := c.session.WrapSizeLimit()

	var written int

	for written < len(b) {
		message := b[written:]
		if limit > 0 && len(message) > limit {
			message = message[:limit]
		}

		frame, err := c.session.WrapWithSASLFraming(message)
		if err != nil {
			return written, err
		}

		if _, err = c.conn.Write(frame); err != nil {
			return written, err
		}

		written += len(message)
	}

	return written, nil
}

// Close closes the connection.
func (c *SecureConn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local network address of the connection.
func (c *SecureConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address of the connection.
func (c *SecureConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines of the connection.
func (c *SecureConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline of the connection.
func (c *SecureConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline of the connection.
func (c *SecureConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
