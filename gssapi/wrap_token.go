package gssapi

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

// RFC 4121, section 4.2.6.2.

const (
	// HdrLen is the length of the Wrap Token's header.
	HdrLen = 16
	// FillerByte is a filler in the WrapToken structure.
	FillerByte byte = 0xFF

	// WrapTokenFlagSentByAcceptor indicates the token was sent by the acceptor.
	WrapTokenFlagSentByAcceptor byte = 0x01
	// WrapTokenFlagSealed indicates the payload is encrypted (confidentiality).
	WrapTokenFlagSealed byte = 0x02
	// WrapTokenFlagAcceptorSubkey indicates the acceptor's subkey is used.
	WrapTokenFlagAcceptorSubkey byte = 0x04
)

// Wrap token attribute flags as defined in RFC 4121 section 4.2.2.
const (
	// FlagSentByAcceptor is set when the token was emitted by the context acceptor.
	FlagSentByAcceptor byte = 0x01
	// FlagSealed is set when the token's payload is encrypted rather than only integrity protected.
	FlagSealed byte = 0x02
	// FlagAcceptorSubkey is set when the acceptor asserted a subkey which is the key protecting the token.
	FlagAcceptorSubkey byte = 0x04
)

// WrapToken represents a GSS API Wrap token, as defined in RFC 4121.
// It contains the header fields, the payload and the checksum, and provides
// the logic for converting to/from bytes plus computing and verifying checksums.
type WrapToken struct {
	// const GSS Token ID: 0x0504.
	// contains three flags: acceptor, sealed, acceptor subkey.
	Flags byte

	// const Filler: 0xFF.
	// checksum length. big-endian.
	EC uint16

	// right rotation count. big-endian.
	RRC uint16

	// sender's sequence number. big-endian.
	SndSeqNum uint64

	// your data! :).
	Payload []byte

	// authenticated checksum of { payload | header }.
	CheckSum []byte
}

// Return the 2 bytes identifying a GSS API Wrap token.
func getGssWrapTokenId() *[2]byte {
	return &[2]byte{0x05, 0x04}
}

// Marshal the WrapToken into a byte slice.
// The payload should have been set and the checksum computed, otherwise an error is returned.
func (wt *WrapToken) Marshal() ([]byte, error) {
	if wt.CheckSum == nil {
		return nil, errors.New("checksum has not been set")
	}

	if wt.Payload == nil {
		return nil, errors.New("payload has not been set")
	}

	pldOffset := HdrLen
	chkSOffset := HdrLen + len(wt.Payload)

	bytes := make([]byte, chkSOffset+int(wt.EC))
	copy(bytes[0:], getGssWrapTokenId()[:])
	bytes[2] = wt.Flags
	bytes[3] = FillerByte
	binary.BigEndian.PutUint16(bytes[4:6], wt.EC)
	binary.BigEndian.PutUint16(bytes[6:8], wt.RRC)
	binary.BigEndian.PutUint64(bytes[8:16], wt.SndSeqNum)
	copy(bytes[pldOffset:], wt.Payload)
	copy(bytes[chkSOffset:], wt.CheckSum)

	return bytes, nil
}

// SetCheckSum uses the passed encryption key and key usage to compute the checksum over the payload and
// the header, and sets the CheckSum field of this WrapToken.
// If the payload has not been set or the checksum has already been set, an error is returned.
func (wt *WrapToken) SetCheckSum(key types.EncryptionKey, keyUsage uint32) error {
	if wt.Payload == nil {
		return errors.New("payload has not been set")
	}

	if wt.CheckSum != nil {
		return errors.New("checksum has already been computed")
	}

	chkSum, cErr := wt.computeCheckSum(key, keyUsage)
	if cErr != nil {
		return cErr
	}

	wt.CheckSum = chkSum

	return nil
}

// ComputeCheckSum computes and returns the checksum of this token, computed using the passed key and key usage.
// Note: This will NOT update the struct's Checksum field.
func (wt *WrapToken) computeCheckSum(key types.EncryptionKey, keyUsage uint32) ([]byte, error) {
	if wt.Payload == nil {
		return nil, errors.New("cannot compute checksum with uninitialized payload")
	}
	// Build a slice containing { payload | header }.
	checksumMe := make([]byte, HdrLen+len(wt.Payload))
	copy(checksumMe[0:], wt.Payload)
	copy(checksumMe[len(wt.Payload):], getChecksumHeader(wt.Flags, wt.SndSeqNum))

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	return encType.GetChecksumHash(key.KeyValue, checksumMe, keyUsage)
}

// Build the 16 byte Wrap Token header described in RFC 4121 section 4.2.6.2.
func wrapTokenHeader(flags byte, ec, rrc uint16, senderSeqNum uint64) []byte {
	header := make([]byte, HdrLen)
	copy(header[0:], getGssWrapTokenId()[:])
	header[2] = flags
	header[3] = FillerByte
	binary.BigEndian.PutUint16(header[4:6], ec)
	binary.BigEndian.PutUint16(header[6:8], rrc)
	binary.BigEndian.PutUint64(header[8:16], senderSeqNum)

	return header
}

// Build a header suitable for a checksum computation.
// RFC 4121 section 4.2.4 requires both the EC and the RRC field to be zeroed for this purpose.
func getChecksumHeader(flags byte, senderSeqNum uint64) []byte {
	return wrapTokenHeader(flags, 0, 0, senderSeqNum)
}

// Verify computes the token's checksum with the provided key and usage,
// and compares it to the checksum present in the token.
// In case of any failure, (false, Err) is returned, with Err an explanatory error.
func (wt *WrapToken) Verify(key types.EncryptionKey, keyUsage uint32) (bool, error) {
	computed, cErr := wt.computeCheckSum(key, keyUsage)
	if cErr != nil {
		return false, cErr
	}

	if !hmac.Equal(computed, wt.CheckSum) {
		return false, fmt.Errorf(
			"checksum mismatch. Computed: %s, Contained in token: %s",
			hex.EncodeToString(computed), hex.EncodeToString(wt.CheckSum))
	}

	return true, nil
}

// Unmarshal bytes into the corresponding WrapToken.
// If expectFromAcceptor is true, we expect the token to have been emitted by the gss acceptor,
// and will check the according flag, returning an error if the token does not match the expectation.
func (wt *WrapToken) Unmarshal(b []byte, expectFromAcceptor bool) error {
	// Check if we can read a whole header.
	if len(b) < 16 {
		return errors.New("bytes shorter than header length")
	}
	// Is the Token ID correct?
	if !bytes.Equal(getGssWrapTokenId()[:], b[0:2]) {
		return fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(getGssWrapTokenId()[:]),
			hex.EncodeToString(b[0:2]))
	}
	// Check the acceptor flag.
	flags := b[2]

	isFromAcceptor := flags&0x01 == 1
	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}

	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
	}
	// Check the filler byte.
	if b[3] != FillerByte {
		return fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s ", hex.EncodeToString(b[3:4]))
	}

	checksumL := binary.BigEndian.Uint16(b[4:6])
	// Sanity check on the checksum length.
	if int(checksumL) > len(b)-HdrLen {
		return fmt.Errorf("inconsistent checksum length: %d bytes to parse, checksum length is %d", len(b), checksumL)
	}

	wt.Flags = flags
	wt.EC = checksumL
	wt.RRC = binary.BigEndian.Uint16(b[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(b[8:16])
	wt.Payload = b[16 : len(b)-int(checksumL)]
	wt.CheckSum = b[len(b)-int(checksumL):]

	return nil
}

// NewInitiatorWrapToken builds a new initiator token (acceptor flag will be set to 0) and computes the authenticated checksum.
// Other flags are set to 0, and the RRC and sequence number are initialized to 0.
// Note that in certain circumstances you may need to provide a sequence number that has been defined earlier.
// This is currently not supported.
func NewInitiatorWrapToken(payload []byte, key types.EncryptionKey) (*WrapToken, error) {
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	token := WrapToken{
		Flags:     0x00,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 0,
		Payload:   payload,
	}

	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	return &token, nil
}

// SealedWrapToken represents a GSS API Wrap token with confidentiality (encryption).
// Per RFC 4121, the encrypted portion contains { data | filler | header }.
type SealedWrapToken struct {
	// Flags contains: acceptor (0x01), sealed (0x02), acceptor subkey (0x04).
	Flags byte
	// EC is the filler length for sealed tokens.
	EC uint16
	// RRC is the right rotation count.
	RRC uint16
	// SndSeqNum is the sender's sequence number.
	SndSeqNum uint64
	// Payload is the decrypted user data.
	Payload []byte
	// Ciphertext is the encrypted data (set during Marshal, used during Unmarshal).
	Ciphertext []byte
}

// IsSealed returns true if the token has the sealed (confidentiality) flag set.
func (wt *WrapToken) IsSealed() bool {
	return wt.Flags&WrapTokenFlagSealed != 0
}

// NewSealedWrapToken creates a new sealed (encrypted) wrap token per RFC 4121.
// This produces a standard CFX wrap token (RRC=0, no rotation). For DCE-style
// tokens (used by WSMan/PSRP), use NewSealedWrapTokenDCE.
func NewSealedWrapToken(payload []byte, key types.EncryptionKey, keyUsage uint32, flags byte, seqNum uint64, ec uint16) ([]byte, error) {
	return newSealedWrapToken(payload, key, keyUsage, flags, seqNum, ec, false)
}

// NewSealedWrapTokenDCE creates a DCE-style sealed wrap token per RFC 4121
// Section 4.2.4. The ciphertext is rotated right by RRC bytes.
//
// The ec parameter controls the filler/padding length:
// - EC = 0: No filler bytes (Windows WinRM mode)
//   RRC = confounder(16) + checksum(12) = 28 bytes
// - EC = 16: One AES block of padding (MS-KILE mode)
//   RRC = EC(16) + confounder(16) + checksum(12) = 44 bytes
//
// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550
func NewSealedWrapTokenDCE(payload []byte, key types.EncryptionKey, keyUsage uint32, flags byte, seqNum uint64, ec uint16) ([]byte, error) {
	return newSealedWrapToken(payload, key, keyUsage, flags, seqNum, ec, true)
}

func newSealedWrapToken(payload []byte, key types.EncryptionKey, keyUsage uint32, flags byte, seqNum uint64, ec uint16, dceStyle bool) ([]byte, error) {
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("error getting encryption type: %w", err)
	}

	// Set the sealed flag.
	flags |= WrapTokenFlagSealed

	// Calculate RRC for DCE-style rotation.
	// RRC = EC + confounder + checksum
	// When EC=0 (WinRM): RRC = 0 + 16 + 12 = 28 for AES-SHA1
	// When EC=16 (MS-KILE): RRC = 16 + 16 + 12 = 44 for AES-SHA1
	checksumLen := uint16(encType.GetHMACBitLength() / 8)
	confounderLen := uint16(encType.GetConfounderByteSize())
	var rrc uint16
	if dceStyle {
		rrc = ec + confounderLen + checksumLen
	}

	// Build the header with EC and RRC=0 for the encrypted copy.
	// Per RFC 4121, the header included in encryption has EC and RRC set to 0.
	header := make([]byte, HdrLen)
	copy(header[0:2], getGssWrapTokenId()[:])
	header[2] = flags
	header[3] = FillerByte
	binary.BigEndian.PutUint16(header[4:6], ec)
	binary.BigEndian.PutUint16(header[6:8], 0) // RRC = 0 for encryption.
	binary.BigEndian.PutUint64(header[8:16], seqNum)

	// Build plaintext: data | filler | header.
	// The filler is EC bytes of padding (value 0x00).
	plaintext := make([]byte, len(payload)+int(ec)+HdrLen)
	copy(plaintext[0:], payload)
	// Filler bytes (ec bytes of 0x00) are already zero from make().
	copy(plaintext[len(payload)+int(ec):], header)

	// Encrypt the plaintext.
	_, ciphertext, err := encType.EncryptMessage(key.KeyValue, plaintext, keyUsage)
	if err != nil {
		return nil, fmt.Errorf("error encrypting wrap token: %w", err)
	}

	// Apply DCE-style right rotation by RRC bytes.
	// This moves the trailing metadata (checksum, confounder portion) to the front.
	if dceStyle && rrc > 0 && len(ciphertext) > 0 {
		rotateRight(ciphertext, int(rrc))
	}

	// Build the final token: header | rotated_ciphertext.
	// The outer header has the actual RRC value (not 0).
	token := make([]byte, HdrLen+len(ciphertext))
	copy(token[0:HdrLen], header)
	binary.BigEndian.PutUint16(token[6:8], rrc) // Set actual RRC in outer header.
	copy(token[HdrLen:], ciphertext)

	return token, nil
}

// parseSealedHeader parses and validates the header of a sealed wrap token.
func parseSealedHeader(tokenBytes []byte, expectFromAcceptor bool) (flags byte, ec, rrc uint16, seqNum uint64, err error) {
	if len(tokenBytes) < HdrLen {
		return 0, 0, 0, 0, errors.New("token too short")
	}

	// Verify token ID.
	if !bytes.Equal(getGssWrapTokenId()[:], tokenBytes[0:2]) {
		return 0, 0, 0, 0, fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(getGssWrapTokenId()[:]),
			hex.EncodeToString(tokenBytes[0:2]))
	}

	flags = tokenBytes[2]

	// Verify sealed flag is set.
	if flags&WrapTokenFlagSealed == 0 {
		return 0, 0, 0, 0, errors.New("token is not sealed (use Unwrap for sign-only tokens)")
	}

	// Check the acceptor flag.
	if err := validateAcceptorFlag(flags, expectFromAcceptor); err != nil {
		return 0, 0, 0, 0, err
	}

	// Check the filler byte.
	if tokenBytes[3] != FillerByte {
		return 0, 0, 0, 0, fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s",
			hex.EncodeToString(tokenBytes[3:4]))
	}

	ec = binary.BigEndian.Uint16(tokenBytes[4:6])
	rrc = binary.BigEndian.Uint16(tokenBytes[6:8])
	seqNum = binary.BigEndian.Uint64(tokenBytes[8:16])

	return flags, ec, rrc, seqNum, nil
}

// validateAcceptorFlag checks if the acceptor flag matches expectations.
func validateAcceptorFlag(flags byte, expectFromAcceptor bool) error {
	isFromAcceptor := flags&WrapTokenFlagSentByAcceptor != 0

	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set")
	}

	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag is not set")
	}

	return nil
}

// buildExpectedHeader constructs the expected header for verification.
func buildExpectedHeader(flags byte, ec uint16, seqNum uint64) []byte {
	header := make([]byte, HdrLen)
	copy(header[0:2], getGssWrapTokenId()[:])
	header[2] = flags
	header[3] = FillerByte
	binary.BigEndian.PutUint16(header[4:6], ec)
	binary.BigEndian.PutUint16(header[6:8], 0) // RRC was 0 during encryption.
	binary.BigEndian.PutUint64(header[8:16], seqNum)

	return header
}

// UnwrapSealed decrypts a sealed wrap token and returns the payload.
// It verifies the token structure and integrity per RFC 4121.
func UnwrapSealed(tokenBytes []byte, key types.EncryptionKey, keyUsage uint32, expectFromAcceptor bool) ([]byte, error) {
	flags, ec, rrc, seqNum, err := parseSealedHeader(tokenBytes, expectFromAcceptor)
	if err != nil {
		return nil, err
	}

	// Get the ciphertext and undo RRC rotation if needed.
	// The sender applied right rotation, so we apply left rotation to undo.
	ciphertext := make([]byte, len(tokenBytes)-HdrLen)
	copy(ciphertext, tokenBytes[HdrLen:])

	if rrc > 0 && len(ciphertext) > 0 {
		rotateLeft(ciphertext, int(rrc))
	}

	// Decrypt the ciphertext.
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("error getting encryption type: %w", err)
	}

	plaintext, err := encType.DecryptMessage(key.KeyValue, ciphertext, keyUsage)
	if err != nil {
		return nil, fmt.Errorf("error decrypting wrap token: %w", err)
	}

	// The plaintext is: data | filler | header.
	if len(plaintext) < HdrLen+int(ec) {
		return nil, errors.New("decrypted data too short")
	}

	// Extract and verify the header.
	headerOffset := len(plaintext) - HdrLen
	decryptedHeader := plaintext[headerOffset:]
	expectedHeader := buildExpectedHeader(flags, ec, seqNum)

	if !bytes.Equal(decryptedHeader, expectedHeader) {
		return nil, errors.New("header mismatch in decrypted data")
	}

	// Extract the payload (skip filler).
	payloadLen := headerOffset - int(ec)
	if payloadLen < 0 {
		return nil, errors.New("invalid filler length")
	}

	return plaintext[:payloadLen], nil
}

// UnwrapResult contains the result of unwrapping a token.
type UnwrapResult struct {
	// Payload is the decrypted/verified data.
	Payload []byte
	// Sealed indicates whether the token was encrypted (true) or sign-only (false).
	Sealed bool
	// SeqNum is the sequence number from the token.
	SeqNum uint64
}

// Unwrap automatically detects whether a token is sealed or sign-only and processes it accordingly.
// This provides a unified API similar to SSPI's DecryptMessage.
// Returns the payload, whether it was sealed, and any error.
func Unwrap(tokenBytes []byte, key types.EncryptionKey, keyUsage uint32, expectFromAcceptor bool) (*UnwrapResult, error) {
	if len(tokenBytes) < HdrLen {
		return nil, errors.New("token too short")
	}

	// Verify token ID.
	if !bytes.Equal(getGssWrapTokenId()[:], tokenBytes[0:2]) {
		return nil, fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(getGssWrapTokenId()[:]),
			hex.EncodeToString(tokenBytes[0:2]))
	}

	flags := tokenBytes[2]

	// Check direction.
	if err := validateAcceptorFlag(flags, expectFromAcceptor); err != nil {
		return nil, err
	}

	// Check the filler byte.
	if tokenBytes[3] != FillerByte {
		return nil, fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s",
			hex.EncodeToString(tokenBytes[3:4]))
	}

	seqNum := binary.BigEndian.Uint64(tokenBytes[8:16])

	// Dispatch based on sealed flag.
	if flags&WrapTokenFlagSealed != 0 {
		payload, err := UnwrapSealed(tokenBytes, key, keyUsage, expectFromAcceptor)
		if err != nil {
			return nil, err
		}

		return &UnwrapResult{
			Payload: payload,
			Sealed:  true,
			SeqNum:  seqNum,
		}, nil
	}

	// Sign-only token - parse and verify.
	var wt WrapToken
	if err := wt.Unmarshal(tokenBytes, expectFromAcceptor); err != nil {
		return nil, err
	}

	ok, err := wt.Verify(key, keyUsage)
	if err != nil {
		return nil, fmt.Errorf("error verifying wrap token: %w", err)
	}

	if !ok {
		return nil, errors.New("wrap token verification failed")
	}

	return &UnwrapResult{
		Payload: wt.Payload,
		Sealed:  false,
		SeqNum:  wt.SndSeqNum,
	}, nil
}

// GetSealedTokenRRC returns the RRC (Right Rotation Count) from a sealed wrap token.
// This is useful for MS-WSMV format where SignatureLength = HdrLen + RRC.
func GetSealedTokenRRC(tokenBytes []byte) (uint16, error) {
	if len(tokenBytes) < HdrLen {
		return 0, errors.New("token too short")
	}

	// Verify token ID.
	if !bytes.Equal(getGssWrapTokenId()[:], tokenBytes[0:2]) {
		return 0, errors.New("wrong Token ID")
	}

	// Verify sealed flag is set.
	if tokenBytes[2]&WrapTokenFlagSealed == 0 {
		return 0, errors.New("token is not sealed")
	}

	return binary.BigEndian.Uint16(tokenBytes[6:8]), nil
}

// rotateRight performs a right rotation of the data by n bytes.
// After right rotation, the last n bytes move to the front.
// Used by sender to apply DCE-style rotation.
func rotateRight(data []byte, n int) {
	if len(data) == 0 {
		return
	}

	n %= len(data)
	if n == 0 {
		return
	}

	// Right rotation by n is equivalent to left rotation by len-n.
	leftRotate := len(data) - n

	// Use a temporary buffer.
	tmp := make([]byte, leftRotate)
	copy(tmp, data[:leftRotate])
	copy(data, data[leftRotate:])
	copy(data[n:], tmp)
}

// rotateLeft performs a left rotation of the data by n bytes.
// After left rotation, the first n bytes move to the end.
// Used by receiver to undo DCE-style rotation.
func rotateLeft(data []byte, n int) {
	if len(data) == 0 {
		return
	}

	n %= len(data)
	if n == 0 {
		return
	}

	// Left rotation: first n bytes move to end.
	tmp := make([]byte, n)
	copy(tmp, data[:n])
	copy(data, data[n:])
	copy(data[len(data)-n:], tmp)
}
