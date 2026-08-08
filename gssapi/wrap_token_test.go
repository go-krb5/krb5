package gssapi

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

const (
	// What a kerberized server might send.
	testChallengeFromAcceptor = "050401ff000c000000000000575e85d601010000853b728d5268525a1386c19f"
	// What an initiator client could reply.
	testChallengeReplyFromInitiator = "050400ff000c000000000000000000000101000079a033510b6f127212242b97"
	// session key used to sign the tokens above.
	sessionKey     = "14f9bde6b50ec508201a97f74c4e5bd3"
	sessionKeyType = 17

	acceptorSeal  = keyusage.GSSAPI_ACCEPTOR_SEAL
	initiatorSeal = keyusage.GSSAPI_INITIATOR_SEAL
)

func getSessionKey() types.EncryptionKey {
	key, _ := hex.DecodeString(sessionKey)

	return types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: key,
	}
}

func getChallengeReference() *WrapToken {
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)

	return &WrapToken{
		Flags:     0x01,
		EC:        12,
		RRC:       0,
		SndSeqNum: binary.BigEndian.Uint64(challenge[8:16]),
		Payload:   []byte{0x01, 0x01, 0x00, 0x00},
		CheckSum:  challenge[20:32],
	}
}

func getResponseReference() *WrapToken {
	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)

	return &WrapToken{
		Flags:     0x00,
		EC:        12,
		RRC:       0,
		SndSeqNum: 0,
		Payload:   []byte{0x01, 0x01, 0x00, 0x00},
		CheckSum:  response[20:32],
	}
}

func getResponseReferenceNoChkSum() *WrapToken {
	r := getResponseReference()
	r.CheckSum = nil

	return r
}

func TestUnmarshal_Challenge(t *testing.T) {
	t.Parallel()

	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)

	var wt WrapToken

	err := wt.Unmarshal(challenge, true)
	assert.Nil(t, err)
	assert.Equal(t, getChallengeReference(), &wt)
}

func TestUnmarshalFailure_Challenge(t *testing.T) {
	t.Parallel()

	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)

	var wt WrapToken

	err := wt.Unmarshal(challenge, false)
	assert.NotNil(t, err)
	assert.Nil(t, wt.Payload)
	assert.Nil(t, wt.CheckSum)
	assert.Equal(t, byte(0x00), wt.Flags)
	assert.Equal(t, uint16(0), wt.EC)
	assert.Equal(t, uint16(0), wt.RRC)
	assert.Equal(t, uint64(0), wt.SndSeqNum)
}

func TestUnmarshal_ChallengeReply(t *testing.T) {
	t.Parallel()

	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)

	var wt WrapToken

	err := wt.Unmarshal(response, false)
	assert.Nil(t, err)
	assert.Equal(t, getResponseReference(), &wt)
}

func TestUnmarshalFailure_ChallengeReply(t *testing.T) {
	t.Parallel()

	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)

	var wt WrapToken

	err := wt.Unmarshal(response, true)
	assert.NotNil(t, err)
	assert.Nil(t, wt.Payload)
	assert.Nil(t, wt.CheckSum)
	assert.Equal(t, byte(0x00), wt.Flags)
	assert.Equal(t, uint16(0), wt.EC)
	assert.Equal(t, uint16(0), wt.RRC)
	assert.Equal(t, uint64(0), wt.SndSeqNum)
}

func TestChallengeChecksumVerification(t *testing.T) {
	t.Parallel()

	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)

	var wt WrapToken
	require.NoError(t, wt.Unmarshal(challenge, true))
	challengeOk, cErr := wt.Verify(getSessionKey(), acceptorSeal)
	assert.Nil(t, cErr)
	assert.True(t, challengeOk)
}

func TestResponseChecksumVerification(t *testing.T) {
	t.Parallel()

	reply, _ := hex.DecodeString(testChallengeReplyFromInitiator)

	var wt WrapToken
	require.NoError(t, wt.Unmarshal(reply, false))
	replyOk, rErr := wt.Verify(getSessionKey(), initiatorSeal)
	assert.Nil(t, rErr)
	assert.True(t, replyOk)
}

func TestChecksumVerificationFailure(t *testing.T) {
	t.Parallel()

	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)

	var wt WrapToken
	require.NoError(t, wt.Unmarshal(challenge, true))

	// Test a failure with the correct key but wrong keyusage:.
	challengeOk, cErr := wt.Verify(getSessionKey(), initiatorSeal)
	assert.NotNil(t, cErr)
	assert.False(t, challengeOk)

	wrongKeyVal, _ := hex.DecodeString("14f9bde6b50ec508201a97f74c4effff")
	badKey := types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: wrongKeyVal,
	}
	// Test a failure with the wrong key but correct keyusage:.
	wrongKeyOk, wkErr := wt.Verify(badKey, acceptorSeal)
	assert.NotNil(t, wkErr)
	assert.False(t, wrongKeyOk)
}

func TestMarshal_Challenge(t *testing.T) {
	t.Parallel()

	bytes, _ := getChallengeReference().Marshal()
	assert.Equal(t, testChallengeFromAcceptor, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_ChallengeReply(t *testing.T) {
	t.Parallel()

	bytes, _ := getResponseReference().Marshal()
	assert.Equal(t, testChallengeReplyFromInitiator, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_Failures(t *testing.T) {
	t.Parallel()

	noChkSum := getResponseReferenceNoChkSum()
	chkBytes, chkErr := noChkSum.Marshal()
	assert.Nil(t, chkBytes)
	assert.NotNil(t, chkErr)

	noPayload := getResponseReference()
	noPayload.Payload = nil
	pldBytes, pldErr := noPayload.Marshal()
	assert.Nil(t, pldBytes)
	assert.NotNil(t, pldErr)
}

func TestNewInitiatorTokenSignatureAndMarshalling(t *testing.T) {
	t.Parallel()

	token, tErr := NewInitiatorWrapToken([]byte{0x01, 0x01, 0x00, 0x00}, getSessionKey())
	assert.Nil(t, tErr)
	assert.Equal(t, getResponseReference(), token)
}

// Tests for sealed (encrypted) wrap tokens.

func getAES256Key() types.EncryptionKey {
	// 32-byte key for AES256-CTS-HMAC-SHA1-96.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	return types.EncryptionKey{
		KeyType:  18, // AES256-CTS-HMAC-SHA1-96.
		KeyValue: key,
	}
}

func TestSealedWrapToken_RoundTrip(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte("test payload for sealed wrap token")

	// Create a sealed token as initiator.
	var flags byte = 0 // Initiator.

	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, initiatorSeal, flags, 12345, 16)
	require.NoError(t, err)
	require.NotNil(t, tokenBytes)

	// Verify the token has the sealed flag.
	assert.Equal(t, byte(0x05), tokenBytes[0])
	assert.Equal(t, byte(0x04), tokenBytes[1])
	assert.Equal(t, WrapTokenFlagSealed, tokenBytes[2]&WrapTokenFlagSealed)

	// Decrypt the token.
	decrypted, err := UnwrapSealed(tokenBytes, key, initiatorSeal, false)
	require.NoError(t, err)
	assert.Equal(t, payload, decrypted)
}

func TestSealedWrapToken_MSKILE_EC_RRC(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte("test payload")

	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, initiatorSeal, 0, 0, 16)
	require.NoError(t, err)

	// Verify EC and RRC values per MS-KILE specification.
	// For AES256-CTS-HMAC-SHA1-96:
	// - EC = 16 (one AES block)
	// - RRC = EC + confounder + checksum = 16 + 16 + 12 = 44
	ec := binary.BigEndian.Uint16(tokenBytes[4:6])
	rrc := binary.BigEndian.Uint16(tokenBytes[6:8])

	assert.Equal(t, uint16(16), ec, "EC should be 16 (one AES block) for MS-KILE compatibility")
	assert.Equal(t, uint16(44), rrc, "RRC should be 44 (EC + confounder + checksum) for MS-KILE compatibility")

	// Verify SignatureLength calculation for MS-WSMV format.
	signatureLen := HdrLen + int(rrc)
	assert.Equal(t, 60, signatureLen, "SignatureLength should be 60 (16 header + 44 RRC)")

	// Verify the helper function works.
	extractedRRC, err := GetSealedTokenRRC(tokenBytes)
	require.NoError(t, err)
	assert.Equal(t, uint16(44), extractedRRC)

	// Verify round-trip still works with the new EC/RRC values.
	decrypted, err := UnwrapSealed(tokenBytes, key, initiatorSeal, false)
	require.NoError(t, err)
	assert.Equal(t, payload, decrypted)
}

func TestSealedWrapToken_Acceptor(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte("response from acceptor")

	// Create a sealed token as acceptor.
	flags := WrapTokenFlagSentByAcceptor

	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, acceptorSeal, flags, 99999, 16)
	require.NoError(t, err)

	// Verify flags.
	assert.Equal(t, WrapTokenFlagSentByAcceptor|WrapTokenFlagSealed, tokenBytes[2])

	// Decrypt expecting from acceptor.
	decrypted, err := UnwrapSealed(tokenBytes, key, acceptorSeal, true)
	require.NoError(t, err)
	assert.Equal(t, payload, decrypted)
}

func TestSealedWrapToken_WithAcceptorSubkey(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte("data with acceptor subkey")

	// Create a sealed token with acceptor subkey flag.
	flags := WrapTokenFlagAcceptorSubkey

	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, initiatorSeal, flags, 1, 16)
	require.NoError(t, err)

	// Verify flags.
	expectedFlags := WrapTokenFlagAcceptorSubkey | WrapTokenFlagSealed
	assert.Equal(t, expectedFlags, tokenBytes[2])

	// Decrypt.
	decrypted, err := UnwrapSealed(tokenBytes, key, initiatorSeal, false)
	require.NoError(t, err)
	assert.Equal(t, payload, decrypted)
}

func TestSealedWrapToken_EmptyPayload(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte{}

	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, initiatorSeal, 0, 0, 16)
	require.NoError(t, err)

	decrypted, err := UnwrapSealed(tokenBytes, key, initiatorSeal, false)
	require.NoError(t, err)
	assert.Equal(t, payload, decrypted)
}

func TestSealedWrapToken_LargePayload(t *testing.T) {
	t.Parallel()

	key := getAES256Key()

	// Create a large payload.
	payload := make([]byte, 64*1024) // 64KB.
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, initiatorSeal, 0, 0, 16)
	require.NoError(t, err)

	decrypted, err := UnwrapSealed(tokenBytes, key, initiatorSeal, false)
	require.NoError(t, err)
	assert.Equal(t, payload, decrypted)
}

func TestSealedWrapToken_WrongKey(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte("secret data")

	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, initiatorSeal, 0, 0, 16)
	require.NoError(t, err)

	// Try to decrypt with wrong key.
	wrongKey := getAES256Key()
	wrongKey.KeyValue[0] = 0xFF

	_, err = UnwrapSealed(tokenBytes, wrongKey, initiatorSeal, false)
	assert.Error(t, err)
}

func TestSealedWrapToken_WrongKeyUsage(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte("test data")

	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, initiatorSeal, 0, 0, 16)
	require.NoError(t, err)

	// Try to decrypt with wrong key usage.
	_, err = UnwrapSealed(tokenBytes, key, acceptorSeal, false)
	assert.Error(t, err)
}

func TestSealedWrapToken_WrongDirection(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte("test data")

	// Create token from initiator.
	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, initiatorSeal, 0, 0, 16)
	require.NoError(t, err)

	// Try to unwrap expecting from acceptor.
	_, err = UnwrapSealed(tokenBytes, key, initiatorSeal, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected acceptor flag")
}

func TestSealedWrapToken_TruncatedToken(t *testing.T) {
	t.Parallel()

	key := getAES256Key()

	// Token shorter than header.
	_, err := UnwrapSealed([]byte{0x05, 0x04}, key, initiatorSeal, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token too short")
}

func TestSealedWrapToken_NotSealed(t *testing.T) {
	t.Parallel()

	key := getAES256Key()

	// Create a sign-only token.
	signOnlyToken, err := NewInitiatorWrapToken([]byte{0x01, 0x02}, getSessionKey())
	require.NoError(t, err)

	tokenBytes, err := signOnlyToken.Marshal()
	require.NoError(t, err)

	// Try to unwrap as sealed.
	_, err = UnwrapSealed(tokenBytes, key, initiatorSeal, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not sealed")
}

func TestSealedWrapToken_CorruptedCiphertext(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte("test data")

	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, initiatorSeal, 0, 0, 16)
	require.NoError(t, err)

	// Corrupt the ciphertext.
	tokenBytes[HdrLen] ^= 0xFF

	_, err = UnwrapSealed(tokenBytes, key, initiatorSeal, false)
	assert.Error(t, err)
}

func TestIsSealed(t *testing.T) {
	t.Parallel()

	// Sign-only token.
	signOnly := &WrapToken{Flags: 0x00}
	assert.False(t, signOnly.IsSealed())

	// Sealed token.
	sealed := &WrapToken{Flags: WrapTokenFlagSealed}
	assert.True(t, sealed.IsSealed())

	// Sealed from acceptor.
	sealedFromAcceptor := &WrapToken{Flags: WrapTokenFlagSealed | WrapTokenFlagSentByAcceptor}
	assert.True(t, sealedFromAcceptor.IsSealed())
}

func TestRotateRight(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		n        int
		expected []byte
	}{
		{
			name:     "no rotation",
			input:    []byte{1, 2, 3, 4, 5},
			n:        0,
			expected: []byte{1, 2, 3, 4, 5},
		},
		{
			name:     "rotate by 1",
			input:    []byte{1, 2, 3, 4, 5},
			n:        1,
			expected: []byte{5, 1, 2, 3, 4},
		},
		{
			name:     "rotate by 2",
			input:    []byte{1, 2, 3, 4, 5},
			n:        2,
			expected: []byte{4, 5, 1, 2, 3},
		},
		{
			name:     "rotate by length (full cycle)",
			input:    []byte{1, 2, 3, 4, 5},
			n:        5,
			expected: []byte{1, 2, 3, 4, 5},
		},
		{
			name:     "rotate by more than length",
			input:    []byte{1, 2, 3, 4, 5},
			n:        7,
			expected: []byte{4, 5, 1, 2, 3}, // Same as 7 % 5 = 2.
		},
		{
			name:     "empty slice",
			input:    []byte{},
			n:        5,
			expected: []byte{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, len(tc.input))
			copy(data, tc.input)
			rotateRight(data, tc.n)
			assert.Equal(t, tc.expected, data)
		})
	}
}

func TestRotateLeft(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		n        int
		expected []byte
	}{
		{
			name:     "no rotation",
			input:    []byte{1, 2, 3, 4, 5},
			n:        0,
			expected: []byte{1, 2, 3, 4, 5},
		},
		{
			name:     "rotate by 1",
			input:    []byte{1, 2, 3, 4, 5},
			n:        1,
			expected: []byte{2, 3, 4, 5, 1},
		},
		{
			name:     "rotate by 2",
			input:    []byte{1, 2, 3, 4, 5},
			n:        2,
			expected: []byte{3, 4, 5, 1, 2},
		},
		{
			name:     "rotate by length (full cycle)",
			input:    []byte{1, 2, 3, 4, 5},
			n:        5,
			expected: []byte{1, 2, 3, 4, 5},
		},
		{
			name:     "rotate by more than length",
			input:    []byte{1, 2, 3, 4, 5},
			n:        7,
			expected: []byte{3, 4, 5, 1, 2}, // Same as 7 % 5 = 2.
		},
		{
			name:     "empty slice",
			input:    []byte{},
			n:        5,
			expected: []byte{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, len(tc.input))
			copy(data, tc.input)
			rotateLeft(data, tc.n)
			assert.Equal(t, tc.expected, data)
		})
	}
}

func TestRotateLeftRightInverse(t *testing.T) {
	t.Parallel()

	// Rotating left by n and then right by n should give original.
	original := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for n := 0; n <= len(original)+2; n++ {
		data := make([]byte, len(original))
		copy(data, original)

		rotateRight(data, n)
		rotateLeft(data, n)
		assert.Equal(t, original, data, "rotateRight then rotateLeft with n=%d", n)
	}

	// Rotating right by n and then left by n should also give original.
	for n := 0; n <= len(original)+2; n++ {
		data := make([]byte, len(original))
		copy(data, original)

		rotateLeft(data, n)
		rotateRight(data, n)
		assert.Equal(t, original, data, "rotateLeft then rotateRight with n=%d", n)
	}
}

// Tests for auto-detect Unwrap function.

func TestUnwrap_AutoDetectSealed(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte("sealed message for auto-detect")

	// Create a sealed token.
	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, initiatorSeal, 0, 42, 16)
	require.NoError(t, err)

	// Use auto-detect Unwrap.
	result, err := Unwrap(tokenBytes, key, initiatorSeal, false)
	require.NoError(t, err)

	assert.Equal(t, payload, result.Payload)
	assert.True(t, result.Sealed, "should detect as sealed")
	assert.Equal(t, uint64(42), result.SeqNum)
}

func TestUnwrap_AutoDetectSignOnly(t *testing.T) {
	t.Parallel()

	key := getSessionKey()
	payload := []byte{0x01, 0x01, 0x00, 0x00}

	// Create a sign-only token.
	token, err := NewInitiatorWrapToken(payload, key)
	require.NoError(t, err)

	tokenBytes, err := token.Marshal()
	require.NoError(t, err)

	// Use auto-detect Unwrap.
	result, err := Unwrap(tokenBytes, key, initiatorSeal, false)
	require.NoError(t, err)

	assert.Equal(t, payload, result.Payload)
	assert.False(t, result.Sealed, "should detect as sign-only")
	assert.Equal(t, uint64(0), result.SeqNum)
}

func TestUnwrap_AutoDetectFromAcceptor(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte("response from server")

	// Create a sealed token from acceptor.
	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, acceptorSeal, WrapTokenFlagSentByAcceptor, 100, 16)
	require.NoError(t, err)

	// Use auto-detect Unwrap expecting from acceptor.
	result, err := Unwrap(tokenBytes, key, acceptorSeal, true)
	require.NoError(t, err)

	assert.Equal(t, payload, result.Payload)
	assert.True(t, result.Sealed)
	assert.Equal(t, uint64(100), result.SeqNum)
}

func TestUnwrap_AutoDetectWrongDirection(t *testing.T) {
	t.Parallel()

	key := getAES256Key()
	payload := []byte("test")

	// Create a sealed token from initiator.
	tokenBytes, err := NewSealedWrapTokenDCE(payload, key, initiatorSeal, 0, 0, 16)
	require.NoError(t, err)

	// Try to unwrap expecting from acceptor - should fail.
	_, err = Unwrap(tokenBytes, key, initiatorSeal, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected acceptor flag")
}

func TestUnwrap_TooShort(t *testing.T) {
	t.Parallel()

	key := getAES256Key()

	_, err := Unwrap([]byte{0x05}, key, initiatorSeal, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token too short")
}

func TestUnwrap_WrongTokenID(t *testing.T) {
	t.Parallel()

	key := getAES256Key()

	// Invalid token ID.
	badToken := make([]byte, HdrLen)
	badToken[0] = 0x00
	badToken[1] = 0x00

	_, err := Unwrap(badToken, key, initiatorSeal, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "wrong Token ID")
}
