package gssapi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

// securityLayerEtypes are the encryption types a security layer session is exercised against. They cover the
// ciphertext stealing types, the stream cipher and the one type whose message block size makes filler necessary.
var securityLayerEtypes = []int32{
	etypeID.AES128_CTS_HMAC_SHA1_96,
	etypeID.AES256_CTS_HMAC_SHA1_96,
	etypeID.AES128_CTS_HMAC_SHA256_128,
	// AES256_CTS_HMAC_SHA384_192 is omitted because crypto.Aes256CtsHmacSha384192.GetKeyByteSize reports the 24
	// byte truncated hash size rather than the 32 byte key size of RFC 8009 section 5, so the encryption type
	// cannot encrypt or decrypt anything at all.
	etypeID.DES3_CBC_SHA1_KD,
	etypeID.RC4_HMAC,
}

func testSecurityLayerKey(t *testing.T, id int32) types.EncryptionKey {
	t.Helper()

	et, err := crypto.GetEtype(id)
	require.NoError(t, err)

	kv := make([]byte, et.GetKeyByteSize())
	for i := range kv {
		kv[i] = byte(i + 1)
	}

	return types.EncryptionKey{KeyType: id, KeyValue: et.RandomToKey(kv)}
}

// testSecurityLayerPair returns the initiator and acceptor sessions of a context sharing a session key.
func testSecurityLayerPair(t *testing.T, id int32, layer SecurityLayer, maxBufferSize int) (initiator, acceptor *SecurityLayerSession) {
	t.Helper()

	key := testSecurityLayerKey(t, id)

	initiator, err := NewSecurityLayerSession(key, layer, true, maxBufferSize)
	require.NoError(t, err)

	acceptor, err = NewSecurityLayerSession(key, layer, false, maxBufferSize)
	require.NoError(t, err)

	return initiator, acceptor
}

func TestNewSecurityLayerSession(t *testing.T) {
	key := testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)

	t.Run("ShouldRejectAnUnknownLayer", func(t *testing.T) {
		_, err := NewSecurityLayerSession(key, SecurityLayer(3), true, 0)
		assert.EqualError(t, err, "invalid security layer: 3")
	})

	t.Run("ShouldRejectANegativeMaximumBufferSize", func(t *testing.T) {
		_, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, -1)
		assert.EqualError(t, err, "invalid maximum buffer size: -1")
	})

	t.Run("ShouldRejectAnUnknownEncryptionType", func(t *testing.T) {
		_, err := NewSecurityLayerSession(types.EncryptionKey{KeyType: 9999}, SecurityLayerIntegrity, true, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not get the encryption type of the session key")
	})

	t.Run("ShouldRejectAMaximumBufferSizeSmallerThanTheTokenOverhead", func(t *testing.T) {
		_, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 16)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maximum buffer size 16 is too small")
	})

	t.Run("ShouldReportTheLayerAndBufferSize", func(t *testing.T) {
		s, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 65536)
		require.NoError(t, err)

		assert.Equal(t, SecurityLayerIntegrity, s.Layer())
		assert.Equal(t, 65536, s.MaxBufferSize())
		assert.Equal(t, 65536-HdrLen-12, s.WrapSizeLimit())
	})

	t.Run("ShouldNotLimitTheWrapSizeWithoutABufferSize", func(t *testing.T) {
		s, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
		require.NoError(t, err)

		assert.Equal(t, 0, s.WrapSizeLimit())
	})
}

func TestSecurityLayerValues(t *testing.T) {
	// RFC 4752 section 3.1 defines the security layer bit-mask.
	assert.Equal(t, SecurityLayer(1), SecurityLayerNone)
	assert.Equal(t, SecurityLayer(2), SecurityLayerIntegrity)
	assert.Equal(t, SecurityLayer(4), SecurityLayerConfidentiality)

	assert.Equal(t, "none", SecurityLayerNone.String())
	assert.Equal(t, "integrity", SecurityLayerIntegrity.String())
	assert.Equal(t, "confidentiality", SecurityLayerConfidentiality.String())
	assert.Equal(t, "unknown security layer (3)", SecurityLayer(3).String())
}

func TestSecurityLayerSessionNone(t *testing.T) {
	initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerNone, 0)

	message := []byte("no security layer was negotiated")

	wrapped, err := initiator.Wrap(message)
	require.NoError(t, err)
	assert.Equal(t, message, wrapped)

	unwrapped, err := acceptor.Unwrap(wrapped)
	require.NoError(t, err)
	assert.Equal(t, message, unwrapped)

	_, err = initiator.WrapWithSASLFraming(message)
	assert.EqualError(t, err, "SASL framing is not applied when no security layer has been negotiated")

	_, err = acceptor.UnwrapFromSASLFraming(bytes.NewReader(nil))
	assert.EqualError(t, err, "SASL framing is not applied when no security layer has been negotiated")
}

func TestSecurityLayerSessionRoundTrip(t *testing.T) {
	messages := map[string][]byte{
		"Empty":     {},
		"Nil":       nil,
		"Short":     []byte("a"),
		"Text":      []byte("the quick brown fox jumps over the lazy dog"),
		"BlockSize": bytes.Repeat([]byte{0xAB}, 16),
		"Long":      bytes.Repeat([]byte("0123456789"), 1000),
	}

	for _, layer := range []SecurityLayer{SecurityLayerIntegrity, SecurityLayerConfidentiality} {
		t.Run(layer.String(), func(t *testing.T) {
			for _, id := range securityLayerEtypes {
				t.Run(strconv.Itoa(int(id)), func(t *testing.T) {
					for name, message := range messages {
						t.Run(name, func(t *testing.T) {
							initiator, acceptor := testSecurityLayerPair(t, id, layer, 0)

							// An unwrapped message is always a slice, never nil.
							want := message
							if want == nil {
								want = []byte{}
							}

							token, err := initiator.Wrap(message)
							require.NoError(t, err)

							// The message must not appear in the clear once it is sealed. Messages short enough
							// to turn up in the ciphertext by chance are not worth checking.
							if layer == SecurityLayerConfidentiality && len(message) >= 8 {
								assert.NotContains(t, string(token), string(message))
							}

							got, err := acceptor.Unwrap(token)
							require.NoError(t, err)
							assert.Equal(t, want, got, "the unwrapped message must match the original")

							// The acceptor's replies must be readable by the initiator.
							reply, err := acceptor.Wrap(message)
							require.NoError(t, err)

							got, err = initiator.Unwrap(reply)
							require.NoError(t, err)
							assert.Equal(t, want, got)
						})
					}
				})
			}
		})
	}
}

func TestSecurityLayerSessionTokenFormat(t *testing.T) {
	message := []byte("a message to be wrapped")

	t.Run("Integrity", func(t *testing.T) {
		initiator, _ := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		assert.Equal(t, []byte{0x05, 0x04}, token[0:2], "RFC 4121 section 4.2.6.2 token identifier")
		assert.Equal(t, byte(0x00), token[2], "an initiator sets neither the acceptor nor the sealed flag")
		assert.Equal(t, FillerByte, token[3])
		// RFC 4121 section 4.2.3: without confidentiality the EC field holds the length of the trailing checksum.
		assert.Equal(t, uint16(12), binary.BigEndian.Uint16(token[4:6]))
		assert.Equal(t, uint16(0), binary.BigEndian.Uint16(token[6:8]), "RRC")
		assert.Equal(t, uint64(0), binary.BigEndian.Uint64(token[8:16]), "the first sequence number")

		// The payload is carried in plaintext followed by the checksum.
		require.Len(t, token, HdrLen+len(message)+12)
		assert.Equal(t, message, token[HdrLen:HdrLen+len(message)])
	})

	t.Run("Confidentiality", func(t *testing.T) {
		initiator, _ := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerConfidentiality, 0)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		assert.Equal(t, []byte{0x05, 0x04}, token[0:2])
		assert.Equal(t, FlagSealed, token[2], "an initiator sealing a token sets only the sealed flag")
		assert.Equal(t, FillerByte, token[3])
		// RFC 4121 section 4.2.3: with confidentiality the EC field holds the length of the filler, which a
		// ciphertext stealing encryption type never needs.
		assert.Equal(t, uint16(0), binary.BigEndian.Uint16(token[4:6]))
		assert.Equal(t, uint16(0), binary.BigEndian.Uint16(token[6:8]), "RRC")

		// header | encrypt(message | filler | header) with a 16 byte confounder and a 12 byte integrity hash.
		assert.Len(t, token, HdrLen+16+len(message)+HdrLen+12)
	})

	t.Run("Acceptor", func(t *testing.T) {
		_, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		token, err := acceptor.Wrap(message)
		require.NoError(t, err)

		assert.Equal(t, FlagSentByAcceptor, token[2])
	})
}

// TestSecurityLayerSessionFillerRemovesResidue asserts the requirement of RFC 4121 section 4.2.4 that no
// crypto-system residue is present after decryption, for the one encryption type that pads.
func TestSecurityLayerSessionFillerRemovesResidue(t *testing.T) {
	for messageLen := range 32 {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.DES3_CBC_SHA1_KD, SecurityLayerConfidentiality, 0)

		message := bytes.Repeat([]byte{0xCD}, messageLen)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		// The filler is recorded in the EC field and aligns the plaintext to the 8 byte message block size.
		ec := int(binary.BigEndian.Uint16(token[4:6]))
		assert.Equal(t, 0, (8+messageLen+ec+HdrLen)%8, "message of %d bytes with %d bytes of filler", messageLen, ec)

		got, err := acceptor.Unwrap(token)
		require.NoError(t, err)
		assert.Equal(t, message, got, "message of %d bytes must survive with no residue", messageLen)
	}
}

func TestSecurityLayerSessionSequenceNumbers(t *testing.T) {
	t.Run("ShouldIncrementPerToken", func(t *testing.T) {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		for i := range uint64(4) {
			token, err := initiator.Wrap([]byte("message"))
			require.NoError(t, err)

			assert.Equal(t, i, binary.BigEndian.Uint64(token[8:16]))

			_, err = acceptor.Unwrap(token)
			require.NoError(t, err)
		}
	})

	t.Run("ShouldRejectAReplayedToken", func(t *testing.T) {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerConfidentiality, 0)

		token, err := initiator.Wrap([]byte("message"))
		require.NoError(t, err)

		_, err = acceptor.Unwrap(token)
		require.NoError(t, err)

		_, err = acceptor.Unwrap(token)
		assert.EqualError(t, err, "wrap token sequence number 0 is out of sequence, expected 1")
	})

	t.Run("ShouldRejectAReorderedToken", func(t *testing.T) {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		first, err := initiator.Wrap([]byte("first"))
		require.NoError(t, err)

		second, err := initiator.Wrap([]byte("second"))
		require.NoError(t, err)

		third, err := initiator.Wrap([]byte("third"))
		require.NoError(t, err)

		_, err = acceptor.Unwrap(first)
		require.NoError(t, err)

		_, err = acceptor.Unwrap(third)
		assert.EqualError(t, err, "wrap token sequence number 2 is out of sequence, expected 1")

		_, err = acceptor.Unwrap(second)
		require.NoError(t, err)
	})

	t.Run("ShouldAdoptTheFirstSequenceNumberReceived", func(t *testing.T) {
		key := testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)

		initiator, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0, InitialSendSequenceNumber(1234))
		require.NoError(t, err)

		acceptor, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
		require.NoError(t, err)

		token, err := initiator.Wrap([]byte("message"))
		require.NoError(t, err)
		assert.Equal(t, uint64(1234), binary.BigEndian.Uint64(token[8:16]))

		_, err = acceptor.Unwrap(token)
		require.NoError(t, err)

		// Having adopted 1234 the acceptor now requires the token that follows it.
		token, err = initiator.Wrap([]byte("message"))
		require.NoError(t, err)

		_, err = acceptor.Unwrap(token)
		require.NoError(t, err)
	})

	t.Run("ShouldRequireTheConfiguredSequenceNumber", func(t *testing.T) {
		key := testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)

		initiator, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
		require.NoError(t, err)

		acceptor, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0, InitialReceiveSequenceNumber(7))
		require.NoError(t, err)

		token, err := initiator.Wrap([]byte("message"))
		require.NoError(t, err)

		_, err = acceptor.Unwrap(token)
		assert.EqualError(t, err, "wrap token sequence number 0 is out of sequence, expected 7")
	})
}

func TestSecurityLayerSessionUnwrapRejections(t *testing.T) {
	message := []byte("a message to be wrapped")

	t.Run("ShouldRejectAShortToken", func(t *testing.T) {
		_, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		_, err := acceptor.Unwrap([]byte{0x05, 0x04})
		assert.EqualError(t, err, "wrap token of 2 bytes is shorter than the 16 byte header")
	})

	t.Run("ShouldRejectAWrongTokenID", func(t *testing.T) {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		token[1] = 0x01

		_, err = acceptor.Unwrap(token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wrong Token ID")
	})

	t.Run("ShouldRejectAWrongFillerByte", func(t *testing.T) {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		token[3] = 0x00

		_, err = acceptor.Unwrap(token)
		assert.EqualError(t, err, "unexpected filler byte: expecting 0xFF, was 00")
	})

	t.Run("ShouldRejectATokenReflectedBackToItsSender", func(t *testing.T) {
		initiator, _ := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerConfidentiality, 0)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		_, err = initiator.Unwrap(token)
		assert.EqualError(t, err, "expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
	})

	t.Run("ShouldRejectAnAcceptorTokenSentToAnAcceptor", func(t *testing.T) {
		_, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		token, err := acceptor.Wrap(message)
		require.NoError(t, err)

		_, err = acceptor.Unwrap(token)
		assert.EqualError(t, err, "unexpected acceptor flag is set: not expecting a token from the acceptor")
	})

	t.Run("ShouldRejectAnUnsealedTokenWhenConfidentialityWasNegotiated", func(t *testing.T) {
		key := testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)

		initiator, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
		require.NoError(t, err)

		acceptor, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0)
		require.NoError(t, err)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		_, err = acceptor.Unwrap(token)
		assert.EqualError(t, err, "wrap token does not match the negotiated confidentiality security layer: sealed flag is false")
	})

	t.Run("ShouldRejectASealedTokenWhenIntegrityWasNegotiated", func(t *testing.T) {
		key := testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)

		initiator, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
		require.NoError(t, err)

		acceptor, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
		require.NoError(t, err)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		_, err = acceptor.Unwrap(token)
		assert.EqualError(t, err, "wrap token does not match the negotiated integrity security layer: sealed flag is true")
	})

	t.Run("ShouldRejectATamperedIntegrityPayload", func(t *testing.T) {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		token[HdrLen] ^= 0xFF

		_, err = acceptor.Unwrap(token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})

	t.Run("ShouldRejectATamperedChecksum", func(t *testing.T) {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		token[len(token)-1] ^= 0xFF

		_, err = acceptor.Unwrap(token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})

	t.Run("ShouldRejectAnInconsistentChecksumLength", func(t *testing.T) {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		binary.BigEndian.PutUint16(token[4:6], uint16(len(token)))

		_, err = acceptor.Unwrap(token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "inconsistent checksum length")
	})

	t.Run("ShouldRejectATamperedCiphertext", func(t *testing.T) {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerConfidentiality, 0)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		token[HdrLen] ^= 0xFF

		_, err = acceptor.Unwrap(token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not decrypt the wrap token payload")
	})

	t.Run("ShouldRejectAShortCiphertext", func(t *testing.T) {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerConfidentiality, 0)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		_, err = acceptor.Unwrap(token[:HdrLen+8])
		assert.EqualError(t, err, "wrap token payload of 8 bytes is too short to be decrypted, expected more than 28")
	})

	// The header the sender encrypted with the message binds the message to the header on the wire, so a header
	// altered in flight must be caught even though the ciphertext itself is untouched.
	t.Run("ShouldRejectATamperedSealedHeader", func(t *testing.T) {
		initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerConfidentiality, 0)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		token[2] |= FlagAcceptorSubkey

		_, err = acceptor.Unwrap(token)
		assert.EqualError(t, err, "wrap token header does not match the copy of it encrypted with the payload")
	})

	t.Run("ShouldRejectATokenLargerThanTheMaximumBufferSize", func(t *testing.T) {
		key := testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)

		initiator, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
		require.NoError(t, err)

		acceptor, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 64)
		require.NoError(t, err)

		token, err := initiator.Wrap(bytes.Repeat([]byte{0x01}, 128))
		require.NoError(t, err)

		_, err = acceptor.Unwrap(token)
		assert.EqualError(t, err, "wrap token of 156 bytes exceeds the maximum buffer size of 64 bytes")
	})
}

func TestSecurityLayerSessionWrapMaxBufferSize(t *testing.T) {
	initiator, _ := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 64)

	// A message of exactly the wrap size limit fits.
	token, err := initiator.Wrap(bytes.Repeat([]byte{0x01}, initiator.WrapSizeLimit()))
	require.NoError(t, err)
	assert.Len(t, token, 64)

	_, err = initiator.Wrap(bytes.Repeat([]byte{0x01}, initiator.WrapSizeLimit()+1))
	assert.EqualError(t, err, "wrap token of 65 bytes exceeds the maximum buffer size of 64 bytes")
}

// TestSecurityLayerSessionRotatedToken asserts that a token rotated by the RRC field can be read, which RFC 4121
// section 4.2.5 requires of a receiver for any rotation count, including one longer than the token data.
func TestSecurityLayerSessionRotatedToken(t *testing.T) {
	for _, layer := range []SecurityLayer{SecurityLayerIntegrity, SecurityLayerConfidentiality} {
		t.Run(layer.String(), func(t *testing.T) {
			message := []byte("a message that will be rotated")

			for _, rrc := range []uint16{0, 1, 12, 28, 41, 4096, 65535} {
				initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, layer, 0)

				token, err := initiator.Wrap(message)
				require.NoError(t, err)

				rotated := rotateSecurityLayerToken(t, token, rrc)

				got, err := acceptor.Unwrap(rotated)
				require.NoError(t, err, "rotation count %d", rrc)
				assert.Equal(t, message, got, "rotation count %d", rrc)
			}
		})
	}
}

// rotateSecurityLayerToken rotates the data of a wrap token to the right by rrc octets and records the count in the
// RRC field, as a sender using the in place encryption of SSPI would.
func rotateSecurityLayerToken(t *testing.T, token []byte, rrc uint16) []byte {
	t.Helper()

	data := token[HdrLen:]

	rotated := make([]byte, len(token))
	copy(rotated, token[:HdrLen])
	binary.BigEndian.PutUint16(rotated[6:8], rrc)

	if len(data) == 0 {
		return rotated
	}

	n := int(rrc) % len(data)
	copy(rotated[HdrLen:], data[len(data)-n:])
	copy(rotated[HdrLen+n:], data[:len(data)-n])

	return rotated
}

func TestSecurityLayerSessionUnrotate(t *testing.T) {
	// The example of RFC 4121 section 4.2.5.
	data := []byte("aabbccddeeffgghh")
	rotated := []byte("ffgghhaabbccddee")

	assert.Equal(t, data, unrotate(rotated, 6))
	assert.Equal(t, data, unrotate(data, 0))
	assert.Equal(t, data, unrotate(rotated, 6+uint16(len(data))*2), "a rotation count longer than the data")
	assert.Empty(t, unrotate([]byte{}, 9))
}

func TestSecurityLayerSessionSASLFraming(t *testing.T) {
	initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerConfidentiality, 0)

	message := []byte("a message carried in a SASL buffer")

	frame, err := initiator.WrapWithSASLFraming(message)
	require.NoError(t, err)

	// RFC 4422 section 3.7: a four octet length in network byte order that excludes itself.
	require.Greater(t, len(frame), SASLFrameHeaderLen)
	assert.Equal(t, uint32(len(frame)-SASLFrameHeaderLen), binary.BigEndian.Uint32(frame[:SASLFrameHeaderLen]))

	r := bytes.NewReader(frame)

	got, err := acceptor.UnwrapFromSASLFraming(r)
	require.NoError(t, err)
	assert.Equal(t, message, got)
	assert.Zero(t, r.Len(), "the reader must be left at the end of the buffer")
}

func TestSecurityLayerSessionUnwrapFromSASLFramingRejections(t *testing.T) {
	t.Run("ShouldRejectATruncatedLength", func(t *testing.T) {
		_, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		_, err := acceptor.UnwrapFromSASLFraming(bytes.NewReader([]byte{0x00, 0x00}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not read the SASL buffer length")
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("ShouldRejectATruncatedBuffer", func(t *testing.T) {
		_, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		_, err := acceptor.UnwrapFromSASLFraming(bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x20, 0x05, 0x04}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not read the SASL buffer")
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("ShouldRejectABufferOverTheSessionMaximum", func(t *testing.T) {
		_, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 1024)

		_, err := acceptor.UnwrapFromSASLFraming(bytes.NewReader([]byte{0x00, 0x00, 0x10, 0x00}))
		assert.EqualError(t, err, "SASL buffer of 4096 bytes exceeds the maximum buffer size of 1024 bytes")
	})

	// Without a negotiated maximum a peer could otherwise announce a buffer of up to four gigabytes.
	t.Run("ShouldRejectABufferOverTheDefaultMaximum", func(t *testing.T) {
		_, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

		_, err := acceptor.UnwrapFromSASLFraming(bytes.NewReader([]byte{0xFF, 0xFF, 0xFF, 0xFF}))
		assert.EqualError(t, err, "SASL buffer of 4294967295 bytes exceeds the maximum buffer size of 16777216 bytes")
	})
}

// TestSecurityLayerSessionKeyUsage asserts the key usage values of RFC 4121 section 2 are used for each direction.
func TestSecurityLayerSessionKeyUsage(t *testing.T) {
	initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

	assert.Equal(t, uint32(keyusage.GSSAPI_INITIATOR_SEAL), initiator.keyUsage(true))
	assert.Equal(t, uint32(keyusage.GSSAPI_ACCEPTOR_SEAL), initiator.keyUsage(false))
	assert.Equal(t, uint32(keyusage.GSSAPI_ACCEPTOR_SEAL), acceptor.keyUsage(true))
	assert.Equal(t, uint32(keyusage.GSSAPI_INITIATOR_SEAL), acceptor.keyUsage(false))
}

// securityLayerPipe returns the two ends of an in memory connection protected by a security layer.
func securityLayerPipe(t *testing.T, layer SecurityLayer, maxBufferSize int) (client, server *SecureConn) {
	t.Helper()

	initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, layer, maxBufferSize)

	c, s := net.Pipe()
	t.Cleanup(func() {
		_ = c.Close()
		_ = s.Close()
	})

	return NewSecureConn(c, initiator), NewSecureConn(s, acceptor)
}

func TestSecureConn(t *testing.T) {
	for _, layer := range []SecurityLayer{SecurityLayerNone, SecurityLayerIntegrity, SecurityLayerConfidentiality} {
		t.Run(layer.String(), func(t *testing.T) {
			client, server := securityLayerPipe(t, layer, 0)

			assert.Equal(t, client.LocalAddr(), client.LocalAddr())
			assert.NotNil(t, client.RemoteAddr())
			require.NoError(t, client.SetDeadline(zeroDeadline()))
			require.NoError(t, client.SetReadDeadline(zeroDeadline()))
			require.NoError(t, client.SetWriteDeadline(zeroDeadline()))

			message := []byte("a request travelling over a protected connection")

			errs := make(chan error, 1)

			go func() {
				_, err := client.Write(message)
				errs <- err
			}()

			got := make([]byte, len(message))
			_, err := io.ReadFull(server, got)
			require.NoError(t, err)
			require.NoError(t, <-errs)
			assert.Equal(t, message, got)

			// And in the other direction.
			go func() {
				_, err := server.Write(message)
				errs <- err
			}()

			got = make([]byte, len(message))
			_, err = io.ReadFull(client, got)
			require.NoError(t, err)
			require.NoError(t, <-errs)
			assert.Equal(t, message, got)
		})
	}
}

func TestSecureConnPartialRead(t *testing.T) {
	client, server := securityLayerPipe(t, SecurityLayerConfidentiality, 0)

	message := []byte("0123456789")

	go func() {
		_, _ = client.Write(message)
	}()

	// A read smaller than the buffer must return the remainder on the reads that follow.
	got := make([]byte, 4)

	n, err := server.Read(got)
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, []byte("0123"), got)

	rest := make([]byte, 6)
	_, err = io.ReadFull(server, rest)
	require.NoError(t, err)
	assert.Equal(t, []byte("456789"), rest)
}

// TestSecureConnSplitsLargeWrites asserts that a write longer than the negotiated maximum buffer size is split
// across several buffers rather than producing a token the peer is obliged to reject.
func TestSecureConnSplitsLargeWrites(t *testing.T) {
	const maxBufferSize = 512

	client, server := securityLayerPipe(t, SecurityLayerConfidentiality, maxBufferSize)

	message := bytes.Repeat([]byte("0123456789"), 500)

	go func() {
		n, err := client.Write(message)
		assert.NoError(t, err)
		assert.Equal(t, len(message), n)
	}()

	got := make([]byte, len(message))
	_, err := io.ReadFull(server, got)
	require.NoError(t, err)
	assert.Equal(t, message, got)
}

func TestSecureConnEmptyWrite(t *testing.T) {
	client, _ := securityLayerPipe(t, SecurityLayerIntegrity, 0)

	n, err := client.Write(nil)
	require.NoError(t, err)
	assert.Zero(t, n, "an empty write must not put an empty buffer on the wire")
}

func TestSecureConnReadError(t *testing.T) {
	initiator, _ := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

	conn := NewSecureConn(&errConn{err: errors.New("connection reset")}, initiator)

	_, err := conn.Read(make([]byte, 16))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection reset")

	_, err = conn.Write([]byte("message"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection reset")

	require.NoError(t, conn.Close())
}

func TestSecureConnRejectsTamperedTraffic(t *testing.T) {
	initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

	frame, err := initiator.WrapWithSASLFraming([]byte("a message that will be altered"))
	require.NoError(t, err)

	frame[SASLFrameHeaderLen+HdrLen] ^= 0xFF

	conn := NewSecureConn(&readerConn{r: bytes.NewReader(frame)}, acceptor)

	_, err = conn.Read(make([]byte, 64))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestSecureConnImplementsNetConn(t *testing.T) {
	initiator, _ := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerIntegrity, 0)

	var conn net.Conn = NewSecureConn(&errConn{err: io.EOF}, initiator)
	assert.NotNil(t, conn)
}

// TestSecurityLayerSessionConcurrentWrap asserts a session can be used from several goroutines at once.
func TestSecurityLayerSessionConcurrentWrap(t *testing.T) {
	initiator, acceptor := testSecurityLayerPair(t, etypeID.AES256_CTS_HMAC_SHA1_96, SecurityLayerConfidentiality, 0)

	const n = 64

	tokens := make([][]byte, n)

	var wg sync.WaitGroup

	for i := range n {
		wg.Add(1)

		go func() {
			defer wg.Done()

			token, err := initiator.Wrap([]byte(strings.Repeat("m", i+1)))
			assert.NoError(t, err)

			tokens[i] = token
		}()
	}

	wg.Wait()

	// Every token carries a distinct sequence number, so ordering them by it recovers the order they were
	// produced in and all of them unwrap.
	byteSeq := make(map[uint64][]byte, n)
	for _, token := range tokens {
		require.NotNil(t, token)

		byteSeq[binary.BigEndian.Uint64(token[8:16])] = token
	}

	require.Len(t, byteSeq, n, "each token must carry a distinct sequence number")

	for i := range uint64(n) {
		_, err := acceptor.Unwrap(byteSeq[i])
		require.NoError(t, err, "sequence number %d", i)
	}
}

func zeroDeadline() time.Time {
	return time.Time{}
}

// errConn is a net.Conn that fails every read and write.
type errConn struct {
	net.Conn
	err error
}

func (c *errConn) Read([]byte) (int, error)  { return 0, c.err }
func (c *errConn) Write([]byte) (int, error) { return 0, c.err }
func (c *errConn) Close() error              { return nil }

// readerConn is a net.Conn that reads from a reader and discards writes.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *readerConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *readerConn) Close() error                { return nil }

// TestSecurityLayerSessionInteroperability unwraps and reproduces the integrity protected Wrap tokens captured from
// a kerberized server that the WrapToken tests are built on, so the session is checked against real tokens rather
// than only against itself.
func TestSecurityLayerSessionInteroperability(t *testing.T) {
	fromAcceptor, err := hex.DecodeString(testChallengeFromAcceptor)
	require.NoError(t, err)

	fromInitiator, err := hex.DecodeString(testChallengeReplyFromInitiator)
	require.NoError(t, err)

	payload := []byte{0x01, 0x01, 0x00, 0x00}

	t.Run("ShouldUnwrapATokenFromTheAcceptor", func(t *testing.T) {
		s, err := NewSecurityLayerSession(getSessionKey(), SecurityLayerIntegrity, true, 0)
		require.NoError(t, err)

		got, err := s.Unwrap(fromAcceptor)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("ShouldWrapTheTokenTheInitiatorReplied", func(t *testing.T) {
		s, err := NewSecurityLayerSession(getSessionKey(), SecurityLayerIntegrity, true, 0)
		require.NoError(t, err)

		got, err := s.Wrap(payload)
		require.NoError(t, err)
		assert.Equal(t, fromInitiator, got)
	})

	t.Run("ShouldUnwrapTheTokenTheInitiatorReplied", func(t *testing.T) {
		s, err := NewSecurityLayerSession(getSessionKey(), SecurityLayerIntegrity, false, 0)
		require.NoError(t, err)

		got, err := s.Unwrap(fromInitiator)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})
}
