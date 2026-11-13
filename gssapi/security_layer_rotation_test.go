package gssapi

import (
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
)

func TestSecurityLayerSessionRotateTrailerSealed(t *testing.T) {
	key := testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)
	message := []byte("a message carried apart from its header")

	initiator, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0, RotateTrailer(), InitialSendSequenceNumber(7))
	require.NoError(t, err)

	token, err := initiator.Wrap(message)
	require.NoError(t, err)

	assert.Equal(t, uint16(0), binary.BigEndian.Uint16(token[4:6]))
	assert.Equal(t, uint16(28), binary.BigEndian.Uint16(token[6:8]))
	assert.Len(t, token, HdrLen+16+len(message)+HdrLen+12)

	plaintext := decryptRotatedToken(t, token, 28, keyusage.GSSAPI_INITIATOR_SEAL)
	assert.Equal(t, message, plaintext[:len(message)])
	assert.Equal(t, wrapTokenHeader(FlagSealed, 0, 0, 7), plaintext[len(message):])

	acceptor, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0)
	require.NoError(t, err)

	got, err := acceptor.Unwrap(token)
	require.NoError(t, err)
	assert.Equal(t, message, got)
}

func TestSecurityLayerSessionRotateTrailerSigned(t *testing.T) {
	key := testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)
	message := []byte("an integrity protected message")

	initiator, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0, RotateTrailer())
	require.NoError(t, err)

	token, err := initiator.Wrap(message)
	require.NoError(t, err)

	assert.Equal(t, uint16(12), binary.BigEndian.Uint16(token[4:6]))
	assert.Equal(t, uint16(12), binary.BigEndian.Uint16(token[6:8]))
	assert.Equal(t, message, token[HdrLen+12:])

	acceptor, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	got, err := acceptor.Unwrap(token)
	require.NoError(t, err)
	assert.Equal(t, message, got)
}

func TestSecurityLayerSessionDCEStyle(t *testing.T) {
	key := testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)
	message := []byte("a DCE style message")

	initiator, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0, DCEStyle())
	require.NoError(t, err)

	acceptor, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0, DCEStyle())
	require.NoError(t, err)

	token, err := initiator.Wrap(message)
	require.NoError(t, err)

	assert.Equal(t, uint16(16), binary.BigEndian.Uint16(token[4:6]))
	assert.Equal(t, uint16(28), binary.BigEndian.Uint16(token[6:8]))
	assert.Len(t, token, HdrLen+16+len(message)+16+HdrLen+12)

	plaintext := decryptRotatedToken(t, token, 44, keyusage.GSSAPI_INITIATOR_SEAL)
	assert.Equal(t, message, plaintext[:len(message)])
	assert.Equal(t, make([]byte, 16), plaintext[len(message):len(message)+16])
	assert.Equal(t, wrapTokenHeader(FlagSealed, 16, 0, 0), plaintext[len(message)+16:])

	got, err := acceptor.Unwrap(token)
	require.NoError(t, err)
	assert.Equal(t, message, got)

	reply, err := acceptor.Wrap(message)
	require.NoError(t, err)

	got, err = initiator.Unwrap(reply)
	require.NoError(t, err)
	assert.Equal(t, message, got)

	t.Run("ShouldNotBeReadByASessionThatIsNotDCEStyle", func(t *testing.T) {
		plain, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0)
		require.NoError(t, err)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		_, err = plain.Unwrap(token)
		assert.Error(t, err)
	})
}

func TestSecurityLayerSessionDCEStyleEtypes(t *testing.T) {
	for _, id := range securityLayerEtypes {
		t.Run(strconv.Itoa(int(id)), func(t *testing.T) {
			key := testSecurityLayerKey(t, id)

			initiator, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0, DCEStyle())
			require.NoError(t, err)

			acceptor, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0, DCEStyle())
			require.NoError(t, err)

			for _, n := range []int{0, 1, 7, 8, 16, 33} {
				message := make([]byte, n)
				for i := range message {
					message[i] = byte(i)
				}

				token, err := initiator.Wrap(message)
				require.NoError(t, err)
				assert.NotZero(t, binary.BigEndian.Uint16(token[4:6]))

				got, err := acceptor.Unwrap(token)
				require.NoError(t, err)
				assert.Equal(t, message, got)
			}
		})
	}
}

func TestSecurityLayerSessionDCEStyleWrapSizeLimit(t *testing.T) {
	key := testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)

	s, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 1024, DCEStyle())
	require.NoError(t, err)

	token, err := s.Wrap(make([]byte, s.WrapSizeLimit()))
	require.NoError(t, err)
	assert.LessOrEqual(t, len(token), 1024)
}

func TestSecurityLayerSessionAcceptorSubkey(t *testing.T) {
	key := testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)
	message := []byte("protected with the acceptor subkey")

	for _, layer := range []SecurityLayer{SecurityLayerIntegrity, SecurityLayerConfidentiality} {
		t.Run(layer.String(), func(t *testing.T) {
			initiator, err := NewSecurityLayerSession(key, layer, true, 0, AcceptorSubkey())
			require.NoError(t, err)

			acceptor, err := NewSecurityLayerSession(key, layer, false, 0, AcceptorSubkey())
			require.NoError(t, err)

			token, err := initiator.Wrap(message)
			require.NoError(t, err)
			assert.Equal(t, FlagAcceptorSubkey, token[2]&FlagAcceptorSubkey)

			got, err := acceptor.Unwrap(token)
			require.NoError(t, err)
			assert.Equal(t, message, got)

			reply, err := acceptor.Wrap(message)
			require.NoError(t, err)
			assert.Equal(t, FlagAcceptorSubkey|FlagSentByAcceptor, reply[2]&(FlagAcceptorSubkey|FlagSentByAcceptor))

			got, err = initiator.Unwrap(reply)
			require.NoError(t, err)
			assert.Equal(t, message, got)
		})
	}

	t.Run("ShouldRejectATokenWithoutTheFlag", func(t *testing.T) {
		initiator, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
		require.NoError(t, err)

		acceptor, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0, AcceptorSubkey())
		require.NoError(t, err)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		_, err = acceptor.Unwrap(token)
		assert.EqualError(t, err, "acceptor subkey flag is not set: the token is not protected with the acceptor's subkey this session holds")
	})

	t.Run("ShouldRejectATokenWithTheFlag", func(t *testing.T) {
		initiator, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0, AcceptorSubkey())
		require.NoError(t, err)

		acceptor, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0)
		require.NoError(t, err)

		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		_, err = acceptor.Unwrap(token)
		assert.EqualError(t, err, "unexpected acceptor subkey flag is set: the token is protected with an acceptor subkey this session does not hold")
	})
}

func decryptRotatedToken(t *testing.T, token []byte, rotation int, usage uint32) []byte {
	t.Helper()

	data := token[HdrLen:]
	ciphertext := append(append([]byte{}, data[rotation:]...), data[:rotation]...)

	et, err := crypto.GetEType(etypeID.AES256_CTS_HMAC_SHA1_96)
	require.NoError(t, err)

	plaintext, err := et.DecryptMessage(testSecurityLayerKey(t, etypeID.AES256_CTS_HMAC_SHA1_96).KeyValue, ciphertext, usage)
	require.NoError(t, err)

	return plaintext
}
