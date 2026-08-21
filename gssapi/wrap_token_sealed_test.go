package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

func TestSecurityLayerSessionSealedRoundTrip(t *testing.T) {
	t.Parallel()

	key := sealedTestKey(t)

	initiator, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
	require.NoError(t, err)

	acceptor, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0)
	require.NoError(t, err)

	for _, message := range [][]byte{
		[]byte("the quick brown fox"),
		{},
		make([]byte, 4096),
	} {
		token, err := initiator.Wrap(message)
		require.NoError(t, err)

		if len(message) > 0 {
			assert.NotContains(t, string(token), string(message))
		}

		assert.NotZero(t, token[2]&FlagSealed, "the sealed flag should be set")

		out, err := acceptor.Unwrap(token)
		require.NoError(t, err)
		assert.Equal(t, message, out)
	}
}

func TestWrapTokenRefusesASealedToken(t *testing.T) {
	t.Parallel()

	key := sealedTestKey(t)

	s, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
	require.NoError(t, err)

	token, err := s.Wrap([]byte("the quick brown fox"))
	require.NoError(t, err)

	var wt WrapToken

	assert.Error(t, wt.Unmarshal(token, false), "a sealed token must not be parsed as an integrity protected one")
}

func TestWrapTokenUnrotatesTheRotateCount(t *testing.T) {
	t.Parallel()

	key := sealedTestKey(t)

	s, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	token, err := s.Wrap([]byte("the quick brown fox"))
	require.NoError(t, err)

	body := token[HdrLen:]

	for _, rrc := range []uint16{0, 1, 5, uint16(len(body)), uint16(len(body)) + 3, 60000} {
		rotated := append([]byte(nil), token[:HdrLen]...)
		rotated = append(rotated, rotateRight(body, rrc)...)
		rotated[6] = byte(rrc >> 8)
		rotated[7] = byte(rrc)

		var wt WrapToken

		require.NoError(t, wt.Unmarshal(rotated, false), "rrc=%d", rrc)

		ok, err := wt.Verify(key, keyusage.GSSAPI_INITIATOR_SEAL)
		require.NoError(t, err, "rrc=%d", rrc)
		assert.True(t, ok, "rrc=%d", rrc)
		assert.Equal(t, "the quick brown fox", string(wt.Payload), "rrc=%d", rrc)
	}
}

func TestWrapTokenRoundTripsARotatedToken(t *testing.T) {
	t.Parallel()

	key := sealedTestKey(t)

	s, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	token, err := s.Wrap([]byte("the quick brown fox"))
	require.NoError(t, err)

	body := token[HdrLen:]

	rotated := append([]byte(nil), token[:HdrLen]...)
	rotated = append(rotated, rotateRight(body, 5)...)
	rotated[6], rotated[7] = 0, 5

	var wt WrapToken

	require.NoError(t, wt.Unmarshal(rotated, false))
	assert.Equal(t, uint16(5), wt.RRC)

	out, err := wt.Marshal()
	require.NoError(t, err)
	assert.Equal(t, rotated, out)
}

func sealedTestKey(t *testing.T) types.EncryptionKey {
	t.Helper()

	return types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
}

func rotateRight(b []byte, rrc uint16) []byte {
	if len(b) == 0 {
		return b
	}

	n := int(rrc) % len(b)
	out := make([]byte, len(b))
	copy(out[n:], b[:len(b)-n])
	copy(out[:n], b[len(b)-n:])

	return out
}
