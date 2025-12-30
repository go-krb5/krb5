package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/crypto/common"
	"github.com/go-krb5/krb5/crypto/rfc8009"
)

// TestAes128CtsHmacSha256128_StringToKey handles test vectors from RFC 8009 Appendix A.
func TestAes128CtsHmacSha256128_StringToKey(t *testing.T) {
	t.Parallel()

	r, err := hex.DecodeString("10DF9DD783E5BC8ACEA1730E74355F61")
	require.NoError(t, err)

	s := string(r)

	e := &Aes128CtsHmacSha256128{}

	testCases := []struct {
		name       string
		iterations uint32
		phrase     string
		salt       string
		saltp      string
		key        string
	}{
		{"Vector1", 32768, "password", s + "ATHENA.MIT.EDUraeburn", "6165733132382d6374732d686d61632d7368613235362d3132380010df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e", "089bca48b105ea6ea77ca5d2f39dc5e7"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			saltp := rfc8009.GetSaltP(tc.salt, "aes128-cts-hmac-sha256-128")
			assert.Equal(t, tc.saltp, hex.EncodeToString([]byte(saltp)))

			k, err := e.StringToKey(tc.phrase, tc.salt, common.IterationsToS2Kparams(tc.iterations))
			assert.Equal(t, tc.key, hex.EncodeToString(k))
			assert.NoError(t, err)
		})
	}
}

// TestAes128CtsHmacSha256128_DeriveKey handles test vectors from RFC 8009 Appendix A.
func TestAes128CtsHmacSha256128_DeriveKey(t *testing.T) {
	t.Parallel()

	protocolBaseKey, err := hex.DecodeString("3705d96080c17728a0e800eab6e0d23c")
	require.NoError(t, err)

	testUsage := uint32(2)

	e := &Aes128CtsHmacSha256128{}

	k, err := e.DeriveKey(protocolBaseKey, common.GetUsageKc(testUsage))
	require.NoError(t, err)

	assert.Equal(t, "b31a018a48f54776f403e9a396325dc3", hex.EncodeToString(k))

	k, err = e.DeriveKey(protocolBaseKey, common.GetUsageKe(testUsage))
	require.NoError(t, err)

	assert.Equal(t, "9b197dd1e8c5609d6e67c3e37c62c72e", hex.EncodeToString(k))

	k, err = e.DeriveKey(protocolBaseKey, common.GetUsageKi(testUsage))
	require.NoError(t, err)

	assert.Equal(t, "9fda0e56ab2d85e1569a688696c26a6c", hex.EncodeToString(k))
}

// TestAes128CtsHmacSha256128_DeriveKey handles test vectors from RFC 8009 Appendix A.
func TestAes128CtsHmacSha256128_VerifyIntegrity(t *testing.T) {
	t.Parallel()

	protocolBaseKey, err := hex.DecodeString("3705d96080c17728a0e800eab6e0d23c")
	require.NoError(t, err)

	testUsage := uint32(2)

	e := &Aes128CtsHmacSha256128{}

	testCases := []struct {
		name   string
		kc     string
		pt     string
		chksum string
	}{
		{"Vector1", "b31a018a48f54776f403e9a396325dc3", "000102030405060708090a0b0c0d0e0f1011121314", "d78367186643d67b411cba9139fc1dee"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := hex.DecodeString(tc.pt)
			assert.NoError(t, err)

			b, err := e.GetChecksumHash(protocolBaseKey, p, testUsage)
			assert.NoError(t, err)

			assert.Equal(t, tc.chksum, hex.EncodeToString(b))
		})
	}
}

func TestAes128CtsHmacSha256128_Crypto(t *testing.T) {
	t.Parallel()

	protocolBaseKey, err := hex.DecodeString("3705d96080c17728a0e800eab6e0d23c")
	require.NoError(t, err)

	testUsage := uint32(2)

	e := &Aes128CtsHmacSha256128{}

	testCases := []struct {
		name       string
		plain      string
		confounder string
		ke         string
		ki         string
		encrypted  string
		hash       string
		cipher     string
	}{
		{"Vector1", "", "7e5895eaf2672435bad817f545a37148", "9b197dd1e8c5609d6e67c3e37c62c72e", "9fda0e56ab2d85e1569a688696c26a6c", "ef85fb890bb8472f4dab20394dca781d", "ad877eda39d50c870c0d5a0a8e48c718", "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718"},
		{"Vector2", "000102030405", "7bca285e2fd4130fb55b1a5c83bc5b24", "9b197dd1e8c5609d6e67c3e37c62c72e", "9fda0e56ab2d85e1569a688696c26a6c", "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6", "877ce99e247e52d16ed4421dfdf8976c", "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877ce99e247e52d16ed4421dfdf8976c"},
		{"Vector3", "000102030405060708090a0b0c0d0e0f", "56ab21713ff62c0a1457200f6fa9948f", "9b197dd1e8c5609d6e67c3e37c62c72e", "9fda0e56ab2d85e1569a688696c26a6c", "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc2", "95fb4852e7d83e1e7c48c37eebe6b0d3", "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc295fb4852e7d83e1e7c48c37eebe6b0d3"},
		{"Vector4", "000102030405060708090a0b0c0d0e0f1011121314", "a7a4e29a4728ce10664fb64e49ad3fac", "9b197dd1e8c5609d6e67c3e37c62c72e", "9fda0e56ab2d85e1569a688696c26a6c", "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c1", "86b39a413c2f92ca9b8334a287ffcbfc", "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c186b39a413c2f92ca9b8334a287ffcbfc"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := hex.DecodeString(tc.plain)
			require.NoError(t, err)

			b, err := hex.DecodeString(tc.encrypted)
			require.NoError(t, err)

			ke, err := hex.DecodeString(tc.ke)
			require.NoError(t, err)

			cf, err := hex.DecodeString(tc.confounder)
			require.NoError(t, err)

			ct, err := hex.DecodeString(tc.cipher)
			require.NoError(t, err)

			cfm := append(cf, m...)

			_, c, err := e.EncryptData(ke, cfm)
			assert.NoError(t, err)

			assert.Equal(t, tc.encrypted, hex.EncodeToString(c))

			p, err := e.DecryptData(ke, b)
			assert.NoError(t, err)

			p = p[e.GetConfounderByteSize():]

			assert.Equal(t, tc.plain, hex.EncodeToString(p))

			assert.True(t, e.VerifyIntegrity(protocolBaseKey, ct, ct, testUsage))

			_, cm, err := e.EncryptMessage(protocolBaseKey, m, testUsage)
			assert.NoError(t, err)

			dm, err := e.DecryptMessage(protocolBaseKey, cm, testUsage)
			assert.NoError(t, err)

			assert.Equal(t, m, dm)

			ivz := make([]byte, e.GetConfounderByteSize())
			hm := append(ivz, b...)

			mac, err := common.GetIntegrityHash(hm, protocolBaseKey, testUsage, e)
			assert.Equal(t, tc.hash, hex.EncodeToString(mac))
			assert.NoError(t, err)
		})
	}
}
