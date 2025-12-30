package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/crypto/common"
	"github.com/go-krb5/krb5/crypto/rfc3962"
)

// TestAes128CtsHmacSha196_StringToKey handles test vectors from RFC 3962 Appendix B.
func TestAes128CtsHmacSha196_StringToKey(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString("1234567878563412")
	require.NoError(t, err)

	s := string(b)

	b, err = hex.DecodeString("f09d849e")
	require.NoError(t, err)

	s2 := string(b)

	e := &Aes128CtsHmacSha96{}

	testCases := []RFC3962AppendixBTestCase{
		{"Vector1", 1, "password", "ATHENA.MIT.EDUraeburn", "cdedb5281bb2f801565a1122b2563515", "42263c6e89f4fc28b8df68ee09799f15"},
		{"Vector2", 2, "password", "ATHENA.MIT.EDUraeburn", "01dbee7f4a9e243e988b62c73cda935d", "c651bf29e2300ac27fa469d693bdda13"},
		{"Vector3", 1200, "password", "ATHENA.MIT.EDUraeburn", "5c08eb61fdf71e4e4ec3cf6ba1f5512b", "4c01cd46d632d01e6dbe230a01ed642a"},
		{"Vector4", 5, "password", s, "d1daa78615f287e6a1c8b120d7062a49", "e9b23d52273747dd5c35cb55be619d8e"},
		{"Vector5", 1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase equals block size", "139c30c0966bc32ba55fdbf212530ac9", "59d1bb789a828b1aa54ef9c2883f69ed"},
		{"Vector6", 1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase exceeds block size", "9ccad6d468770cd51b10e6a68721be61", "cb8005dc5f90179a7f02104c0018751d"},
		{"Vector7", 50, s2, "EXAMPLE.COMpianist", "6b9cf26d45455a43a5b8bb276a403b39", "f149c1f2e154a73452d43e7fe62a56e5"},

		// TODO: Add vectors for CBC with ciphertext stealing.
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.pbkdf2, hex.EncodeToString(rfc3962.StringToPBKDF2(tc.phrase, tc.salt, tc.iterations, e)))

			k, err := e.StringToKey(tc.phrase, tc.salt, common.IterationsToS2Kparams(uint32(tc.iterations)))
			require.NoError(t, err)

			assert.Equal(t, tc.key, hex.EncodeToString(k))
		})
	}
}
