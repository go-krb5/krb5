package rfc4757_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/crypto/rfc4757"
)

// TestDecryptMessageShouldRejectAShortCiphertext covers the length guard, matching the ones in rfc3961, rfc3962 and
// rfc8009. RC4 puts its checksum first rather than last, but the exposure is the same: the length of the
// EncryptedData is chosen by whoever encoded it, and splitting a message shorter than the checksum plus a
// confounder used to index out of range.
func TestDecryptMessageShouldRejectAShortCiphertext(t *testing.T) {
	t.Parallel()

	var e crypto.RC4HMAC

	key := make([]byte, 16)

	for _, size := range []int{0, 1, 6, 16, 23} {
		assert.NotPanics(t, func() {
			_, err := rfc4757.DecryptMessage(key, make([]byte, size), 2, false, &e)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "ciphertext is too short to be an encrypted message")
		}, "a %d byte ciphertext must be an error, not a panic", size)
	}
}

// TestVerifyIntegrityShouldRejectAShortMessage covers the same exposure on the exported integrity check, which
// reads the checksum out of the message directly.
func TestVerifyIntegrityShouldRejectAShortMessage(t *testing.T) {
	t.Parallel()

	var e crypto.RC4HMAC

	key := make([]byte, 16)

	for _, size := range []int{0, 1, 15} {
		assert.NotPanics(t, func() {
			assert.False(t, rfc4757.VerifyIntegrity(key, make([]byte, 8), make([]byte, size), &e))
		}, "a %d byte message must verify false, not panic", size)
	}
}
