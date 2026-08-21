package common_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/crypto/common"
)

func TestVerifyChecksumFailsClosedWhenTheChecksumCannotBeComputed(t *testing.T) {
	t.Parallel()

	var e crypto.Aes256CtsHmacSha96

	badKey := make([]byte, 5)

	assert.False(t, common.VerifyChecksum(badKey, []byte{}, []byte("a message"), 1, e),
		"an empty checksum must not verify when the expected one could not be computed")
	assert.False(t, common.VerifyChecksum(badKey, nil, []byte("a message"), 1, e))
}

func TestVerifyChecksumAcceptsAGoodChecksum(t *testing.T) {
	t.Parallel()

	var e crypto.Aes256CtsHmacSha96

	key := make([]byte, 32)

	sum, err := common.GetChecksumHash([]byte("a message"), key, 1, e)
	assert.NoError(t, err)

	assert.True(t, common.VerifyChecksum(key, sum, []byte("a message"), 1, e))
	assert.False(t, common.VerifyChecksum(key, sum, []byte("another message"), 1, e))
}
