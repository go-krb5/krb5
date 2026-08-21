package crypto

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/krb5/crypto/rfc3961"
)

func TestDeriveRandomReturnsWhenEncryptionFailsPartWayThrough(t *testing.T) {
	t.Parallel()

	e := &failAfterFirstEncrypt{}
	key := make([]byte, 32)

	done := make(chan error, 1)

	go func() {
		_, err := rfc3961.DeriveRandom(key, []byte("usage"), e)
		done <- err
	}()

	select {
	case err := <-done:
		assert.Error(t, err, "the failure should be reported rather than swallowed")
	case <-time.After(2 * time.Second):
		t.Fatal("DeriveRandom did not return: it loops when EncryptData fails part way through")
	}
}

type failAfterFirstEncrypt struct {
	Aes256CtsHmacSha96

	calls int
}

func (e *failAfterFirstEncrypt) EncryptData(key, data []byte) ([]byte, []byte, error) {
	e.calls++

	if e.calls > 1 {
		return nil, nil, errors.New("encryption unavailable")
	}

	return e.Aes256CtsHmacSha96.EncryptData(key, data)
}
