package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/crypto/common"
	"github.com/go-krb5/krb5/crypto/etype"
	"github.com/go-krb5/krb5/crypto/rfc3962"
)

type RFC3962AppendixBTestCase struct {
	name       string
	iterations int64
	phrase     string
	salt       string
	pbkdf2     string
	key        string
}

func HandleTestRFC3962AppendixB(t *testing.T, e etype.EType, tc RFC3962AppendixBTestCase) {
	assert.Equal(t, tc.pbkdf2, hex.EncodeToString(rfc3962.StringToPBKDF2(tc.phrase, tc.salt, tc.iterations, e)))

	k, err := e.StringToKey(tc.phrase, tc.salt, common.IterationsToS2Kparams(uint32(tc.iterations)))
	require.NoError(t, err)

	assert.Equal(t, tc.key, hex.EncodeToString(k))
}
