package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/krb5/crypto/rfc8009"

	"github.com/go-krb5/krb5/crypto/common"
	"github.com/go-krb5/krb5/crypto/etype"
)

type RFC8009AppendixATestCase struct {
	name       string
	iterations uint32
	phrase     string
	salt       string
	saltp      string
	key        string
}

func HandleTestRFC8009AppendixA(t *testing.T, e etype.EType, ename string, tc RFC8009AppendixATestCase) {
	saltp := rfc8009.GetSaltP(tc.salt, ename)
	assert.Equal(t, tc.saltp, hex.EncodeToString([]byte(saltp)))

	k, err := e.StringToKey(tc.phrase, tc.salt, common.IterationsToS2Kparams(tc.iterations))
	assert.Equal(t, tc.key, hex.EncodeToString(k))
	assert.NoError(t, err)
}
