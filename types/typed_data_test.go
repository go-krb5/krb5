package types

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestUnmarshalTypedData(t *testing.T) {
	t.Parallel()

	var a TypedDataSequence

	b, err := hex.DecodeString(testdata.MarshaledKRB5typed_data)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, 2, len(a))

	for _, d := range a {
		assert.Equal(t, patype.PA_SAM_RESPONSE, d.DataType)
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), d.DataValue)
	}
}
