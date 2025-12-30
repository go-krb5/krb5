package types

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestUnmarshalEncryptedData(t *testing.T) {
	t.Parallel()

	var a EncryptedData

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_data)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, testdata.TEST_ETYPE, a.EType)
	assert.Equal(t, iana.PVNO, a.KVNO)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Cipher)
}

func TestUnmarshalEncryptedData_MSBsetkvno(t *testing.T) {
	t.Parallel()

	var a EncryptedData

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_dataMSBSetkvno)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, testdata.TEST_ETYPE, a.EType)
	assert.Equal(t, -16777216, a.KVNO)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Cipher)
}

func TestUnmarshalEncryptedData_kvno_neg1(t *testing.T) {
	t.Parallel()

	var a EncryptedData

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_dataKVNONegOne)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, testdata.TEST_ETYPE, a.EType)
	assert.Equal(t, -1, a.KVNO)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Cipher)
}

func TestUnmarshalEncryptionKey(t *testing.T) {
	t.Parallel()

	var a EncryptionKey

	b, err := hex.DecodeString(testdata.MarshaledKRB5keyblock)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, int32(1), a.KeyType)
	assert.Equal(t, []byte("12345678"), a.KeyValue)
}

func TestMarshalEncryptedData(t *testing.T) {
	t.Parallel()

	var a EncryptedData

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_data)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	mb, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)
}
