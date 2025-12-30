package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestUnmarshalAPRep(t *testing.T) {
	t.Parallel()

	var a APRep

	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_AP_REP, a.MsgType)
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher)
}

func TestUnmarshalEncAPRepPart(t *testing.T) {
	t.Parallel()

	var a EncAPRepPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_part)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, tt, a.CTime)
	assert.Equal(t, 123456, a.Cusec)
	assert.Equal(t, int32(1), a.Subkey.KeyType)
	assert.Equal(t, []byte("12345678"), a.Subkey.KeyValue)
	assert.Equal(t, int64(17), a.SequenceNumber)
}

func TestUnmarshalEncAPRepPart_optionalsNULL(t *testing.T) {
	t.Parallel()

	var a EncAPRepPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_partOptionalsNULL)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, tt, a.CTime)
	assert.Equal(t, 123456, a.Cusec)
}
