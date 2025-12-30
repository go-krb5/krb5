package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/addrtype"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestUnmarshalKRBPriv(t *testing.T) {
	t.Parallel()

	var a KRBPriv

	b, err := hex.DecodeString(testdata.MarshaledKRB5priv)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_PRIV, a.MsgType)
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO)
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher)
}

func TestUnmarshalEncPrivPart(t *testing.T) {
	t.Parallel()

	var a EncKrbPrivPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_priv_part)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, "krb5data", string(a.UserData))
	assert.Equal(t, tt, a.Timestamp)
	assert.Equal(t, 123456, a.Usec)
	assert.Equal(t, int64(17), a.SequenceNumber)
	assert.Equal(t, addrtype.IPv4, a.SAddress.AddrType)
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SAddress.Address))
	assert.Equal(t, addrtype.IPv4, a.RAddress.AddrType)
	assert.Equal(t, "12d00023", hex.EncodeToString(a.RAddress.Address))
}

func TestUnmarshalEncPrivPart_optionalsNULL(t *testing.T) {
	t.Parallel()

	var a EncKrbPrivPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_priv_partOptionalsNULL)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, "krb5data", string(a.UserData))
	assert.Equal(t, addrtype.IPv4, a.SAddress.AddrType)
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SAddress.Address))
}

func TestMarshalKRBPriv(t *testing.T) {
	t.Parallel()

	var a KRBPriv

	b, err := hex.DecodeString(testdata.MarshaledKRB5priv)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	mb, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)

	be, err := hex.DecodeString(testdata.MarshaledKRB5enc_priv_part)
	require.NoError(t, err)

	require.NoError(t, a.DecryptedEncPart.Unmarshal(be))

	mb, err = a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)
}

func TestKRBPriv_EncryptEncPart(t *testing.T) {
	t.Parallel()

	var a KRBPriv

	b, err := hex.DecodeString(testdata.MarshaledKRB5priv)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	b, err = hex.DecodeString(testdata.MarshaledKRB5enc_priv_part)
	require.NoError(t, err)

	require.NoError(t, a.DecryptedEncPart.Unmarshal(b))

	key := types.EncryptionKey{
		KeyType:  int32(18),
		KeyValue: []byte("12345678901234567890123456789012"),
	}

	require.NoError(t, a.EncryptEncPart(key))
}
