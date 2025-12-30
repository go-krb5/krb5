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
)

func TestUnmarshalKRBSafe(t *testing.T) {
	t.Parallel()

	var a KRBSafe

	b, err := hex.DecodeString(testdata.MarshaledKRB5safe)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_SAFE, a.MsgType)
	assert.Equal(t, []byte("krb5data"), a.SafeBody.UserData)
	assert.Equal(t, tt, a.SafeBody.Timestamp)
	assert.Equal(t, 123456, a.SafeBody.Usec)
	assert.Equal(t, int64(17), a.SafeBody.SequenceNumber)
	assert.Equal(t, addrtype.IPv4, a.SafeBody.SAddress.AddrType)
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SafeBody.SAddress.Address))
	assert.Equal(t, addrtype.IPv4, a.SafeBody.RAddress.AddrType)
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SafeBody.RAddress.Address))
	assert.Equal(t, int32(1), a.Cksum.CksumType)
	assert.Equal(t, []byte("1234"), a.Cksum.Checksum)
}

func TestUnmarshalKRBSafe_optionalsNULL(t *testing.T) {
	t.Parallel()

	var a KRBSafe

	b, err := hex.DecodeString(testdata.MarshaledKRB5safeOptionalsNULL)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_SAFE, a.MsgType)
	assert.Equal(t, []byte("krb5data"), a.SafeBody.UserData)
	assert.Equal(t, addrtype.IPv4, a.SafeBody.SAddress.AddrType)
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SafeBody.SAddress.Address))
	assert.Equal(t, int32(1), a.Cksum.CksumType)
	assert.Equal(t, []byte("1234"), a.Cksum.Checksum)
}
