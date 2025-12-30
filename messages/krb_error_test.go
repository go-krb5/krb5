package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestUnmarshalMarshalKRBError(t *testing.T) {
	t.Parallel()

	var a KRBError

	b, err := hex.DecodeString(testdata.MarshaledKRB5error)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_ERROR, a.MsgType)
	assert.Equal(t, tt, a.CTime)
	assert.Equal(t, 123456, a.Cusec)
	assert.Equal(t, tt, a.STime)
	assert.Equal(t, 123456, a.Susec)
	assert.Equal(t, errorcode.KRB_ERR_GENERIC, a.ErrorCode)
	assert.Equal(t, testdata.TEST_REALM, a.CRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString)
	assert.Equal(t, testdata.TEST_REALM, a.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString)
	assert.Equal(t, "krb5data", a.EText)
	assert.Equal(t, []byte("krb5data"), a.EData)

	b2, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, b2)
}

func TestUnmarshalMarshalKRBError_optionalsNULL(t *testing.T) {
	t.Parallel()

	var a KRBError

	b, err := hex.DecodeString(testdata.MarshaledKRB5errorOptionalsNULL)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_ERROR, a.MsgType)
	assert.Equal(t, 123456, a.Cusec)
	assert.Equal(t, tt, a.STime)
	assert.Equal(t, 123456, a.Susec)
	assert.Equal(t, errorcode.KRB_ERR_GENERIC, a.ErrorCode)
	assert.Equal(t, testdata.TEST_REALM, a.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString)

	b2, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, b2)
}
