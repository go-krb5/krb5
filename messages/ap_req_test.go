package messages

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestUnmarshalAPReq(t *testing.T) {
	t.Parallel()

	var a APReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_req)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AP_REQ, a.MsgType, "MsgType is not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.APOptions.Bytes), "AP Options not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO, "Ticket VNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType, "Ticket SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "Ticket SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName name string entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Ticket encPart etype not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO, "Ticket encPart KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Ticket.EncPart.Cipher, "Ticket encPart cipher not as expected")
}

func TestMarshalAPReq(t *testing.T) {
	t.Parallel()

	var a APReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_req)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	mb, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb, "Marshal bytes of Authenticator not as expected")
}
