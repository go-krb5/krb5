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
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestUnmarshalKDCReqBody(t *testing.T) {
	t.Parallel()

	var a KDCReqBody

	b, err := hex.DecodeString(testdata.MarshaledKRB5kdc_req_body)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, "fedcba90", hex.EncodeToString(a.KDCOptions.Bytes))
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString)
	assert.Equal(t, testdata.TEST_REALM, a.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString)
	assert.Equal(t, tt, a.From)
	assert.Equal(t, tt, a.Till)
	assert.Equal(t, tt, a.RTime)
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce)
	assert.Equal(t, []int32{0, 1}, a.EType)
	assert.Equal(t, 2, len(a.Addresses))

	for _, addr := range a.Addresses {
		assert.Equal(t, addrtype.IPv4, addr.AddrType)
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address))
	}

	assert.Equal(t, testdata.TEST_ETYPE, a.EncAuthData.EType)
	assert.Equal(t, iana.PVNO, a.EncAuthData.KVNO)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncAuthData.Cipher)
	assert.Equal(t, 2, len(a.AdditionalTickets))

	for _, tkt := range a.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO)
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm)
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType)
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString)
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType)
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO)
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher)
	}
}

func TestUnmarshalKDCReqBody_optionalsNULLexceptsecond_ticket(t *testing.T) {
	t.Parallel()

	var a KDCReqBody

	b, err := hex.DecodeString(testdata.MarshaledKRB5kdc_req_bodyOptionalsNULLexceptsecond_ticket)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.KDCOptions.Bytes))
	assert.Equal(t, testdata.TEST_REALM, a.Realm)
	assert.Equal(t, tt, a.Till)
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce)
	assert.Equal(t, []int32{0, 1}, a.EType)
	assert.Equal(t, 0, len(a.Addresses))
	assert.Equal(t, 0, len(a.EncAuthData.Cipher))
	assert.Equal(t, 2, len(a.AdditionalTickets))

	for _, tkt := range a.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO)
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm)
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType)
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString)
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType)
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO)
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher)
	}
}

func TestUnmarshalKDCReqBody_optionalsNULLexceptserver(t *testing.T) {
	t.Parallel()

	var a KDCReqBody

	b, err := hex.DecodeString(testdata.MarshaledKRB5kdc_req_bodyOptionalsNULLexceptserver)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, "fedcba90", hex.EncodeToString(a.KDCOptions.Bytes))
	assert.Equal(t, testdata.TEST_REALM, a.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString)
	assert.Equal(t, tt, a.Till)
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce)
	assert.Equal(t, []int32{0, 1}, a.EType)
	assert.Equal(t, 0, len(a.Addresses))
	assert.Equal(t, 0, len(a.EncAuthData.Cipher))
	assert.Equal(t, 0, len(a.AdditionalTickets))
}

func TestUnmarshalASReq(t *testing.T) {
	t.Parallel()

	var a ASReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5as_req)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_AS_REQ, a.MsgType)
	assert.Equal(t, 2, len(a.PAData))

	for _, pa := range a.PAData {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType)
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue)
	}

	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes))
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.CName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.CName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.CName.NameString)
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString)
	assert.Equal(t, tt, a.ReqBody.From)
	assert.Equal(t, tt, a.ReqBody.Till)
	assert.Equal(t, tt, a.ReqBody.RTime)
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce)
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType)
	assert.Equal(t, 2, len(a.ReqBody.Addresses))

	for _, addr := range a.ReqBody.Addresses {
		assert.Equal(t, addrtype.IPv4, addr.AddrType)
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address))
	}

	assert.Equal(t, testdata.TEST_ETYPE, a.ReqBody.EncAuthData.EType)
	assert.Equal(t, iana.PVNO, a.ReqBody.EncAuthData.KVNO)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.ReqBody.EncAuthData.Cipher)
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets))

	for _, tkt := range a.ReqBody.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO)
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm)
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType)
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString)
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType)
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO)
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher)
	}
}

func TestUnmarshalASReq_optionalsNULLexceptsecond_ticket(t *testing.T) {
	t.Parallel()

	var a ASReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5as_reqOptionalsNULLexceptsecond_ticket)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_AS_REQ, a.MsgType)
	assert.Equal(t, 0, len(a.PAData))
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes))
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm)
	assert.Equal(t, tt, a.ReqBody.Till)
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce)
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType)
	assert.Equal(t, 0, len(a.ReqBody.Addresses))
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher))
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets))

	for _, tkt := range a.ReqBody.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO)
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm)
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType)
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString)
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType)
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO)
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher)
	}
}

func TestUnmarshalASReq_optionalsNULLexceptserver(t *testing.T) {
	t.Parallel()

	var a ASReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5as_reqOptionalsNULLexceptserver)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_AS_REQ, a.MsgType)
	assert.Equal(t, 0, len(a.PAData))
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes))
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString)
	assert.Equal(t, tt, a.ReqBody.Till)
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce)
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType)
	assert.Equal(t, 0, len(a.ReqBody.Addresses))
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher))
	assert.Equal(t, 0, len(a.ReqBody.AdditionalTickets))
}

func TestUnmarshalTGSReq(t *testing.T) {
	t.Parallel()

	var a TGSReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_req)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_TGS_REQ, a.MsgType)
	assert.Equal(t, 2, len(a.PAData))

	for _, pa := range a.PAData {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType)
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue)
	}

	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes))
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.CName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.CName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.CName.NameString)
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString)
	assert.Equal(t, tt, a.ReqBody.From)
	assert.Equal(t, tt, a.ReqBody.Till)
	assert.Equal(t, tt, a.ReqBody.RTime)
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce)
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType)
	assert.Equal(t, 2, len(a.ReqBody.Addresses))

	for _, addr := range a.ReqBody.Addresses {
		assert.Equal(t, addrtype.IPv4, addr.AddrType)
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address))
	}

	assert.Equal(t, testdata.TEST_ETYPE, a.ReqBody.EncAuthData.EType)
	assert.Equal(t, iana.PVNO, a.ReqBody.EncAuthData.KVNO)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.ReqBody.EncAuthData.Cipher)
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets))

	for _, tkt := range a.ReqBody.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO)
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm)
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType)
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString)
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType)
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO)
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher)
	}
}

func TestUnmarshalTGSReq_optionalsNULLexceptsecond_ticket(t *testing.T) {
	t.Parallel()

	var a TGSReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_reqOptionalsNULLexceptsecond_ticket)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_TGS_REQ, a.MsgType)
	assert.Equal(t, 0, len(a.PAData))
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes))
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm)
	assert.Equal(t, tt, a.ReqBody.Till)
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce)
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType)
	assert.Equal(t, 0, len(a.ReqBody.Addresses))
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher))
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets))

	for _, tkt := range a.ReqBody.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO)
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm)
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType)
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString)
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType)
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO)
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher)
	}
}

func TestUnmarshalTGSReq_optionalsNULLexceptserver(t *testing.T) {
	t.Parallel()

	var a TGSReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_reqOptionalsNULLexceptserver)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_TGS_REQ, a.MsgType)
	assert.Equal(t, 0, len(a.PAData))
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes))
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString)
	assert.Equal(t, tt, a.ReqBody.Till)
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce)
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType)
	assert.Equal(t, 0, len(a.ReqBody.Addresses))
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher))
	assert.Equal(t, 0, len(a.ReqBody.AdditionalTickets))
}

//// Marshal Tests ////.

func TestMarshalKDCReqBody(t *testing.T) {
	t.Parallel()

	var a KDCReqBody

	b, err := hex.DecodeString(testdata.MarshaledKRB5kdc_req_body)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	mb, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)
}

func TestMarshalASReq(t *testing.T) {
	t.Parallel()

	var a ASReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5as_req)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	mb, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)
}

func TestMarshalTGSReq(t *testing.T) {
	t.Parallel()

	var a TGSReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_req)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	mb, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)
}
