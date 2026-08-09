package messages

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/addrtype"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
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

// forwardedTGSReqTestTGT builds a TGT shaped like a real one for NewForwardedTGSReq's tests: SName is the realm's
// own krbtgt, since that is what setPAData's authenticator is encrypted against
// (keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR, selected by authenticatorKeyUsage keying off Ticket.SName).
func forwardedTGSReqTestTGT(realm string) Ticket {
	return Ticket{
		Realm: realm,
		SName: types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", realm}},
	}
}

// decryptForwardedAuthenticator decrypts the PA-TGS-REQ entry of a forwarded TGS-REQ, requiring it to succeed
// under the hardcoded keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR (7) - the usage RFC 4120 Section 3.3.1
// specifies for an authenticator carried inside TGS-REQ PA-DATA - rather than deriving that usage from the
// decrypted ticket the way APReq.DecryptAuthenticator does, which would make the check tautological against
// authenticatorKeyUsage's own logic. Decryption fails here if the encryption side actually used
// AP_REQ_AUTHENTICATOR (11), the usage for a bare AP-REQ presented directly to a service, pinning that setPAData
// encrypts under the correct, fixed usage.
func decryptForwardedAuthenticator(t *testing.T, req TGSReq, sessionKey types.EncryptionKey) types.Authenticator {
	t.Helper()

	// The entry is located by type rather than by position: a forwarded request may also carry
	// PA-SUPPORTED-ENCTYPES, and asserting a position would break the moment it does.
	var pa *types.PAData

	for i := range req.PAData {
		if req.PAData[i].PADataType == patype.PA_TGS_REQ {
			pa = &req.PAData[i]

			break
		}
	}

	require.NotNil(t, pa, "a TGS-REQ must carry a PA-TGS-REQ entry")

	var apReq APReq
	require.NoError(t, apReq.Unmarshal(pa.PADataValue))

	ab, err := crypto.DecryptEncPart(apReq.EncryptedAuthenticator, sessionKey, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR)
	require.NoError(t, err, "PA-DATA authenticator must decrypt under key usage 7 (TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR)")

	var auth types.Authenticator
	require.NoError(t, auth.Unmarshal(ab))

	return auth
}

// TestNewForwardedTGSReqShouldRequestAForwardedTGT asserts the KDC options and service name RFC 4120 Section 3.3
// requires of a forwarding request, and mirrors what MIT's krb5_fwd_tgt_creds sends.
func TestNewForwardedTGSReqShouldRequestAForwardedTGT(t *testing.T) {
	t.Parallel()

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser1"}}
	key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0E}, 32)}

	req, err := NewForwardedTGSReq(cname, "TEST.GOKRB5", "TEST.GOKRB5", c, forwardedTGSReqTestTGT("TEST.GOKRB5"), key, nil, nil, 0)
	require.NoError(t, err)

	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Forwarded), "FORWARDED requests the forwarding")
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Forwardable),
		"RFC 4121 Section 4.1.1: the forwarded ticket SHOULD have its forwardable flag set")
	assert.Equal(t, []string{"krbtgt", "TEST.GOKRB5"}, req.ReqBody.SName.NameString)
	assert.Equal(t, nametype.KRB_NT_SRV_INST, req.ReqBody.SName.NameType)

	decryptForwardedAuthenticator(t, req, key)
}

// TestNewForwardedTGSReqShouldCarryOnlyTheAddressesGiven asserts addresses are the caller's decision. MIT supplies
// them only when the source TGT itself has addresses, and this library defaults NoAddresses to true, so the
// addressless path RFC 4120 Section 2.6 blesses is the normal one.
func TestNewForwardedTGSReqShouldCarryOnlyTheAddressesGiven(t *testing.T) {
	t.Parallel()

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser1"}}
	key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0E}, 32)}

	none, err := NewForwardedTGSReq(cname, "TEST.GOKRB5", "TEST.GOKRB5", c, forwardedTGSReqTestTGT("TEST.GOKRB5"), key, nil, nil, 0)
	require.NoError(t, err)
	assert.Empty(t, none.ReqBody.Addresses)
	decryptForwardedAuthenticator(t, none, key)

	addr := types.HostAddress{AddrType: addrtype.IPv4, Address: []byte{10, 0, 0, 9}}

	some, err := NewForwardedTGSReq(cname, "TEST.GOKRB5", "TEST.GOKRB5", c, forwardedTGSReqTestTGT("TEST.GOKRB5"), key,
		types.HostAddresses{addr}, nil, 0)
	require.NoError(t, err)
	require.Len(t, some.ReqBody.Addresses, 1)
	assert.Equal(t, addr, some.ReqBody.Addresses[0])
	decryptForwardedAuthenticator(t, some, key)
}

// TestNewForwardedTGSReqShouldPinTheEncryptionType asserts the MS-KILE Section 3.3.5.7.4 requirement that the
// client "set the etype field of the TGS-REQ to the contents of the keytype field in the previous TGS-REP". The
// forwarded ticket's session key has to be one the application server can use, and the configured default list
// says nothing about that server.
func TestNewForwardedTGSReqShouldPinTheEncryptionType(t *testing.T) {
	t.Parallel()

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser1"}}
	key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0E}, 32)}

	pinned, err := NewForwardedTGSReq(cname, "TEST.GOKRB5", "TEST.GOKRB5", c,
		forwardedTGSReqTestTGT("TEST.GOKRB5"), key, nil, []int32{etypeID.AES128_CTS_HMAC_SHA1_96}, 0)
	require.NoError(t, err)
	assert.Equal(t, []int32{etypeID.AES128_CTS_HMAC_SHA1_96}, pinned.ReqBody.EType)
	decryptForwardedAuthenticator(t, pinned, key)

	// A nil list leaves whatever the configuration chose, which is the pre-MS-KILE behaviour and the fallback the
	// client retries with when a KDC refuses the pinned type.
	unpinned, err := NewForwardedTGSReq(cname, "TEST.GOKRB5", "TEST.GOKRB5", c,
		forwardedTGSReqTestTGT("TEST.GOKRB5"), key, nil, nil, 0)
	require.NoError(t, err)
	assert.Equal(t, c.LibDefaults.DefaultTGSEnctypeIDs, unpinned.ReqBody.EType)
	assert.NotEqual(t, []int32{etypeID.AES128_CTS_HMAC_SHA1_96}, unpinned.ReqBody.EType)
}

// TestNewForwardedTGSReqShouldAdvertiseSupportedEncryptionTypes asserts the PA-SUPPORTED-ENCTYPES entry is
// appended alongside the PA-TGS-REQ that setPAData installs, rather than replacing it. Losing the PA-TGS-REQ would
// make the request unauthenticated and the KDC would reject it outright.
func TestNewForwardedTGSReqShouldAdvertiseSupportedEncryptionTypes(t *testing.T) {
	t.Parallel()

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser1"}}
	key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0E}, 32)}
	supported := types.NewSupportedETypesFromIDs([]int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC})

	req, err := NewForwardedTGSReq(cname, "TEST.GOKRB5", "TEST.GOKRB5", c,
		forwardedTGSReqTestTGT("TEST.GOKRB5"), key, nil, nil, supported)
	require.NoError(t, err)

	require.True(t, req.PAData.Contains(patype.PA_TGS_REQ), "the authenticating PA-TGS-REQ must survive")
	require.True(t, req.PAData.Contains(patype.PA_SUPPORTED_ETYPES))

	assert.Equal(t, supported, types.SupportedETypesFromPAData(req.PAData))
	decryptForwardedAuthenticator(t, req, key)

	// Nothing is advertised when nothing is known, rather than an empty advertisement claiming no common type.
	none, err := NewForwardedTGSReq(cname, "TEST.GOKRB5", "TEST.GOKRB5", c,
		forwardedTGSReqTestTGT("TEST.GOKRB5"), key, nil, nil, 0)
	require.NoError(t, err)
	assert.False(t, none.PAData.Contains(patype.PA_SUPPORTED_ETYPES))
	assert.True(t, none.PAData.Contains(patype.PA_TGS_REQ))
}
