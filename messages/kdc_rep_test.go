package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/test/testdata"
)

const (
	testuser1EType18Keytab = "05020000004b0001000b544553542e474f4b5242350009746573747573657231000000015898e0770100120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de900000001"
	testuser1EType18ASREP  = "6b8202f3308202efa003020105a10302010ba22e302c302aa103020113a2230421301f301da003020112a1161b14544553542e474f4b524235746573747573657231a30d1b0b544553542e474f4b524235a4163014a003020101a10d300b1b09746573747573657231a582015a6182015630820152a003020105a10d1b0b544553542e474f4b524235a220301ea003020102a11730151b066b72627467741b0b544553542e474f4b524235a382011830820114a003020112a103020101a28201060482010237e486e32cd18ab1ac9f8d42e93f8babd7b3497084cc5599f18ec61961c6d5242d350354d99d67a7604c451116188d16cb719e84377212eac2743440e8c504ef69c755e489cc6b65f935dd032bfc076f9b2c56d816197845b8fe857d738bc59712787631a50e86833d1b0e4732c8712c856417a6a257758e7d01d3182adb3233f0dde65d228c240ed26aa1af69f8d765dc0bc69096fdb037a75af220fea176839528d44b70f7dabfaa2ea506de1296f847176a60c501fd8cef8e0a51399bb6d5f753962d96292e93ffe344c6630db912931d46d88c0279f00719e22d0efcfd4ee33a702d0b660c1f13970a9beec12c0c8af3dda68bd81ac1fe3f126d2a24ebb445c5a682012c30820128a003020112a282011f0482011bb149cc16018072c4c18788d95a33aba540e52c11b54a93e67e788d05de75d8f3d4aa1afafbbfa6fde3eb40e5aa1890644cea2607efd5213a3fd00345b02eeb9ae1b589f36c74c689cd4ec1239dfe61e42ba6afa33f6240e3cfab291e4abb465d273302dbf7dbd148a299a9369044dd03377c1687e7dd36aa66501284a4ca50c0a7b08f4f87aecfa23b0dd0b11490e3ad330906dab715de81fc52f120d09c39990b8b5330d4601cc396b2ed258834329c4cc02c563a12de3ef9bf11e946258bc2ab5257f4caa4d443a7daf0fc25f6f531c2fcba88af8ca55c85300997cd05abbea52811fe2d038ba8f62fc8e3bc71ce04362d356ea2e1df8ac55c784c53cfb07817d48e39fe99fc8788040d98209c79dcf044d97e80de9f47824646"
	testRealm              = "TEST.GOKRB5"
	testUser               = "testuser1"
	testUserPassword       = "passwordvalue"
)

func TestUnmarshalASRep(t *testing.T) {
	t.Parallel()

	var a ASRep

	b, err := hex.DecodeString(testdata.MarshaledKRB5as_rep)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_AS_REP, a.MsgType)
	assert.Equal(t, 2, len(a.PAData))

	for _, pa := range a.PAData {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType)
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue)
	}

	assert.Equal(t, testdata.TEST_REALM, a.CRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString)
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO)
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString)
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO)
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher))
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO)
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher))
}

func TestUnmarshalASRep_optionalsNULL(t *testing.T) {
	t.Parallel()

	var a ASRep

	b, err := hex.DecodeString(testdata.MarshaledKRB5as_repOptionalsNULL)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_AS_REP, a.MsgType)
	assert.Equal(t, 0, len(a.PAData))
	assert.Equal(t, testdata.TEST_REALM, a.CRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString)
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO)
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString)
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO)
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher))
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO)
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher))
}

func TestMarshalASRep(t *testing.T) {
	t.Parallel()

	var a ASRep

	b, err := hex.DecodeString(testdata.MarshaledKRB5as_rep)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	mb, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)
}

func TestUnmarshalTGSRep(t *testing.T) {
	t.Parallel()

	var a TGSRep

	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_rep)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_TGS_REP, a.MsgType)
	assert.Equal(t, 2, len(a.PAData))

	for _, pa := range a.PAData {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType)
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue)
	}

	assert.Equal(t, testdata.TEST_REALM, a.CRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString)
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO)
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString)
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO)
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher))
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO)
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher))
}

func TestUnmarshalTGSRep_optionalsNULL(t *testing.T) {
	t.Parallel()

	var a TGSRep

	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_repOptionalsNULL)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_TGS_REP, a.MsgType)
	assert.Equal(t, 0, len(a.PAData))
	assert.Equal(t, testdata.TEST_REALM, a.CRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString)
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO)
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString)
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO)
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher))
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO)
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher))
}

func TestMarshalTGSRep(t *testing.T) {
	t.Parallel()

	var a TGSRep

	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_rep)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	mb, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)
}

func TestUnmarshalEncKDCRepPart(t *testing.T) {
	t.Parallel()

	var a EncKDCRepPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_kdc_rep_part)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, int32(1), a.Key.KeyType)
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue)
	assert.Equal(t, 2, len(a.LastReqs))

	for _, r := range a.LastReqs {
		assert.Equal(t, int32(-5), r.LRType)
		assert.Equal(t, tt, r.LRValue)
	}

	assert.Equal(t, testdata.TEST_NONCE, a.Nonce)
	assert.Equal(t, tt, a.KeyExpiration)
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes))
	assert.Equal(t, tt, a.AuthTime)
	assert.Equal(t, tt, a.StartTime)
	assert.Equal(t, tt, a.EndTime)
	assert.Equal(t, tt, a.RenewTill)
	assert.Equal(t, testdata.TEST_REALM, a.SRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType)
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString)
	assert.Equal(t, 2, len(a.CAddr))

	for _, addr := range a.CAddr {
		assert.Equal(t, int32(2), addr.AddrType)
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address))
	}
}

func TestUnmarshalEncKDCRepPart_optionalsNULL(t *testing.T) {
	t.Parallel()

	var a EncKDCRepPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_kdc_rep_partOptionalsNULL)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, int32(1), a.Key.KeyType)
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue)
	assert.Equal(t, 2, len(a.LastReqs))

	for _, r := range a.LastReqs {
		assert.Equal(t, int32(-5), r.LRType)
		assert.Equal(t, tt, r.LRValue)
	}

	assert.Equal(t, testdata.TEST_NONCE, a.Nonce)
	assert.Equal(t, "fe5cba98", hex.EncodeToString(a.Flags.Bytes))
	assert.Equal(t, tt, a.EndTime)
	assert.Equal(t, testdata.TEST_REALM, a.SRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType)
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString)
}

func TestUnmarshalASRepDecodeAndDecrypt(t *testing.T) {
	t.Parallel()

	var asRep ASRep

	b, err := hex.DecodeString(testuser1EType18ASREP)
	require.NoError(t, err)

	require.NoError(t, asRep.Unmarshal(b))

	assert.Equal(t, 5, asRep.PVNO)
	assert.Equal(t, 11, asRep.MsgType)
	assert.Equal(t, testRealm, asRep.CRealm)
	assert.Equal(t, int32(1), asRep.CName.NameType)
	assert.Equal(t, testUser, asRep.CName.NameString[0])
	assert.Equal(t, int32(19), asRep.PAData[0].PADataType)
	assert.Equal(t, 5, asRep.Ticket.TktVNO)
	assert.Equal(t, testRealm, asRep.Ticket.Realm)
	assert.Equal(t, int32(2), asRep.Ticket.SName.NameType)
	assert.Equal(t, "krbtgt", asRep.Ticket.SName.NameString[0])
	assert.Equal(t, testRealm, asRep.Ticket.SName.NameString[1])
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], asRep.Ticket.EncPart.EType)
	assert.Equal(t, 1, asRep.Ticket.EncPart.KVNO)
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], asRep.EncPart.EType)
	assert.Equal(t, 0, asRep.EncPart.KVNO)

	ktb, err := hex.DecodeString(testuser1EType18Keytab)
	require.NoError(t, err)

	kt := keytab.New()

	require.NoError(t, kt.Unmarshal(ktb))

	cred := credentials.New(testUser, testRealm)

	_, err = asRep.DecryptEncPart(cred.WithKeytab(kt))
	require.NoError(t, err)

	assert.Equal(t, int32(18), asRep.DecryptedEncPart.Key.KeyType)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.LastReqs[0].LRValue)
	assert.Equal(t, 2069991465, asRep.DecryptedEncPart.Nonce)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.KeyExpiration)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.AuthTime)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.StartTime)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.EndTime)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.RenewTill)
	assert.Equal(t, testRealm, asRep.DecryptedEncPart.SRealm)
	assert.Equal(t, int32(2), asRep.DecryptedEncPart.SName.NameType)
	assert.Equal(t, []string{"krbtgt", testRealm}, asRep.DecryptedEncPart.SName.NameString)
}

func TestUnmarshalASRepDecodeAndDecrypt_withPassword(t *testing.T) {
	t.Parallel()

	var asRep ASRep

	b, err := hex.DecodeString(testuser1EType18ASREP)
	require.NoError(t, err)

	require.NoError(t, asRep.Unmarshal(b))

	assert.Equal(t, 5, asRep.PVNO)
	assert.Equal(t, 11, asRep.MsgType)
	assert.Equal(t, testRealm, asRep.CRealm)
	assert.Equal(t, int32(1), asRep.CName.NameType)
	assert.Equal(t, testUser, asRep.CName.NameString[0])
	assert.Equal(t, int32(19), asRep.PAData[0].PADataType)
	assert.Equal(t, 5, asRep.Ticket.TktVNO)
	assert.Equal(t, testRealm, asRep.Ticket.Realm)
	assert.Equal(t, int32(2), asRep.Ticket.SName.NameType)
	assert.Equal(t, "krbtgt", asRep.Ticket.SName.NameString[0])
	assert.Equal(t, testRealm, asRep.Ticket.SName.NameString[1])
	assert.Equal(t, etypeID.AES256_CTS_HMAC_SHA1_96, asRep.Ticket.EncPart.EType)
	assert.Equal(t, 1, asRep.Ticket.EncPart.KVNO)
	assert.Equal(t, etypeID.AES256_CTS_HMAC_SHA1_96, asRep.EncPart.EType)
	assert.Equal(t, 0, asRep.EncPart.KVNO)

	cred := credentials.New(testUser, testRealm)

	_, err = asRep.DecryptEncPart(cred.WithPassword(testUserPassword))
	require.NoError(t, err)

	assert.Equal(t, int32(18), asRep.DecryptedEncPart.Key.KeyType)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.LastReqs[0].LRValue)
	assert.Equal(t, 2069991465, asRep.DecryptedEncPart.Nonce)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.KeyExpiration)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.AuthTime)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.StartTime)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.EndTime)
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.RenewTill)
	assert.Equal(t, testRealm, asRep.DecryptedEncPart.SRealm)
	assert.Equal(t, nametype.KRB_NT_SRV_INST, asRep.DecryptedEncPart.SName.NameType)
	assert.Equal(t, []string{"krbtgt", testRealm}, asRep.DecryptedEncPart.SName.NameString)
}
