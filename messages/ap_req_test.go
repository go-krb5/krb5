package messages

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestUnmarshalAPReq(t *testing.T) {
	t.Parallel()

	var a APReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_req)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_AP_REQ, a.MsgType)
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.APOptions.Bytes))
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO)
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString)
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Ticket.EncPart.Cipher)
}

func TestMarshalAPReq(t *testing.T) {
	t.Parallel()

	var a APReq

	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_req)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	mb, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)
}

// TestDecryptAuthenticatorShouldNotPanicOnAnEmptySName guards a remotely reachable panic. A ticket's plaintext
// SName sits outside EncPart and PrincipalName.NameString may legally be empty, so a client holding any valid
// service ticket can blank it and still reach DecryptAuthenticator; nothing on that path may index it.
func TestDecryptAuthenticatorShouldNotPanicOnAnEmptySName(t *testing.T) {
	t.Parallel()

	var a APReq

	assert.NotPanics(t, func() {
		_ = a.DecryptAuthenticator(apReqTestKey())
	})
}

// TestNewAPReqShouldUseTheAPREQKeyUsageForATGT pins that the key usage follows the AP_REQ's position rather than
// what its ticket names. RFC 4120 Section 7.5.1 assigns 11 to an AP-REQ authenticator, and the ticket presented in
// one is a TGT whenever the exchange is the user-to-user authentication of Section 3.7.
func TestNewAPReqShouldUseTheAPREQKeyUsageForATGT(t *testing.T) {
	t.Parallel()

	key := apReqTestKey()
	tgt := Ticket{
		Realm: testRealm,
		SName: types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{testKrbtgt, testRealm}},
	}

	apReq, err := NewAPReq(tgt, key, apReqTestAuthenticator(t))
	require.NoError(t, err)

	_, err = crypto.DecryptEncPart(apReq.EncryptedAuthenticator, key, keyusage.AP_REQ_AUTHENTICATOR)
	require.NoError(t, err, "an AP-REQ authenticator takes key usage 11 whatever its ticket names")
}

// TestNewAPReqPATGSReqShouldUseTheTGSREQKeyUsageForAServiceTicket is the converse: the pre-authentication position
// takes key usage 7, and renewal presents the service ticket being renewed rather than a TGT.
func TestNewAPReqPATGSReqShouldUseTheTGSREQKeyUsageForAServiceTicket(t *testing.T) {
	t.Parallel()

	key := apReqTestKey()
	svc := Ticket{
		Realm: testRealm,
		SName: types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{testHTTPService, testHTTPHost}},
	}

	apReq, err := newAPReqPATGSReq(svc, key, apReqTestAuthenticator(t))
	require.NoError(t, err)

	_, err = crypto.DecryptEncPart(apReq.EncryptedAuthenticator, key, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR)
	require.NoError(t, err, "a PA-TGS-REQ authenticator takes key usage 7 whatever its ticket names")
}

// testKrbtgt and testHTTPService name the two ticket kinds an AP_REQ can carry, a TGT and a service ticket.
const (
	testKrbtgt      = "krbtgt"
	testHTTPService = "HTTP"
	testHTTPHost    = "host.test.gokrb5"
)

func apReqTestKey() types.EncryptionKey {
	return types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x0E}, 32)}
}

func apReqTestAuthenticator(t *testing.T) types.Authenticator {
	t.Helper()

	auth, err := types.NewAuthenticator(testRealm,
		types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{testUser}})
	require.NoError(t, err)

	return auth
}
