package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

func TestReferralASReqIsReissuedAgainstTheNewRealm(t *testing.T) {
	t.Parallel()

	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser")

	req, err := messages.NewASReqForTGT("OLD.GOKRB5", config.New(), cname)
	require.NoError(t, err)

	req.PAData = types.PADataSequence{{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: []byte("stale")}}

	referred := referralASReq(req, "NEW.GOKRB5")

	assert.Equal(t, "NEW.GOKRB5", referred.ReqBody.Realm)
	assert.Equal(t, []string{"krbtgt", "NEW.GOKRB5"}, referred.ReqBody.SName.NameString)

	assert.Empty(t, referred.PAData)

	assert.Equal(t, cname, referred.ReqBody.CName)
	assert.Equal(t, req.ReqBody.Nonce, referred.ReqBody.Nonce)
}

func TestReferralASReqLeavesANonTGTServiceNameAlone(t *testing.T) {
	t.Parallel()

	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser")

	req, err := messages.NewASReqForChgPasswd("OLD.GOKRB5", config.New(), cname)
	require.NoError(t, err)

	referred := referralASReq(req, "NEW.GOKRB5")

	assert.Equal(t, "NEW.GOKRB5", referred.ReqBody.Realm)
	assert.Equal(t, []string{"kadmin", "changepw"}, referred.ReqBody.SName.NameString)
}

func TestSetPADataDoesNotAccumulateAcrossCalls(t *testing.T) {
	t.Parallel()

	cl := NewWithPassword("testuser", "TEST.GOKRB5", "password", config.New())

	req, err := messages.NewASReqForTGT("TEST.GOKRB5", cl.Config, cl.Credentials.CName())
	require.NoError(t, err)

	require.NoError(t, setPAData(cl, nil, &req))
	first := len(req.PAData)

	require.NotPanics(t, func() {
		require.NoError(t, setPAData(cl, nil, &req))
	})

	assert.Equal(t, first, len(req.PAData), "a second call must replace the pre-authentication data, not add to it")
	assert.Equal(t, 1, countPAData(req.PAData, patype.PA_REQ_ENC_PA_REP))
}

func TestSetPADataReplacesAnExistingEncTimestamp(t *testing.T) {
	t.Parallel()

	cl := NewWithPassword("testuser", "TEST.GOKRB5", "password", config.New())
	cl.settings.assumePreAuthentication = true

	req, err := messages.NewASReqForTGT("TEST.GOKRB5", cl.Config, cl.Credentials.CName())
	require.NoError(t, err)

	req.PAData = types.PADataSequence{
		{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: []byte("stale")},
		{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: []byte("staler")},
		{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: []byte("stalest")},
	}

	require.NotPanics(t, func() {
		require.NoError(t, setPAData(cl, nil, &req))
	})

	assert.Equal(t, 1, countPAData(req.PAData, patype.PA_ENC_TIMESTAMP))
	assert.Equal(t, 1, countPAData(req.PAData, patype.PA_REQ_ENC_PA_REP))
}

func TestSetPADataKeepsTheKDCsSaltForLaterLogins(t *testing.T) {
	t.Parallel()

	cl := NewWithPassword("testuser", "TEST.GOKRB5", "passwordvalue", config.New())
	cl.settings.assumePreAuthentication = true

	krberr := saltedPreAuthError(t, errorcode.KDC_ERR_PREAUTH_REQUIRED)

	first, err := messages.NewASReqForTGT("TEST.GOKRB5", cl.Config, cl.Credentials.CName())
	require.NoError(t, err)
	require.NoError(t, setPAData(cl, &krberr, &first))
	assert.NoError(t, decryptEncTimestamp(t, first, saltedKey(t)))

	later, err := messages.NewASReqForTGT("TEST.GOKRB5", cl.Config, cl.Credentials.CName())
	require.NoError(t, err)
	require.NoError(t, setPAData(cl, nil, &later))
	assert.NoError(t, decryptEncTimestamp(t, later, saltedKey(t)))
}

func TestSetPADataUsesTheSaltInAPreAuthFailedError(t *testing.T) {
	t.Parallel()

	cl := NewWithPassword("testuser", "TEST.GOKRB5", "passwordvalue", config.New())
	cl.settings.assumePreAuthentication = true

	krberr := saltedPreAuthError(t, errorcode.KDC_ERR_PREAUTH_FAILED)

	req, err := messages.NewASReqForTGT("TEST.GOKRB5", cl.Config, cl.Credentials.CName())
	require.NoError(t, err)
	require.NoError(t, setPAData(cl, &krberr, &req))
	assert.NoError(t, decryptEncTimestamp(t, req, saltedKey(t)))
}

const kdcSalt = "TEST.GOKRB5hostweb.test.gokrb5"

func saltedPreAuthError(t *testing.T, code int32) messages.KRBError {
	t.Helper()

	info := types.ETypeInfo2{{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Salt: kdcSalt}}

	v, err := asn1.Marshal(info, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	pas, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: v}},
		asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	return messages.KRBError{ErrorCode: code, EData: pas}
}

func saltedKey(t *testing.T) types.EncryptionKey {
	t.Helper()

	et, err := crypto.GetEType(etypeID.AES256_CTS_HMAC_SHA1_96)
	require.NoError(t, err)

	k, err := et.StringToKey("passwordvalue", kdcSalt, et.GetDefaultStringToKeyParams())
	require.NoError(t, err)

	return types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: k}
}

func decryptEncTimestamp(t *testing.T, req messages.ASReq, key types.EncryptionKey) error {
	t.Helper()

	for _, pa := range req.PAData {
		if pa.PADataType != patype.PA_ENC_TIMESTAMP {
			continue
		}

		var ed types.EncryptedData

		require.NoError(t, ed.Unmarshal(pa.PADataValue))

		_, err := crypto.DecryptEncPart(ed, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP)

		return err
	}

	t.Fatal("the AS-REQ carries no PA-ENC-TIMESTAMP")

	return nil
}

func countPAData(pas types.PADataSequence, t int32) int {
	var n int

	for _, pa := range pas {
		if pa.PADataType == t {
			n++
		}
	}

	return n
}
