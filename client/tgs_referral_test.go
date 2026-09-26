package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

func TestTGSExchangeReportsTooManyReferralsCleanly(t *testing.T) {
	t.Parallel()

	kdc := newS4UKDC(t, func(_ int, req messages.TGSReq) []byte {
		return referral(t, req, referredSessionKey(t, req), req.ReqBody.CName, loopingRealm)
	})
	cl := s4uClient(t, kdc.addr)
	cl.Config.Realms = append(cl.Config.Realms, config.Realm{Realm: loopingRealm, KDC: []string{kdc.addr}})
	t.Cleanup(cl.Destroy)

	tgt := messages.Ticket{
		TktVNO:  iana.PVNO,
		Realm:   s4uRealm,
		SName:   types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{s4uKrbtgt, s4uRealm}},
		EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 1, Cipher: []byte("opaque to the client")},
	}

	_, _, err := cl.TGSREQGenerateAndExchange(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/far.example"), s4uRealm, tgt, s4uSessionKey(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum number of referrals exceeded")
	assert.NotContains(t, err.Error(), "%!")
}

const loopingRealm = "LOOP.EXAMPLE"

func referredSessionKey(t *testing.T, req messages.TGSReq) types.EncryptionKey {
	t.Helper()

	require.NotEmpty(t, req.PAData)
	require.Equal(t, patype.PA_TGS_REQ, req.PAData[0].PADataType)

	var ap messages.APReq

	require.NoError(t, ap.Unmarshal(req.PAData[0].PADataValue))

	if ap.Ticket.SName.NameString[len(ap.Ticket.SName.NameString)-1] == s4uRealm {
		return s4uSessionKey()
	}

	kt := keytab.New()
	require.NoError(t, kt.AddEntry(ap.Ticket.SName.PrincipalNameString(), ap.Ticket.Realm, s4uServiceKey, time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96))
	require.NoError(t, ap.Ticket.DecryptEncPart(kt, nil))

	return ap.Ticket.DecryptedEncPart.Key
}
