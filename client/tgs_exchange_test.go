package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

func TestUser2UserRequestFollowsAReferralAsUser2User(t *testing.T) {
	t.Parallel()

	kdc := newS4UKDC(t, func(n int, req messages.TGSReq) []byte {
		if n == 1 {
			return referral(t, req, s4uSessionKey(), req.ReqBody.CName, u2uReferralRealm)
		}

		return refusal(t, errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN, "end of the test")
	})
	cl := s4uClient(t, kdc.addr)
	cl.Config.Realms = append(cl.Config.Realms, config.Realm{Realm: u2uReferralRealm, KDC: []string{kdc.addr}})

	tgt := u2uTicket(s4uKrbtgt, s4uRealm)
	verifying := u2uTicket(s4uKrbtgt, s4uRealm)
	verifying.EncPart.Cipher = []byte("the other principal's TGT")
	sname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "bob")

	req, err := messages.NewUser2UserTGSReq(cl.Credentials.CName(), s4uRealm, cl.Config, tgt, s4uSessionKey(), sname, false, verifying)
	require.NoError(t, err)

	_, _, err = cl.TGSExchange(req, s4uRealm, tgt, s4uSessionKey(), 0)
	require.Error(t, err)

	reqs := kdc.seen()
	require.Len(t, reqs, 2)

	followed := reqs[1]
	assert.Equal(t, u2uReferralRealm, followed.ReqBody.Realm)
	assert.True(t, followed.ReqBody.SName.Equal(sname))
	assert.True(t, types.IsFlagSet(&followed.ReqBody.KDCOptions, flags.EncTktInSkey), "the followed request is no longer user-to-user")
	require.Len(t, followed.ReqBody.AdditionalTickets, 1)
	assert.Equal(t, verifying.EncPart.Cipher, followed.ReqBody.AdditionalTickets[0].EncPart.Cipher)

	require.NotEmpty(t, followed.PAData)
	require.Equal(t, patype.PA_TGS_REQ, followed.PAData[0].PADataType)

	var ap messages.APReq

	require.NoError(t, ap.Unmarshal(followed.PAData[0].PADataValue))
	assert.Equal(t, []string{s4uKrbtgt, u2uReferralRealm}, ap.Ticket.SName.NameString, "the followed request is not made with the referral TGT")
}

const u2uReferralRealm = "OTHER.EXAMPLE"

func u2uTicket(service, realm string) messages.Ticket {
	return messages.Ticket{
		TktVNO:  iana.PVNO,
		Realm:   realm,
		SName:   types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{service, realm}},
		EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 1, Cipher: []byte("opaque to the client")},
	}
}
