package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
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
