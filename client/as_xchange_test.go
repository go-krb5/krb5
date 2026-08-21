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

func countPAData(pas types.PADataSequence, t int32) int {
	var n int

	for _, pa := range pas {
		if pa.PADataType == t {
			n++
		}
	}

	return n
}
