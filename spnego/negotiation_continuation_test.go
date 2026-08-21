package spnego

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/types"
)

func TestAcceptSecContextAcceptsAContinuationWithoutSupportedMech(t *testing.T) {
	t.Parallel()

	b, kt := continuationToken(t)

	var st SPNEGOToken

	require.NoError(t, st.Unmarshal(b))
	require.True(t, st.Resp)
	require.Empty(t, st.NegTokenResp.SupportedMech, "an initiator does not send supportedMech")

	ok, _, status := SPNEGOService(kt).AcceptSecContext(&st)

	assert.True(t, ok, "status was %d: %s", status.Code, status.Message)
	assert.Equal(t, gssapi.StatusComplete, status.Code)
}

func TestNegTokenRespVerifyAcceptsAContinuationWithoutSupportedMech(t *testing.T) {
	t.Parallel()

	b, kt := continuationToken(t)

	_, nt, err := UnmarshalNegToken(b)
	require.NoError(t, err)

	resp := nt.(NegTokenResp)
	resp.settings = service.NewSettings(kt)

	ok, status := resp.Verify()

	assert.True(t, ok, "status was %d: %s", status.Code, status.Message)
	assert.Equal(t, gssapi.StatusComplete, status.Code)
}

func TestNegTokenRespVerifyStillRejectsAnUnsupportedMechanism(t *testing.T) {
	t.Parallel()

	resp := NegTokenResp{SupportedMech: gssapi.OIDGSSIAKerb.OID(), ResponseToken: []byte{0x60, 0x01, 0x00}}

	ok, status := resp.Verify()

	assert.False(t, ok)
	assert.Equal(t, gssapi.StatusBadMech, status.Code)
}

func continuationToken(t *testing.T) ([]byte, *keytab.Keytab) {
	t.Helper()

	kt := keytab.New()
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.test.gokrb5")

	require.NoError(t, kt.AddEntry("HTTP/host.test.gokrb5", "TEST.GOKRB5", "servicepassword",
		time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96))

	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser")
	now := time.Now().UTC()

	tkt, sessionKey, err := messages.NewTicket(cname, "TEST.GOKRB5", sname, "TEST.GOKRB5",
		types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		now, now, now.Add(time.Hour), now.Add(2*time.Hour))
	require.NoError(t, err)

	auth, err := types.NewAuthenticator("TEST.GOKRB5", cname)
	require.NoError(t, err)

	apreq, err := messages.NewAPReq(tkt, sessionKey, auth)
	require.NoError(t, err)

	mt := KRB5Token{OID: gssapi.OIDKRB5.OID(), tokID: []byte{0x01, 0x00}, APReq: apreq}

	mb, err := mt.Marshal()
	require.NoError(t, err)

	resp := NegTokenResp{NegState: asn1.Enumerated(NegStateAcceptIncomplete), ResponseToken: mb}

	b, err := resp.Marshal()
	require.NoError(t, err)

	return b, kt
}
