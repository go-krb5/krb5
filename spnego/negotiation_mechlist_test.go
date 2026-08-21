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
	"github.com/go-krb5/krb5/types"
)

func TestAcceptSecContextSelectsKerberosWhenItIsNotTheFirstMechanism(t *testing.T) {
	t.Parallel()

	kt := testKeytab(t)

	// The optimistic mech token belongs to NTLM, the initiator's first choice, so it is not ours to read.
	init := NegTokenInit{
		MechTypes:      []asn1.ObjectIdentifier{oidNTLMSSP, gssapi.OIDKRB5.OID()},
		MechTokenBytes: []byte("NTLMSSP\x00\x01\x00\x00\x00"),
	}

	ok, _, status := SPNEGOService(kt).AcceptSecContext(spnegoInitToken(t, init))

	assert.False(t, ok)
	assert.Equal(t, gssapi.StatusContinueNeeded, status.Code, "message was %q", status.Message)
}

func TestAcceptSecContextStillRejectsAListWithoutKerberos(t *testing.T) {
	t.Parallel()

	kt := testKeytab(t)

	init := NegTokenInit{
		MechTypes:      []asn1.ObjectIdentifier{oidNTLMSSP},
		MechTokenBytes: []byte("NTLMSSP\x00\x01\x00\x00\x00"),
	}

	ok, _, status := SPNEGOService(kt).AcceptSecContext(spnegoInitToken(t, init))

	assert.False(t, ok)
	assert.Equal(t, gssapi.StatusBadMech, status.Code)
}

func TestAcceptSecContextStillAcceptsTheOptimisticKerberosToken(t *testing.T) {
	t.Parallel()

	mtb, _, kt := krb5MechToken(t)

	init := NegTokenInit{
		MechTypes:      []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
		MechTokenBytes: mtb,
	}

	ok, _, status := SPNEGOService(kt).AcceptSecContext(spnegoInitToken(t, init))

	assert.True(t, ok, "status was %d: %s", status.Code, status.Message)
	assert.Equal(t, gssapi.StatusComplete, status.Code)
}

func TestMechListMICPayloadIsTheUntaggedMechTypeList(t *testing.T) {
	t.Parallel()

	mechs := []asn1.ObjectIdentifier{oidNTLMSSP, gssapi.OIDKRB5.OID()}

	payload, err := mechListMICPayload(nil, mechs)
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	assert.EqualValues(t, 0x30, payload[0], "expected a SEQUENCE, not the [0] context tag 0xa0")

	init := NegTokenInit{MechTypes: mechs, MechTokenBytes: []byte{0xde, 0xad}}

	b, err := init.Marshal()
	require.NoError(t, err)

	var outer asn1.RawValue

	_, err = asn1.Unmarshal(b, &outer)
	require.NoError(t, err)

	var field0 struct {
		MechTypes asn1.RawValue `asn1:"explicit,tag:0"`
	}

	_, err = asn1.Unmarshal(outer.Bytes, &field0)
	require.NoError(t, err)

	assert.Equal(t, field0.MechTypes.Bytes, payload)
}

func TestMechListMICPayloadPrefersTheOctetsReceived(t *testing.T) {
	t.Parallel()

	raw := []byte{0x30, 0x00}

	payload, err := mechListMICPayload(raw, []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()})
	require.NoError(t, err)

	assert.Equal(t, raw, payload)
}

func TestNegTokenInitVerifiesACorrectMechListMIC(t *testing.T) {
	t.Parallel()

	init, kt, _ := negTokenInitWithMIC(t)

	ok, _, status := SPNEGOService(kt).AcceptSecContext(spnegoInitToken(t, init))

	assert.True(t, ok, "status was %d: %s", status.Code, status.Message)
	assert.Equal(t, gssapi.StatusComplete, status.Code)
}

func TestNegTokenInitRejectsAnIncorrectMechListMIC(t *testing.T) {
	t.Parallel()

	init, kt, _ := negTokenInitWithMIC(t)

	init.MechListMIC[len(init.MechListMIC)-1] ^= 0xff

	ok, _, status := SPNEGOService(kt).AcceptSecContext(spnegoInitToken(t, init))

	assert.False(t, ok)
	assert.Equal(t, gssapi.StatusDefectiveToken, status.Code)
}

func TestNegTokenInitRejectsAMechListMICOverADifferentList(t *testing.T) {
	t.Parallel()

	init, kt, _ := negTokenInitWithMIC(t)

	init.MechTypes = append(init.MechTypes, oidNTLMSSP)

	ok, _, status := SPNEGOService(kt).AcceptSecContext(spnegoInitToken(t, init))

	assert.False(t, ok)
	assert.Equal(t, gssapi.StatusDefectiveToken, status.Code)
}

func TestAcceptorReturnsAMechListMIC(t *testing.T) {
	t.Parallel()

	init, kt, key := negTokenInitWithMIC(t)

	s := SPNEGOService(kt)

	ok, _, status := s.AcceptSecContext(spnegoInitToken(t, init))
	require.True(t, ok, "status was %d: %s", status.Code, status.Message)

	mic := s.MechListMIC()
	require.NotEmpty(t, mic, "the acceptor must return a mechListMIC when the initiator sent one")

	payload, err := mechListMICPayload(nil, init.MechTypes)
	require.NoError(t, err)

	assert.NoError(t, verifyMechListMIC(mic, payload, key, true))
}

func TestAcceptorReturnsNoMechListMICWhenTheInitiatorSentNone(t *testing.T) {
	t.Parallel()

	mtb, _, kt := krb5MechToken(t)

	init := NegTokenInit{MechTypes: []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}, MechTokenBytes: mtb}

	s := SPNEGOService(kt)

	ok, _, status := s.AcceptSecContext(spnegoInitToken(t, init))
	require.True(t, ok, "status was %d: %s", status.Code, status.Message)

	assert.Empty(t, s.MechListMIC())
}

func TestNegTokenRespVerifiesAMechListMICAgainstTheRetainedList(t *testing.T) {
	t.Parallel()

	s, mechs, key, mtb := negotiationInProgress(t)

	mic := mechListMICOver(t, mechs, key, false)

	ok, _, status := s.AcceptSecContext(spnegoRespToken(t, NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptIncomplete),
		ResponseToken: mtb,
		MechListMIC:   mic,
	}))

	assert.True(t, ok, "status was %d: %s", status.Code, status.Message)
	assert.Equal(t, gssapi.StatusComplete, status.Code)
	assert.NotEmpty(t, s.MechListMIC(), "the acceptor owes a mechListMIC in reply")
}

func TestNegTokenRespRejectsAMechListMICOverADifferentList(t *testing.T) {
	t.Parallel()

	s, _, key, mtb := negotiationInProgress(t)

	mic := mechListMICOver(t, []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}, key, false)

	ok, _, status := s.AcceptSecContext(spnegoRespToken(t, NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptIncomplete),
		ResponseToken: mtb,
		MechListMIC:   mic,
	}))

	assert.False(t, ok)
	assert.Equal(t, gssapi.StatusDefectiveToken, status.Code)
}

func TestNegTokenRespRejectsAMechListMICWithoutTheList(t *testing.T) {
	t.Parallel()

	mtb, key, kt := krb5MechToken(t)

	mic := mechListMICOver(t, []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}, key, false)

	ok, _, status := SPNEGOService(kt).AcceptSecContext(spnegoRespToken(t, NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptIncomplete),
		ResponseToken: mtb,
		MechListMIC:   mic,
	}))

	assert.False(t, ok)
	assert.Equal(t, gssapi.StatusDefectiveToken, status.Code)
	assert.Contains(t, status.Message, "did not retain")
}

func negotiationInProgress(t *testing.T) (*SPNEGO, []asn1.ObjectIdentifier, types.EncryptionKey, []byte) {
	t.Helper()

	mtb, key, kt := krb5MechToken(t)
	mechs := []asn1.ObjectIdentifier{oidNTLMSSP, gssapi.OIDKRB5.OID()}

	s := SPNEGOService(kt)

	_, _, status := s.AcceptSecContext(spnegoInitToken(t, NegTokenInit{
		MechTypes:      mechs,
		MechTokenBytes: []byte("NTLMSSP\x00\x01\x00\x00\x00"),
	}))
	require.Equal(t, gssapi.StatusContinueNeeded, status.Code, "message was %q", status.Message)

	return s, mechs, key, mtb
}

func mechListMICOver(t *testing.T, mechs []asn1.ObjectIdentifier, key types.EncryptionKey, fromAcceptor bool) []byte {
	t.Helper()

	payload, err := mechListMICPayload(nil, mechs)
	require.NoError(t, err)

	mic, err := newMechListMIC(payload, key, fromAcceptor)
	require.NoError(t, err)

	return mic
}

func spnegoRespToken(t *testing.T, resp NegTokenResp) *SPNEGOToken {
	t.Helper()

	b, err := resp.Marshal()
	require.NoError(t, err)

	var st SPNEGOToken

	require.NoError(t, st.Unmarshal(b))

	return &st
}

func krb5MechToken(t *testing.T) ([]byte, types.EncryptionKey, *keytab.Keytab) {
	t.Helper()

	kt := testKeytab(t)
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.test.gokrb5")
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

	b, err := mt.Marshal()
	require.NoError(t, err)

	return b, sessionKey, kt
}

func testKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()

	kt := keytab.New()
	require.NoError(t, kt.AddEntry("HTTP/host.test.gokrb5", "TEST.GOKRB5", "servicepassword",
		time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96))

	return kt
}

func spnegoInitToken(t *testing.T, init NegTokenInit) *SPNEGOToken {
	t.Helper()

	b, err := (&SPNEGOToken{Init: true, NegTokenInit: init}).Marshal()
	require.NoError(t, err)

	var st SPNEGOToken

	require.NoError(t, st.Unmarshal(b))

	return &st
}

func negTokenInitWithMIC(t *testing.T) (NegTokenInit, *keytab.Keytab, types.EncryptionKey) {
	t.Helper()

	mtb, key, kt := krb5MechToken(t)

	mechs := []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID(), oidNTLMSSP}

	payload, err := mechListMICPayload(nil, mechs)
	require.NoError(t, err)

	mic, err := newMechListMIC(payload, key, false)
	require.NoError(t, err)

	return NegTokenInit{MechTypes: mechs, MechTokenBytes: mtb, MechListMIC: mic}, kt, key
}

var oidNTLMSSP = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
