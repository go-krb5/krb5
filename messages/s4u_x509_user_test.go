package messages

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/types"
)

func TestNewS4U2SelfTGSReqCarriesAPAS4UX509UserBoundToTheRequest(t *testing.T) {
	t.Parallel()

	req, user, key := protocolTransition(t)

	p := requestPAS4UX509User(t, req)
	assert.Equal(t, req.ReqBody.Nonce, p.UserID.Nonce)
	assert.True(t, p.UserID.CName.Equal(user))
	assert.Equal(t, s4uRealm, p.UserID.CRealm)
	assert.Empty(t, p.UserID.SubjectCertificate)

	// MS-SFU 2.2.2: USE_REPLY_KEY_USAGE is 0x20000000.
	assert.Equal(t, asn1.BitString{Bytes: []byte{0x20, 0, 0, 0}, BitLength: 32}, p.UserID.Options)

	et, err := crypto.GetEType(key.KeyType)
	require.NoError(t, err)

	b, err := p.UserID.Marshal()
	require.NoError(t, err)

	assert.Equal(t, et.GetHashID(), p.Cksum.CksumType)
	assert.True(t, et.VerifyChecksum(key.KeyValue, b, p.Cksum.Checksum, keyusage.PA_S4U_X509_USER_REQUEST))
}

func TestTGSRepVerifyProtocolTransitionAcceptsTheKDCsEcho(t *testing.T) {
	t.Parallel()

	req, _, key := protocolTransition(t)

	testCases := []struct {
		name  string
		usage uint32
		enc   bool
	}{
		{"InThePAData", keyusage.PA_S4U_X509_USER_REPLY, false},
		{"InTheEncryptedPAData", keyusage.PA_S4U_X509_USER_REPLY, true},
		{"UnderTheRequestKeyUsage", keyusage.PA_S4U_X509_USER_REQUEST, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			echo := kdcEcho(t, req, key, tc.usage, nil)

			var rep TGSRep
			if tc.enc {
				rep.DecryptedEncPart.EncPAData = types.PADataSequence{echo}
			} else {
				rep.PAData = types.PADataSequence{echo}
			}

			assert.NoError(t, rep.VerifyProtocolTransition(req, key))
		})
	}
}

func TestTGSRepVerifyProtocolTransitionRefusesAReplyWithoutTheEcho(t *testing.T) {
	t.Parallel()

	req, _, key := protocolTransition(t)

	var rep TGSRep

	assert.ErrorIs(t, rep.VerifyProtocolTransition(req, key), ErrProtocolTransitionUnconfirmed)
}

func TestTGSRepVerifyProtocolTransitionRefusesAnEchoForAnotherUser(t *testing.T) {
	t.Parallel()

	req, _, key := protocolTransition(t)

	rep := TGSRep{KDCRepFields{PAData: types.PADataSequence{kdcEcho(t, req, key, keyusage.PA_S4U_X509_USER_REPLY, func(id *S4UUserID) {
		id.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "bob")
	})}}}

	assert.Error(t, rep.VerifyProtocolTransition(req, key))
}

func TestTGSRepVerifyProtocolTransitionRefusesAnEchoForAnotherRequest(t *testing.T) {
	t.Parallel()

	req, _, key := protocolTransition(t)

	rep := TGSRep{KDCRepFields{PAData: types.PADataSequence{kdcEcho(t, req, key, keyusage.PA_S4U_X509_USER_REPLY, func(id *S4UUserID) {
		id.Nonce++
	})}}}

	assert.Error(t, rep.VerifyProtocolTransition(req, key))
}

func TestTGSRepVerifyProtocolTransitionRefusesAnEchoWithABadChecksum(t *testing.T) {
	t.Parallel()

	req, _, key := protocolTransition(t)

	echo := kdcEcho(t, req, key, keyusage.PA_S4U_X509_USER_REPLY, nil)

	var p PAS4UX509User

	require.NoError(t, p.Unmarshal(echo.PADataValue))

	p.Cksum.Checksum[0] ^= 0xff

	forged, err := p.PAData()
	require.NoError(t, err)

	rep := TGSRep{KDCRepFields{PAData: types.PADataSequence{forged}}}

	err = rep.VerifyProtocolTransition(req, key)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrProtocolTransitionUnconfirmed)
}

func TestTGSRepVerifyProtocolTransitionRefusesARequestWithoutPAS4UX509User(t *testing.T) {
	t.Parallel()

	req, _, key := protocolTransition(t)
	echo := kdcEcho(t, req, key, keyusage.PA_S4U_X509_USER_REPLY, nil)

	var kept types.PADataSequence

	for _, pa := range req.PAData {
		if pa.PADataType != patype.PA_FOR_X509_USER {
			kept = append(kept, pa)
		}
	}

	req.PAData = kept

	rep := TGSRep{KDCRepFields{PAData: types.PADataSequence{echo}}}

	assert.Error(t, rep.VerifyProtocolTransition(req, key))
}

func protocolTransition(t *testing.T) (TGSReq, types.PrincipalName, types.EncryptionKey) {
	t.Helper()

	c, service, tgt, key := s4uFixture(t)
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")

	req, err := NewS4U2SelfTGSReq(service, s4uRealm, s4uRealm, c, tgt, key, user, s4uRealm)
	require.NoError(t, err)

	return req, user, key
}

func requestPAS4UX509User(t *testing.T, req TGSReq) PAS4UX509User {
	t.Helper()

	for _, pa := range req.PAData {
		if pa.PADataType == patype.PA_FOR_X509_USER {
			var p PAS4UX509User

			require.NoError(t, p.Unmarshal(pa.PADataValue))

			return p
		}
	}

	t.Fatal("the request carries no PA-S4U-X509-USER")

	return PAS4UX509User{}
}

func kdcEcho(t *testing.T, req TGSReq, key types.EncryptionKey, usage uint32, edit func(*S4UUserID)) types.PAData {
	t.Helper()

	id := requestPAS4UX509User(t, req).UserID
	id.SubjectCertificate = nil

	if usage != keyusage.PA_S4U_X509_USER_REPLY {
		id.Options = asn1.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 32}
	}

	if edit != nil {
		edit(&id)
	}

	b, err := id.Marshal()
	require.NoError(t, err)

	et, err := crypto.GetEType(key.KeyType)
	require.NoError(t, err)

	cs, err := et.GetChecksumHash(key.KeyValue, b, usage)
	require.NoError(t, err)

	echo := PAS4UX509User{UserID: id, Cksum: types.Checksum{CksumType: et.GetHashID(), Checksum: cs}}

	pa, err := echo.PAData()
	require.NoError(t, err)

	return pa
}
