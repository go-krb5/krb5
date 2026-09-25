package client

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
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

func TestLoginKeepsTheSaltTheKDCConfirmed(t *testing.T) {
	t.Parallel()

	kdc := newASKDC(t, func(n int, req messages.ASReq) []byte {
		if n == 1 {
			return preAuthRequiredReply(t, kdcSalt)
		}

		return asRepReply(t, req, kdcSalt)
	})
	cl := asClient(t, kdc.addr)

	require.NoError(t, cl.Login())
	require.NoError(t, cl.Login())

	reqs := kdc.seen()
	require.Len(t, reqs, 3)
	assert.NoError(t, decryptEncTimestamp(t, reqs[2], saltedKey(t)))
}

func TestLoginDoesNotKeepASaltTheKDCDidNotConfirm(t *testing.T) {
	t.Parallel()

	kdc := newASKDC(t, func(n int, req messages.ASReq) []byte {
		switch n {
		case 1:
			return preAuthRequiredReply(t, bogusSalt)
		case 2:
			return krbErrorReply(t, errorcode.KDC_ERR_PREAUTH_FAILED, nil)
		default:
			return asRepReply(t, req, "")
		}
	})
	cl := asClient(t, kdc.addr)

	require.Error(t, cl.Login())
	require.NoError(t, cl.Login())

	reqs := kdc.seen()
	require.Len(t, reqs, 3)
	assert.NoError(t, decryptEncTimestamp(t, reqs[2], defaultSaltKey(t, cl)))
}

func TestLoginKeepsTheSaltThatDecryptedTheReplyRatherThanTheErrors(t *testing.T) {
	t.Parallel()

	kdc := newASKDC(t, func(n int, req messages.ASReq) []byte {
		if n == 1 {
			return preAuthRequiredReply(t, bogusSalt)
		}

		return asRepReply(t, req, kdcSalt)
	})
	cl := asClient(t, kdc.addr)

	require.NoError(t, cl.Login())
	require.NoError(t, cl.Login())

	reqs := kdc.seen()
	require.Len(t, reqs, 3)
	assert.NoError(t, decryptEncTimestamp(t, reqs[2], saltedKey(t)))
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

const (
	kdcSalt   = "TEST.GOKRB5hostweb.test.gokrb5"
	bogusSalt = "EVIL.GOKRB5chosen"
	asRealm   = "TEST.GOKRB5"
	asUser    = "testuser"
	asPass    = "passwordvalue"
)

func saltedPreAuthError(t *testing.T, code int32) messages.KRBError {
	t.Helper()

	pas, err := asn1.Marshal(saltPAData(t, kdcSalt), asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	return messages.KRBError{ErrorCode: code, EData: pas}
}

func saltPAData(t *testing.T, salt string) types.PADataSequence {
	t.Helper()

	info := types.ETypeInfo2{{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Salt: salt}}

	v, err := asn1.Marshal(info, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	return types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: v}}
}

func defaultSaltKey(t *testing.T, cl *Client) types.EncryptionKey {
	t.Helper()

	key, _, err := crypto.GetKeyFromPassword(asPass, cl.Credentials.CName(), cl.Credentials.Domain(), etypeID.AES256_CTS_HMAC_SHA1_96, nil)
	require.NoError(t, err)

	return key
}

type asKDC struct {
	addr     string
	mu       sync.Mutex
	requests []messages.ASReq
}

func (k *asKDC) seen() []messages.ASReq {
	k.mu.Lock()
	defer k.mu.Unlock()

	return append([]messages.ASReq(nil), k.requests...)
}

func newASKDC(t *testing.T, answer func(n int, req messages.ASReq) []byte) *asKDC {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = ln.Close() })

	k := &asKDC{addr: ln.Addr().String()}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			k.serve(t, c, answer)
		}
	}()

	return k
}

func (k *asKDC) serve(t *testing.T, c net.Conn, answer func(n int, req messages.ASReq) []byte) {
	defer c.Close()

	hb := make([]byte, 4)
	if _, err := io.ReadFull(c, hb); err != nil {
		return
	}

	b := make([]byte, binary.BigEndian.Uint32(hb))
	if _, err := io.ReadFull(c, b); err != nil {
		return
	}

	var req messages.ASReq
	if err := req.Unmarshal(b); err != nil {
		t.Errorf("the KDC was sent something that is not an AS-REQ: %v", err)
		return
	}

	k.mu.Lock()
	k.requests = append(k.requests, req)
	n := len(k.requests)
	k.mu.Unlock()

	_, _ = c.Write(framed(answer(n, req)))
}

func asClient(t *testing.T, kdcAddr string) *Client {
	t.Helper()

	c := config.New()
	c.LibDefaults.DefaultRealm = asRealm
	c.LibDefaults.NoAddresses = true
	c.LibDefaults.UDPPreferenceLimit = 1
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96}
	c.Realms = []config.Realm{{Realm: asRealm, KDC: []string{kdcAddr}}}

	cl := NewWithPassword(asUser, asRealm, asPass, c)
	t.Cleanup(cl.Destroy)

	return cl
}

func krbErrorReply(t *testing.T, code int32, edata types.PADataSequence) []byte {
	t.Helper()

	kerr := messages.NewKRBError(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+asRealm), asRealm, code, "")

	if edata != nil {
		b, err := asn1.Marshal(edata, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
		require.NoError(t, err)

		kerr.EData = b
	}

	b, err := kerr.Marshal()
	require.NoError(t, err)

	return b
}

func preAuthRequiredReply(t *testing.T, salt string) []byte {
	t.Helper()

	return krbErrorReply(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, saltPAData(t, salt))
}

func asRepReply(t *testing.T, req messages.ASReq, salt string) []byte {
	t.Helper()

	var pas types.PADataSequence
	if salt != "" {
		pas = saltPAData(t, salt)
	}

	key, _, err := crypto.GetKeyFromPassword(asPass, req.ReqBody.CName, req.ReqBody.Realm, etypeID.AES256_CTS_HMAC_SHA1_96, pas)
	require.NoError(t, err)

	now := time.Now().UTC()
	enc := messages.EncKDCRepPart{
		Key:       types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)},
		Nonce:     req.ReqBody.Nonce,
		Flags:     types.NewKrbFlags(),
		AuthTime:  now,
		StartTime: now,
		EndTime:   now.Add(10 * time.Hour),
		SRealm:    req.ReqBody.Realm,
		SName:     req.ReqBody.SName,
	}

	b, err := enc.Marshal()
	require.NoError(t, err)

	ed, err := crypto.GetEncryptedData(b, key, keyusage.AS_REP_ENCPART, 0)
	require.NoError(t, err)

	rep := messages.ASRep{KDCRepFields: messages.KDCRepFields{
		PVNO: iana.PVNO, MsgType: msgtype.KRB_AS_REP, PAData: pas, CRealm: req.ReqBody.Realm, CName: req.ReqBody.CName,
		Ticket: messages.Ticket{
			TktVNO:  iana.PVNO,
			Realm:   req.ReqBody.Realm,
			SName:   req.ReqBody.SName,
			EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 1, Cipher: []byte("opaque to the client")},
		},
		EncPart: ed,
	}}

	out, err := rep.Marshal()
	require.NoError(t, err)

	return out
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
