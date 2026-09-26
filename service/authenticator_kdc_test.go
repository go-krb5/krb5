package service

import (
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/identity"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

func TestBasicAuthenticatorAcceptsATicketIssuedToTheUser(t *testing.T) {
	t.Parallel()

	kt := basicServiceKeytab(t)
	now := time.Now().UTC()

	i, ok, err := basicAuthenticate(t, kt, basicUser, basicTicket{cname: basicUser, start: now, end: now.Add(time.Hour), service: kt})

	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, basicUser, i.UserName())
	assert.Equal(t, basicRealm, i.Domain())
}

func TestBasicAuthenticatorRefusesATicketIssuedToSomeoneElse(t *testing.T) {
	t.Parallel()

	kt := basicServiceKeytab(t)
	now := time.Now().UTC()

	i, ok, err := basicAuthenticate(t, kt, "administrator", basicTicket{cname: "attacker", start: now, end: now.Add(time.Hour), service: kt})

	assert.Error(t, err)
	assert.False(t, ok)
	assert.Nil(t, i)
}

func TestBasicAuthenticatorRefusesAnExpiredTicket(t *testing.T) {
	t.Parallel()

	kt := basicServiceKeytab(t)
	now := time.Now().UTC()

	i, ok, err := basicAuthenticate(t, kt, basicUser, basicTicket{cname: basicUser, start: now.Add(-73 * time.Hour), end: now.Add(-72 * time.Hour), service: kt})

	assert.Error(t, err)
	assert.False(t, ok)
	assert.Nil(t, i)
}

func TestBasicAuthenticatorLeavesNoRenewalGoroutineBehind(t *testing.T) {
	kt := basicServiceKeytab(t)
	now := time.Now().UTC()

	before := renewalGoroutines()

	for range 5 {
		i, ok, err := basicAuthenticate(t, kt, basicUser, basicTicket{cname: basicUser, start: now, end: now.Add(time.Hour), service: kt})
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, basicUser, i.UserName())
	}

	assert.Eventually(t, func() bool { return renewalGoroutines() <= before }, 2*time.Second, 10*time.Millisecond,
		"%d TGT renewal goroutines are still running after the logins, %d before", renewalGoroutines(), before)
}

func renewalGoroutines() int {
	b := make([]byte, 1<<20)

	return strings.Count(string(b[:runtime.Stack(b, true)]), "(*Client).enableAutoSessionRenewal.func")
}

const (
	basicRealm   = "TEST.GOKRB5"
	basicService = "HTTP/host.test.gokrb5"
	basicUser    = "alice"
)

type basicTicket struct {
	cname   string
	start   time.Time
	end     time.Time
	service *keytab.Keytab
}

func basicAuthenticate(t *testing.T, kt *keytab.Keytab, username string, tkt basicTicket) (identity.Identity, bool, error) {
	t.Helper()

	addr := newBasicKDC(t, "password", tkt)

	c := config.New()
	c.LibDefaults.DefaultRealm = basicRealm
	c.LibDefaults.NoAddresses = true
	c.LibDefaults.UDPPreferenceLimit = 1
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96}
	c.LibDefaults.PermittedEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96}
	c.Realms = []config.Realm{{Realm: basicRealm, KDC: []string{addr}}}
	c.DomainRealm[".test.gokrb5"] = basicRealm

	header := base64.StdEncoding.EncodeToString([]byte(username + "@" + basicRealm + ":password"))
	a := NewKRB5BasicAuthenticator(header, c, NewSettings(kt, SName(basicService)), nil)

	return a.Authenticate()
}

func basicServiceKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()

	kt := keytab.New()
	require.NoError(t, kt.AddEntry(basicService, basicRealm, "service key", time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96))

	return kt
}

func newBasicKDC(t *testing.T, password string, tkt basicTicket) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = ln.Close() })

	tgtKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef0123456789abcdef")}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			serveBasicKDC(t, c, password, tgtKey, tkt)
		}
	}()

	return ln.Addr().String()
}

func serveBasicKDC(t *testing.T, c net.Conn, password string, tgtKey types.EncryptionKey, tkt basicTicket) {
	defer c.Close()

	hb := make([]byte, 4)
	if _, err := io.ReadFull(c, hb); err != nil {
		return
	}

	b := make([]byte, binary.BigEndian.Uint32(hb))
	if _, err := io.ReadFull(c, b); err != nil {
		return
	}

	var out []byte

	var asReq messages.ASReq
	if err := asReq.Unmarshal(b); err == nil {
		out = basicASRep(t, asReq, password, tgtKey)
	} else {
		var tgsReq messages.TGSReq
		if err := tgsReq.Unmarshal(b); err != nil {
			t.Errorf("the KDC was sent neither an AS-REQ nor a TGS-REQ: %v", err)
			return
		}

		out = basicTGSRep(t, tgsReq, tgtKey, tkt)
	}

	rb := binary.BigEndian.AppendUint32(nil, uint32(len(out))) //nolint:gosec
	_, _ = c.Write(append(rb, out...))
}

func basicASRep(t *testing.T, req messages.ASReq, password string, tgtKey types.EncryptionKey) []byte {
	t.Helper()

	key, _, err := crypto.GetKeyFromPassword(password, req.ReqBody.CName, req.ReqBody.Realm, etypeID.AES256_CTS_HMAC_SHA1_96, types.PADataSequence{})
	require.NoError(t, err)

	now := time.Now().UTC()
	enc := messages.EncKDCRepPart{
		Key:       tgtKey,
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
		PVNO: iana.PVNO, MsgType: msgtype.KRB_AS_REP, CRealm: req.ReqBody.Realm, CName: req.ReqBody.CName,
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

func basicTGSRep(t *testing.T, req messages.TGSReq, tgtKey types.EncryptionKey, tkt basicTicket) []byte {
	t.Helper()

	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, tkt.cname)

	ticket, key, err := messages.NewTicket(cname, basicRealm, req.ReqBody.SName, req.ReqBody.Realm, types.NewKrbFlags(), tkt.service,
		etypeID.AES256_CTS_HMAC_SHA1_96, 1, tkt.start, tkt.start, tkt.end, tkt.end)
	require.NoError(t, err)

	now := time.Now().UTC()
	enc := messages.EncKDCRepPart{
		Key:       key,
		Nonce:     req.ReqBody.Nonce,
		Flags:     types.NewKrbFlags(),
		AuthTime:  now,
		StartTime: now,
		EndTime:   now.Add(time.Hour),
		SRealm:    req.ReqBody.Realm,
		SName:     req.ReqBody.SName,
	}
	b, err := enc.Marshal()
	require.NoError(t, err)

	ed, err := crypto.GetEncryptedData(b, tgtKey, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
	require.NoError(t, err)

	rep := messages.TGSRep{KDCRepFields: messages.KDCRepFields{
		PVNO: iana.PVNO, MsgType: msgtype.KRB_TGS_REP, CRealm: basicRealm, CName: req.ReqBody.CName, Ticket: ticket, EncPart: ed,
	}}
	out, err := rep.Marshal()
	require.NoError(t, err)

	return out
}
