package client

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

const (
	s4uRealm   = "TEST.GOKRB5"
	s4uService = "HTTP/front.test.gokrb5"
	s4uTarget  = "HTTP/back.test.gokrb5"
	s4uUser    = "alice"
	s4uKrbtgt  = "krbtgt"
)

// s4uKDC is a KDC on loopback that answers each TGS-REQ with what answer returns, and remembers every request it
// was sent. It decides nothing itself: the tests say what a real KDC would have said, and check what the client
// asked.
type s4uKDC struct {
	addr string

	mu       sync.Mutex
	requests []messages.TGSReq
}

func newS4UKDC(t *testing.T, answer func(n int, req messages.TGSReq) []byte) *s4uKDC {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { _ = ln.Close() })

	k := &s4uKDC{addr: ln.Addr().String()}

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

func (k *s4uKDC) serve(t *testing.T, c net.Conn, answer func(n int, req messages.TGSReq) []byte) {
	defer c.Close()

	hb := make([]byte, 4)
	if _, err := io.ReadFull(c, hb); err != nil {
		return
	}

	b := make([]byte, binary.BigEndian.Uint32(hb))
	if _, err := io.ReadFull(c, b); err != nil {
		return
	}

	var req messages.TGSReq
	if err := req.Unmarshal(b); err != nil {
		t.Errorf("the KDC was sent something that is not a TGS-REQ: %v", err)
		return
	}

	k.mu.Lock()
	k.requests = append(k.requests, req)
	n := len(k.requests)
	k.mu.Unlock()

	_, _ = c.Write(framed(answer(n, req)))
}

func (k *s4uKDC) seen() []messages.TGSReq {
	k.mu.Lock()
	defer k.mu.Unlock()

	return append([]messages.TGSReq(nil), k.requests...)
}

// s4uClient is the front end service, logged in: its TGT session is in place and valid, so the only exchanges the
// tests see are the S4U ones.
func s4uClient(t *testing.T, kdcAddr string) *Client {
	t.Helper()

	c := config.New()
	c.LibDefaults.DefaultRealm = s4uRealm
	c.LibDefaults.NoAddresses = true
	c.LibDefaults.UDPPreferenceLimit = 1
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96}
	c.Realms = []config.Realm{{Realm: s4uRealm, KDC: []string{kdcAddr}}}
	c.DomainRealm[".test.gokrb5"] = s4uRealm
	c.DomainRealm[".other.example"] = "OTHER.EXAMPLE"

	cl := NewWithPassword(s4uService, s4uRealm, "not used", c)

	now := time.Now().UTC()
	cl.sessions.update(&session{
		realm:     s4uRealm,
		authTime:  now.Add(-time.Hour),
		endTime:   now.Add(9 * time.Hour),
		renewTill: now.Add(7 * 24 * time.Hour),
		tgt: messages.Ticket{
			TktVNO:  iana.PVNO,
			Realm:   s4uRealm,
			SName:   types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{s4uKrbtgt, s4uRealm}},
			EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 1, Cipher: []byte("opaque to the client")},
		},
		sessionKey: s4uSessionKey(),
		flags:      types.NewKrbFlags(),
	})

	return cl
}

// reply is what a KDC sends for req: a ticket to the service req names, in the name cname of this realm, with the reply encrypted
// under the TGT session key the way RFC 4120 Section 5.4.2 has it.
func reply(t *testing.T, req messages.TGSReq, sessionKey types.EncryptionKey, cname types.PrincipalName, forwardable bool) []byte {
	t.Helper()

	kt := keytab.New()
	require.NoError(t, kt.AddEntry(req.ReqBody.SName.PrincipalNameString(), req.ReqBody.Realm, "service key", time.Now(), 1, etypeID.AES256_CTS_HMAC_SHA1_96))

	tktFlags := types.NewKrbFlags()
	if forwardable {
		types.SetFlag(&tktFlags, flags.Forwardable)
	}

	now := time.Now().UTC()
	tkt, key, err := messages.NewTicket(cname, s4uRealm, req.ReqBody.SName, req.ReqBody.Realm, tktFlags, kt,
		etypeID.AES256_CTS_HMAC_SHA1_96, 1, now, now, now.Add(time.Hour), now.Add(time.Hour))
	require.NoError(t, err)

	enc := messages.EncKDCRepPart{
		Key:       key,
		Nonce:     req.ReqBody.Nonce,
		Flags:     tktFlags,
		AuthTime:  now,
		StartTime: now,
		EndTime:   now.Add(time.Hour),
		SRealm:    req.ReqBody.Realm,
		SName:     req.ReqBody.SName,
	}
	b, err := enc.Marshal()
	require.NoError(t, err)

	ed, err := crypto.GetEncryptedData(b, sessionKey, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
	require.NoError(t, err)

	rep := messages.TGSRep{KDCRepFields: messages.KDCRepFields{
		PVNO: iana.PVNO, MsgType: msgtype.KRB_TGS_REP, CRealm: s4uRealm, CName: cname, Ticket: tkt, EncPart: ed,
	}}
	out, err := rep.Marshal()
	require.NoError(t, err)

	return out
}

func refusal(t *testing.T, code int32, text string) []byte {
	t.Helper()

	kerr := messages.NewKRBError(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, s4uKrbtgt+"/"+s4uRealm), s4uRealm, code, text)
	b, err := kerr.Marshal()
	require.NoError(t, err)

	return b
}

func alice() types.PrincipalName { return types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, s4uUser) }

// s4uSessionKey is the session key of the front end's TGT, which the KDC encrypts its replies under.
func s4uSessionKey() types.EncryptionKey {
	return types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef0123456789abcdef")}
}

func TestImpersonateAsksForItselfInTheUsersNameThenForTheTarget(t *testing.T) {
	t.Parallel()

	kdc := newS4UKDC(t, func(n int, req messages.TGSReq) []byte {
		return reply(t, req, s4uSessionKey(), alice(), n == 1)
	})
	cl := s4uClient(t, kdc.addr)

	imp, err := cl.Impersonate(alice(), s4uRealm, s4uTarget)
	require.NoError(t, err)

	reqs := kdc.seen()
	require.Len(t, reqs, 2)

	// S4U2Self: a ticket to the service itself, carrying PA-FOR-USER signed with the TGT session key.
	self := reqs[0]
	assert.Equal(t, s4uService, self.ReqBody.SName.PrincipalNameString())
	assert.True(t, types.IsFlagSet(&self.ReqBody.KDCOptions, flags.Forwardable))

	var pfu types.PAForUser

	for _, pa := range self.PAData {
		if pa.PADataType == patype.PA_FOR_USER {
			require.NoError(t, pfu.Unmarshal(pa.PADataValue))
		}
	}

	assert.Equal(t, s4uUser, pfu.UserName.PrincipalNameString())
	assert.NoError(t, pfu.Verify(s4uSessionKey()))

	// S4U2Proxy: the target, with the S4U2Self ticket as evidence under cname-in-addl-tkt.
	proxy := reqs[1]
	assert.Equal(t, s4uTarget, proxy.ReqBody.SName.PrincipalNameString())
	assert.True(t, types.IsFlagSet(&proxy.ReqBody.KDCOptions, flags.CNameInAddlTkt))
	require.Len(t, proxy.ReqBody.AdditionalTickets, 1)
	assert.Equal(t, s4uService, proxy.ReqBody.AdditionalTickets[0].SName.PrincipalNameString())
	assert.False(t, proxy.PAData.Contains(patype.PA_FOR_USER))

	assert.Equal(t, s4uTarget, imp.Ticket.SName.PrincipalNameString())
	assert.Equal(t, s4uUser, imp.CName.PrincipalNameString())
	assert.Equal(t, s4uRealm, imp.CRealm)
	assert.NotEmpty(t, imp.SessionKey.KeyValue)
	assert.WithinDuration(t, time.Now().Add(time.Hour), imp.EndTime, time.Minute)

	// Neither ticket is the client's own, so neither may answer its own requests.
	_, _, cached := cl.GetCachedTicket(s4uTarget)
	assert.False(t, cached, "a ticket in another principal's name was put in the client's cache")
}

func TestImpersonateStopsWhenTheEvidenceIsNotForwardable(t *testing.T) {
	t.Parallel()

	kdc := newS4UKDC(t, func(_ int, req messages.TGSReq) []byte {
		return reply(t, req, s4uSessionKey(), alice(), false)
	})
	cl := s4uClient(t, kdc.addr)

	_, err := cl.Impersonate(alice(), s4uRealm, s4uTarget)
	require.ErrorIs(t, err, ErrEvidenceNotForwardable)
	assert.Contains(t, err.Error(), "ok_to_auth_as_delegate")
	assert.Len(t, kdc.seen(), 1, "the target was asked for although the evidence could not be delegated")
}

func TestImpersonateSurfacesTheKDCsRefusal(t *testing.T) {
	t.Parallel()

	for name, refuseAt := range map[string]int{"protocol transition": 1, "constrained delegation": 2} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			kdc := newS4UKDC(t, func(n int, req messages.TGSReq) []byte {
				if n == refuseAt {
					return refusal(t, errorcode.KDC_ERR_BADOPTION, "not permitted to delegate")
				}

				return reply(t, req, s4uSessionKey(), alice(), true)
			})
			cl := s4uClient(t, kdc.addr)

			_, err := cl.Impersonate(alice(), s4uRealm, s4uTarget)
			require.Error(t, err)

			var kerr messages.KRBError
			require.True(t, errors.As(err, &kerr), "the KDC's KRB_ERROR is not recoverable from %v", err)
			assert.Equal(t, errorcode.KDC_ERR_BADOPTION, kerr.ErrorCode)
			assert.Contains(t, err.Error(), name)
			assert.Contains(t, err.Error(), s4uUser)
		})
	}
}

// TestAReplyThatIsNotTheTicketAskedForIsRefused covers what the client checks in a reply before it hands a ticket
// back: that it is in the user's name, that it decrypts under this exchange's key, and that it is a TGS-REP at all.
func TestAReplyThatIsNotTheTicketAskedForIsRefused(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		answer func(t *testing.T, req messages.TGSReq, sessionKey types.EncryptionKey) []byte
		want   string
	}{
		"in the service's own name": {
			answer: func(t *testing.T, req messages.TGSReq, sessionKey types.EncryptionKey) []byte {
				return reply(t, req, s4uSessionKey(), types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, s4uService), true)
			},
			want: "not in the name it was requested for",
		},
		"under another key": {
			answer: func(t *testing.T, req messages.TGSReq, _ types.EncryptionKey) []byte {
				other := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}

				return reply(t, req, other, alice(), true)
			},
			want: "decrypt",
		},
		"not a reply": {
			answer: func(*testing.T, messages.TGSReq, types.EncryptionKey) []byte {
				return []byte{0x30, 0x03, 0x02, 0x01, 0x05}
			},
			want: "process the TGS_REP",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			kdc := newS4UKDC(t, func(_ int, req messages.TGSReq) []byte { return tc.answer(t, req, s4uSessionKey()) })
			cl := s4uClient(t, kdc.addr)

			_, _, err := cl.S4U2Self(alice(), s4uRealm)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestAnotherRealmIsRefusedWithoutAskingTheKDC: referrals are not followed, so a user or a target in another realm is
// refused before a request is made rather than sent where it cannot be answered.
func TestAnotherRealmIsRefusedWithoutAskingTheKDC(t *testing.T) {
	t.Parallel()

	kdc := newS4UKDC(t, func(int, messages.TGSReq) []byte { return nil })
	cl := s4uClient(t, kdc.addr)

	_, err := cl.Impersonate(alice(), "OTHER.EXAMPLE", s4uTarget)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "another realm")

	_, _, err = cl.S4U2Proxy(messages.Ticket{}, alice(), s4uRealm, "HTTP/host.other.example")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OTHER.EXAMPLE")

	assert.Empty(t, kdc.seen())
}

// TestARequestThatCannotBeBuiltIsNotSent: a session key of an encryption type the library does not implement cannot
// sign the authenticator, and the failure is reported as the request it prevented.
func TestARequestThatCannotBeBuiltIsNotSent(t *testing.T) {
	t.Parallel()

	kdc := newS4UKDC(t, func(int, messages.TGSReq) []byte { return nil })
	cl := s4uClient(t, kdc.addr)

	s, ok := cl.sessions.get(s4uRealm)
	require.True(t, ok)

	s.mux.Lock()
	s.sessionKey = types.EncryptionKey{KeyType: 0, KeyValue: []byte("no such etype")}
	s.mux.Unlock()

	_, _, err := cl.S4U2Self(alice(), s4uRealm)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "S4U2Self TGS_REQ")

	_, _, err = cl.S4U2Proxy(messages.Ticket{}, alice(), s4uRealm, s4uTarget)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "S4U2Proxy TGS_REQ")

	assert.Empty(t, kdc.seen())
}

// TestWithoutASessionNothingIsAsked: a client that cannot log in has no TGT to make either request with.
func TestWithoutASessionNothingIsAsked(t *testing.T) {
	t.Parallel()

	c := config.New()
	c.LibDefaults.DefaultRealm = s4uRealm
	cl := NewWithPassword(s4uService, s4uRealm, "password", c)

	_, _, err := cl.S4U2Self(alice(), s4uRealm)
	require.Error(t, err)

	_, _, err = cl.S4U2Proxy(messages.Ticket{}, alice(), s4uRealm, s4uTarget)
	require.Error(t, err)
}
