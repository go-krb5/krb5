package service

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/adtype"
	"github.com/go-krb5/krb5/iana/asn1apptag"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestVerifyAPREQ(t *testing.T) {
	t.Parallel()

	cl := getClient(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	st := time.Now().UTC()

	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)

	require.NoError(t, err)

	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(t, *cl.Credentials),
	)

	require.NoError(t, err)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))

	ok, creds, err := VerifyAPREQ(&APReq, s)
	assert.True(t, ok)
	assert.NoError(t, err)

	// The authenticated identity must be the one sealed into the ticket by the KDC.
	require.NotNil(t, creds)
	assert.Equal(t, "TEST.GOKRB5", creds.Domain())
	assert.Equal(t, cl.Credentials.CName(), creds.CName())
}

func TestVerifyAPREQWithPrincipalOverride(t *testing.T) {
	t.Parallel()

	cl := getClient(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	st := time.Now().UTC()

	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)

	require.NoError(t, err)

	apReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(t, *cl.Credentials),
	)
	require.NoError(t, err)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h), KeytabPrincipal("foo"))

	ok, _, err := VerifyAPREQ(&apReq, s)
	require.EqualError(t, err, "[Root cause: Decrypting_Error] Decrypting_Error: error decrypting encpart of service ticket provided: KRB Error: (45) KRB_AP_ERR_NOKEY Service key not available - Could not get key from keytab: matching key not found in keytab. Looking for \"foo\" realm: TEST.GOKRB5 kvno: 1 etype: 18")
	require.False(t, ok)
}

func TestVerifyAPREQ_KRB_AP_ERR_BADMATCH(t *testing.T) {
	t.Parallel()

	cl := getClient(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	st := time.Now().UTC()

	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	require.NoError(t, err)

	a := newTestAuthenticator(t, *cl.Credentials)
	a.CName = types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"BADMATCH"},
	}

	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	require.NoError(t, err)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))

	ok, _, err := VerifyAPREQ(&APReq, s)
	require.EqualError(t, err, "KRB Error: (36) KRB_AP_ERR_BADMATCH Ticket and authenticator don't match - CName in Authenticator does not match that in service ticket")
	require.False(t, ok)

	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_BADMATCH, err.(messages.KRBError).ErrorCode)
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

// TestVerifyAPREQ_KRB_AP_ERR_BADMATCH_CRealm asserts that a client cannot claim an arbitrary realm by placing it in the
// authenticator, which it seals itself, while presenting a ticket issued to it in its own realm. See RFC 4120 section
// 3.2.3 and https://github.com/jcmturner/gokrb5/issues/577.
func TestVerifyAPREQ_KRB_AP_ERR_BADMATCH_CRealm(t *testing.T) {
	t.Parallel()

	cl := getClient(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	st := time.Now().UTC()

	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	require.NoError(t, err)

	a := newTestAuthenticator(t, *cl.Credentials)
	a.CRealm = "ELEVATED.GOKRB5"

	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	require.NoError(t, err)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))

	ok, _, err := VerifyAPREQ(&APReq, s)
	require.EqualError(t, err, "KRB Error: (36) KRB_AP_ERR_BADMATCH Ticket and authenticator don't match - CRealm in Authenticator does not match that in service ticket")
	require.False(t, ok)

	require.IsType(t, messages.KRBError{}, err)
	assert.Equal(t, errorcode.KRB_AP_ERR_BADMATCH, err.(messages.KRBError).ErrorCode)
}

func TestVerifyAPREQ_LargeClockSkew(t *testing.T) {
	t.Parallel()

	cl := getClient(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	st := time.Now().UTC()

	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)

	require.NoError(t, err)

	a := newTestAuthenticator(t, *cl.Credentials)
	a.CTime = a.CTime.Add(time.Duration(-10) * time.Minute)

	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)

	require.NoError(t, err)

	h, err := types.GetHostAddress("127.0.0.1:1234")
	require.NoError(t, err)

	s := NewSettings(kt, ClientAddress(h))

	ok, _, err := VerifyAPREQ(&APReq, s)
	require.False(t, ok)
	require.EqualError(t, err, "KRB Error: (37) KRB_AP_ERR_SKEW Clock skew too great - clock skew with client too large. greater than 5m0s seconds")

	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_SKEW, err.(messages.KRBError).ErrorCode)
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyAPREQ_Replay(t *testing.T) {
	cl := getClient(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	st := time.Now().UTC()

	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	require.NoError(t, err)

	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(t, *cl.Credentials),
	)
	require.NoError(t, err)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))

	ok, _, err := VerifyAPREQ(&APReq, s)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, _, err = VerifyAPREQ(&APReq, s)
	require.False(t, ok)
	require.EqualError(t, err, "KRB Error: (34) KRB_AP_ERR_REPEAT Request is a replay - replay detected")

	assert.IsType(t, messages.KRBError{}, err)
	assert.Equal(t, errorcode.KRB_AP_ERR_REPEAT, err.(messages.KRBError).ErrorCode)
}

func TestVerifyAPREQ_FutureTicket(t *testing.T) {
	t.Parallel()

	cl := getClient(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	st := time.Now().UTC()

	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st.Add(time.Duration(60)*time.Minute),
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	require.NoError(t, err)

	a := newTestAuthenticator(t, *cl.Credentials)

	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	require.NoError(t, err)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))

	ok, _, err := VerifyAPREQ(&APReq, s)
	require.False(t, ok)
	require.EqualError(t, err, "KRB Error: (33) KRB_AP_ERR_TKT_NYV Ticket not yet valid - service ticket provided is not yet valid")

	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_NYV, err.(messages.KRBError).ErrorCode)
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyAPREQ_InvalidTicket(t *testing.T) {
	t.Parallel()

	cl := getClient(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	st := time.Now().UTC()
	f := types.NewKrbFlags()
	types.SetFlag(&f, flags.Invalid)

	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		f,
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	require.NoError(t, err)

	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(t, *cl.Credentials),
	)
	require.NoError(t, err)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))

	ok, _, err := VerifyAPREQ(&APReq, s)
	require.False(t, ok)
	require.EqualError(t, err, "KRB Error: (33) KRB_AP_ERR_TKT_NYV Ticket not yet valid - service ticket provided is not yet valid")

	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_NYV, err.(messages.KRBError).ErrorCode)
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyAPREQ_ExpiredTicket(t *testing.T) {
	t.Parallel()

	cl := getClient(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	st := time.Now().UTC()

	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(-30)*time.Minute),
		st.Add(time.Duration(48)*time.Hour),
	)
	require.NoError(t, err)

	a := newTestAuthenticator(t, *cl.Credentials)

	APReq, err := messages.NewAPReq(tkt, sessionKey, a)
	require.NoError(t, err)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))

	ok, _, err := VerifyAPREQ(&APReq, s)
	require.False(t, ok)
	require.EqualError(t, err, "KRB Error: (32) KRB_AP_ERR_TKT_EXPIRED Ticket expired - service ticket provided has expired")

	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_EXPIRED, err.(messages.KRBError).ErrorCode)
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

// TestVerifyAPREQWithChannelBindingConfigured exercises the s.RequireChannelBinding() guard inside VerifyAPREQ end
// to end, against a real AP_REQ sealed against the test keytab: a matching binding is accepted, a mismatched one is
// rejected with KRB_AP_ERR_BADMATCH, and leaving the requirement unset (the guard's false branch) reproduces the
// unchanged, no-verification behaviour of TestVerifyAPREQ.
func TestVerifyAPREQWithChannelBindingConfigured(t *testing.T) {
	t.Parallel()

	cl := getClient(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	sentBinding := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:sent")}

	newSealedAPReq := func(t *testing.T) messages.APReq {
		t.Helper()

		st := time.Now().UTC()

		tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
			sname, "TEST.GOKRB5",
			types.NewKrbFlags(),
			kt,
			18,
			1,
			st,
			st,
			st.Add(time.Duration(24)*time.Hour),
			st.Add(time.Duration(48)*time.Hour),
		)
		require.NoError(t, err)

		a := newTestAuthenticator(t, *cl.Credentials)
		a.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: testGSSAPIChecksum(sentBinding)}

		APReq, err := messages.NewAPReq(tkt, sessionKey, a)
		require.NoError(t, err)

		return APReq
	}

	t.Run("MatchingBindingConfigured", func(t *testing.T) {
		t.Parallel()

		APReq := newSealedAPReq(t)

		h, _ := types.GetHostAddress("127.0.0.1:1234")
		s := NewSettings(kt, ClientAddress(h), RequireChannelBinding(sentBinding))

		ok, creds, err := VerifyAPREQ(&APReq, s)
		assert.True(t, ok)
		assert.NoError(t, err)
		require.NotNil(t, creds)
		assert.Equal(t, cl.Credentials.CName(), creds.CName())
	})

	t.Run("MismatchedBindingConfigured", func(t *testing.T) {
		t.Parallel()

		APReq := newSealedAPReq(t)

		wantBinding := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:want")}

		h, _ := types.GetHostAddress("127.0.0.1:1234")
		s := NewSettings(kt, ClientAddress(h), RequireChannelBinding(wantBinding))

		ok, _, err := VerifyAPREQ(&APReq, s)
		require.False(t, ok)
		require.EqualError(t, err, "KRB Error: (36) KRB_AP_ERR_BADMATCH Ticket and authenticator don't match - channel binding mismatch")

		require.ErrorIs(t, err, ErrBadChannelBinding)

		var krberr messages.KRBError

		require.ErrorAs(t, err, &krberr)
		assert.Equal(t, errorcode.KRB_AP_ERR_BADMATCH, krberr.ErrorCode)
	})

	t.Run("NoBindingConfigured", func(t *testing.T) {
		t.Parallel()

		APReq := newSealedAPReq(t)

		h, _ := types.GetHostAddress("127.0.0.1:1234")
		s := NewSettings(kt, ClientAddress(h))

		ok, creds, err := VerifyAPREQ(&APReq, s)
		assert.True(t, ok)
		assert.NoError(t, err)
		require.NotNil(t, creds)
		assert.Equal(t, cl.Credentials.CName(), creds.CName())
	})
}

// testAPReqWithChecksum builds the minimum AP_REQ needed to exercise channel binding verification.
func testAPReqWithChecksum(cksumType int32, checksum []byte) *messages.APReq {
	return &messages.APReq{
		Ticket: messages.Ticket{
			Realm: "EXAMPLE.ORG",
			SName: types.PrincipalName{NameType: 1, NameString: []string{"HTTP", "host.example.org"}},
		},
		Authenticator: types.Authenticator{
			Cksum: types.Checksum{CksumType: cksumType, Checksum: checksum},
		},
	}
}

// testGSSAPIChecksum builds an RFC 4121 Section 4.1.1 checksum carrying the binding provided.
func testGSSAPIChecksum(cb *gssapi.ChannelBinding) []byte {
	c := make([]byte, 24)
	binary.LittleEndian.PutUint32(c[:4], 16)

	bnd := cb.Bnd()
	copy(c[4:20], bnd[:])

	return c
}

func TestVerifyChannelBindingShouldAcceptAMatchingBinding(t *testing.T) {
	t.Parallel()

	cb := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:test")}

	require.NoError(t, verifyChannelBinding(testAPReqWithChecksum(chksumtype.GSSAPI, testGSSAPIChecksum(cb)), cb))
}

func TestVerifyChannelBindingShouldRejectAMismatchedBinding(t *testing.T) {
	t.Parallel()

	sent := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:sent")}
	want := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:want")}

	err := verifyChannelBinding(testAPReqWithChecksum(chksumtype.GSSAPI, testGSSAPIChecksum(sent)), want)
	require.ErrorIs(t, err, ErrBadChannelBinding)
	assert.Contains(t, err.Error(), "channel binding mismatch")
}

// TestVerifyChannelBindingShouldRejectAnUnboundRequest asserts that configuring a requirement actually requires it:
// an initiator that sent the sixteen zero bytes meaning "no channel bindings" must be rejected.
//
// The checksum is built with a nil binding rather than as 24 zero bytes because an unbound initiator still writes
// Lgth, which RFC 4121 Section 4.1.1 fixes at 16 as the width of the Bnd field regardless of whether any bindings
// were supplied. Only Bnd itself goes to zero. A wholly zeroed checksum would be rejected for its Lgth before the
// comparison this test is about was ever reached.
func TestVerifyChannelBindingShouldRejectAnUnboundRequest(t *testing.T) {
	t.Parallel()

	want := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:want")}

	cksum := testGSSAPIChecksum(nil)
	require.Equal(t, uint32(16), binary.LittleEndian.Uint32(cksum[:4]))
	require.Equal(t, make([]byte, 16), cksum[4:20])

	err := verifyChannelBinding(testAPReqWithChecksum(chksumtype.GSSAPI, cksum), want)
	require.ErrorIs(t, err, ErrBadChannelBinding)
	assert.Contains(t, err.Error(), "channel binding mismatch")
}

// wantMsgNoGSSAPIChecksum is the message verifyChannelBinding reports when the authenticator's checksum is not a
// usable RFC 4121 Section 4.1.1 GSS-API checksum: wrong checksum type, or too short to carry one.
const wantMsgNoGSSAPIChecksum = "does not contain a GSSAPI checksum"

func TestVerifyChannelBindingShouldRejectAMalformedChecksum(t *testing.T) {
	t.Parallel()

	want := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:want")}

	// lgthChecksum builds an otherwise well formed checksum whose four octet Lgth field declares the width given
	// rather than the 16 RFC 4121 Section 4.1.1 fixes.
	lgthChecksum := func(lgth uint32) []byte {
		c := testGSSAPIChecksum(want)
		binary.LittleEndian.PutUint32(c[:4], lgth)

		return c
	}

	for _, tc := range []struct {
		name      string
		cksumType int32
		checksum  []byte
		wantMsg   string
	}{
		{"WrongType", chksumtype.HMAC_SHA1_96_AES256, make([]byte, 24), wantMsgNoGSSAPIChecksum},
		{"TooShort", chksumtype.GSSAPI, make([]byte, 23), wantMsgNoGSSAPIChecksum},
		{"Empty", chksumtype.GSSAPI, nil, wantMsgNoGSSAPIChecksum},
		// A zero, short or oversized Lgth must be rejected on its own terms even when the Bnd octets that follow
		// would have matched, so that a malformed checksum is never reported as a binding mismatch.
		{"ZeroLgth", chksumtype.GSSAPI, lgthChecksum(0), "declares a Bnd length of 0 rather than 16"},
		{"ShortLgth", chksumtype.GSSAPI, lgthChecksum(8), "declares a Bnd length of 8 rather than 16"},
		{"LongLgth", chksumtype.GSSAPI, lgthChecksum(32), "declares a Bnd length of 32 rather than 16"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := verifyChannelBinding(testAPReqWithChecksum(tc.cksumType, tc.checksum), want)
			require.ErrorIs(t, err, ErrBadChannelBinding)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

func TestSettingsRequireChannelBindingShouldDefaultToNil(t *testing.T) {
	t.Parallel()

	assert.Nil(t, NewSettings(nil).RequireChannelBinding())
}

func TestSettingsRequireChannelBindingShouldRoundTrip(t *testing.T) {
	t.Parallel()

	cb := &gssapi.ChannelBinding{ApplicationData: []byte("tls-exporter:test")}

	assert.Same(t, cb, NewSettings(nil, RequireChannelBinding(cb)).RequireChannelBinding())
}

// testDelegatedAPReq builds an AP_REQ carrying a KRB_CRED for the principal given, encrypted under key, in the
// Deleg field of its RFC 4121 Section 4.1.1 checksum.
func testDelegatedAPReq(t *testing.T, cname types.PrincipalName, crealm string, key types.EncryptionKey, subkey types.EncryptionKey) *messages.APReq {
	t.Helper()

	info := messages.KrbCredInfo{
		Key:     types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0C}, 32)},
		PRealm:  crealm,
		PName:   cname,
		SRealm:  crealm,
		SName:   types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", crealm}},
		EndTime: time.Now().UTC().Add(time.Hour),
	}
	tkt := messages.Ticket{TktVNO: 5, Realm: crealm, SName: info.SName}

	credKey := key
	if len(subkey.KeyValue) > 0 {
		credKey = subkey
	}

	cred, err := messages.NewKRBCred([]messages.Ticket{tkt}, []messages.KrbCredInfo{info}, credKey)
	require.NoError(t, err)

	deleg, err := cred.Marshal()
	require.NoError(t, err)

	cksum, err := (&gssapi.AuthenticatorChecksum{Deleg: deleg}).Marshal()
	require.NoError(t, err)

	return &messages.APReq{
		Ticket: messages.Ticket{
			Realm:            crealm,
			SName:            types.PrincipalName{NameType: 1, NameString: []string{"HTTP", "host.test.gokrb5"}},
			DecryptedEncPart: messages.EncTicketPart{Key: key},
		},
		Authenticator: types.Authenticator{
			Cksum:  types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: cksum},
			SubKey: subkey,
		},
	}
}

// TestExtractDelegatedCredentialShouldDecryptWithTheSessionKey asserts the key RFC 4121 Section 4.1.1 mandates:
// "The EncryptedData field of the KRB_CRED message MUST be encrypted in the session key of the ticket used to
// authenticate the context."
func TestExtractDelegatedCredentialShouldDecryptWithTheSessionKey(t *testing.T) {
	t.Parallel()

	key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0B}, 32)}
	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser1"}}

	creds := credentials.NewFromPrincipalName(cname, "TEST.GOKRB5")

	require.NoError(t, extractDelegatedCredential(testDelegatedAPReq(t, cname, "TEST.GOKRB5", key, types.EncryptionKey{}), creds))

	cc, ok := creds.DelegatedCredentials()
	require.True(t, ok)
	assert.Equal(t, cname, cc.GetClientPrincipalName())
	require.Len(t, cc.Credentials, 1)
}

// TestExtractDelegatedCredentialShouldFallBackToTheSubkey asserts we accept a peer that encrypts with the
// authenticator subkey. MIT's rd_cred.c tries the receiving subkey first and falls back to the session key, so
// tolerating both is what interoperating means here even though we always send the session key.
func TestExtractDelegatedCredentialShouldFallBackToTheSubkey(t *testing.T) {
	t.Parallel()

	key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0B}, 32)}
	subkey := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0F}, 32)}
	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser1"}}

	creds := credentials.NewFromPrincipalName(cname, "TEST.GOKRB5")

	require.NoError(t, extractDelegatedCredential(testDelegatedAPReq(t, cname, "TEST.GOKRB5", key, subkey), creds))

	_, ok := creds.DelegatedCredentials()
	assert.True(t, ok)
}

// TestExtractDelegatedCredentialShouldIgnoreARequestWithoutDelegation asserts the ordinary path costs nothing and
// sets nothing.
func TestExtractDelegatedCredentialShouldIgnoreARequestWithoutDelegation(t *testing.T) {
	t.Parallel()

	creds := credentials.New("testuser1", "TEST.GOKRB5")

	require.NoError(t, extractDelegatedCredential(testAPReqWithChecksum(chksumtype.GSSAPI, testGSSAPIChecksum(nil)), creds))

	_, ok := creds.DelegatedCredentials()
	assert.False(t, ok)
}

// TestExtractDelegatedCredentialShouldIgnoreAnUninterpretableChecksum asserts a checksum whose Lgth moves every
// field is not treated as a delegation failure. The parser cannot locate Flags, so it cannot know delegation was
// claimed; reporting a delegation error would be a guess. This is also the property that keeps AP_REQs which
// succeed today succeeding.
func TestExtractDelegatedCredentialShouldIgnoreAnUninterpretableChecksum(t *testing.T) {
	t.Parallel()

	cksum := testGSSAPIChecksum(nil)
	binary.LittleEndian.PutUint32(cksum[:4], 8)

	creds := credentials.New("testuser1", "TEST.GOKRB5")

	require.NoError(t, extractDelegatedCredential(testAPReqWithChecksum(chksumtype.GSSAPI, cksum), creds))

	_, ok := creds.DelegatedCredentials()
	assert.False(t, ok)
}

// TestExtractDelegatedCredentialShouldRejectABrokenDelegation asserts that a checksum which claims a delegation and
// then fails to deliver one is fatal. An acceptor has no ret_flags channel on which to tell the initiator that its
// credential was discarded, so continuing would leave the initiator believing a delegation happened.
func TestExtractDelegatedCredentialShouldRejectABrokenDelegation(t *testing.T) {
	t.Parallel()

	key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0B}, 32)}
	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser1"}}

	for _, tc := range []struct {
		name    string
		mutate  func(*messages.APReq)
		wantMsg string
	}{
		{
			name:    "WrongDlgOpt",
			mutate:  func(r *messages.APReq) { binary.LittleEndian.PutUint16(r.Authenticator.Cksum.Checksum[24:26], 2) },
			wantMsg: "delegation option identifier",
		},
		{
			name: "UndecryptableCredential",
			mutate: func(r *messages.APReq) {
				r.Ticket.DecryptedEncPart.Key = types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x01}, 32)}
			},
			wantMsg: "could not decrypt",
		},
		{
			// The last octet falls inside the HMAC that AES256-CTS-HMAC-SHA1-96 appends to the ciphertext, so
			// flipping it reliably fails the integrity check regardless of how large the fixture's KRB_CRED is.
			// An earlier fixed offset (such as 30) landed inside the outer KRB_CRED length octets instead, which
			// this library's ASN.1 codec does not validate against the buffer size, so corrupting it changed
			// nothing and the test passed the corrupted credential through undetected.
			name: "CorruptCredential",
			mutate: func(r *messages.APReq) {
				cksum := r.Authenticator.Cksum.Checksum
				cksum[len(cksum)-1] ^= 0xFF
			},
			wantMsg: "delegated credential",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			APReq := testDelegatedAPReq(t, cname, "TEST.GOKRB5", key, types.EncryptionKey{})
			tc.mutate(APReq)

			creds := credentials.New("testuser1", "TEST.GOKRB5")

			err := extractDelegatedCredential(APReq, creds)

			require.ErrorIs(t, err, ErrBadDelegation)
			assert.Contains(t, err.Error(), tc.wantMsg)

			var krberr messages.KRBError

			require.ErrorAs(t, err, &krberr)
			assert.Equal(t, errorcode.KRB_AP_ERR_INAPP_CKSUM, krberr.ErrorCode)

			_, ok := creds.DelegatedCredentials()
			assert.False(t, ok, "a failed extraction must leave no partial credential behind")
		})
	}
}

// TestDelegationShouldRoundTripFromInitiatorToAcceptor is the demonstration that the two halves agree. The
// initiator's checksum construction and the acceptor's extraction were written against RFC 4121 Section 4.1.1
// independently; this asserts they meet.
//
// The forwarded TGT is synthesised rather than fetched: what is under test is the KRB_CRED encoding, the checksum
// layout and the key agreement, none of which involve the KDC. cl.ForwardedTGT has its own coverage in
// client/forwarding_test.go.
func TestDelegationShouldRoundTripFromInitiatorToAcceptor(t *testing.T) {
	t.Parallel()

	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser1"}}
	sessionKey := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0B}, 32)}
	fwdKey := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0C}, 32)}

	dep := messages.EncKDCRepPart{
		Key:      fwdKey,
		Flags:    types.NewKrbFlags(),
		AuthTime: time.Now().UTC().Add(-time.Hour),
		EndTime:  time.Now().UTC().Add(time.Hour),
		SRealm:   "TEST.GOKRB5",
		SName:    types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", "TEST.GOKRB5"}},
	}
	fwdTkt := messages.Ticket{TktVNO: 5, Realm: "TEST.GOKRB5", SName: dep.SName}

	cred, err := messages.NewKRBCred([]messages.Ticket{fwdTkt},
		[]messages.KrbCredInfo{messages.NewKrbCredInfo(dep, cname, "TEST.GOKRB5")}, sessionKey)
	require.NoError(t, err)

	deleg, err := cred.Marshal()
	require.NoError(t, err)

	// The initiator half: the same layout spnego.newAuthenticatorChksum produces.
	cksum, err := (&gssapi.AuthenticatorChecksum{Flags: gssapi.ContextFlagInteg, Deleg: deleg}).Marshal()
	require.NoError(t, err)

	APReq := &messages.APReq{
		Ticket: messages.Ticket{
			Realm:            "TEST.GOKRB5",
			SName:            types.PrincipalName{NameType: 1, NameString: []string{"HTTP", "host.test.gokrb5"}},
			DecryptedEncPart: messages.EncTicketPart{Key: sessionKey},
		},
		Authenticator: types.Authenticator{
			Cksum: types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: cksum},
		},
	}

	// The acceptor half.
	creds := credentials.NewFromPrincipalName(cname, "TEST.GOKRB5")
	require.NoError(t, extractDelegatedCredential(APReq, creds))

	cc, ok := creds.DelegatedCredentials()
	require.True(t, ok, "the acceptor must have taken the delegated credential")

	assert.Equal(t, cname, cc.GetClientPrincipalName())
	assert.Equal(t, "TEST.GOKRB5", cc.GetClientRealm())
	require.Len(t, cc.Credentials, 1)
	assert.Equal(t, fwdKey, cc.Credentials[0].Key, "the forwarded TGT's session key must survive the round trip")
	assert.Equal(t, []string{"krbtgt", "TEST.GOKRB5"}, cc.Credentials[0].Server.PrincipalName.NameString)
}

func newTestAuthenticator(t *testing.T, creds credentials.Credentials) types.Authenticator {
	auth, _ := types.NewAuthenticator(creds.Domain(), creds.CName())
	require.NoError(t, auth.GenerateSeqNumberAndSubKey(18, 32))

	return auth
}

func getClient(t *testing.T) *client.Client {
	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	return cl
}

// testAPReqAdvertisingCBT builds an AP_REQ whose checksum carries the binding given and whose authenticator
// advertises KERB_AP_OPTIONS_CBT, as MS-KILE Section 3.2.5.2 has a binding-capable client do.
func testAPReqAdvertisingCBT(t *testing.T, cb *gssapi.ChannelBinding) *messages.APReq {
	t.Helper()

	r := testAPReqWithChecksum(chksumtype.GSSAPI, testGSSAPIChecksum(cb))

	ad, err := types.ADAPOptions(types.ADAPOptionsCBT).AuthorizationData()
	require.NoError(t, err)

	r.Authenticator.AuthorizationData = ad

	return r
}

// TestVerifyChannelBindingSupportShouldRejectOnlyWhenBothConditionsHold pins the MS-KILE Section 3.4.5.3 rule this
// mode implements: reject when the binding is all zero AND the client does not advertise KERB_AP_OPTIONS_CBT.
// Either condition alone is not a rejection, which is exactly what makes this weaker than verifyChannelBinding.
func TestVerifyChannelBindingSupportShouldRejectOnlyWhenBothConditionsHold(t *testing.T) {
	t.Parallel()

	bound := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:test")}

	t.Run("UnboundAndUnadvertisedIsRejected", func(t *testing.T) {
		t.Parallel()

		err := verifyChannelBindingSupport(testAPReqWithChecksum(chksumtype.GSSAPI, testGSSAPIChecksum(nil)))
		require.ErrorIs(t, err, ErrBadChannelBinding)
		assert.Contains(t, err.Error(), "KERB_AP_OPTIONS_CBT")
	})

	t.Run("UnboundButAdvertisedIsAccepted", func(t *testing.T) {
		t.Parallel()

		// This is the case that separates this mode from RequireChannelBinding, which refuses it.
		assert.NoError(t, verifyChannelBindingSupport(testAPReqAdvertisingCBT(t, nil)))
	})

	t.Run("BoundIsAcceptedEvenWithoutTheAdvertisement", func(t *testing.T) {
		t.Parallel()

		assert.NoError(t, verifyChannelBindingSupport(testAPReqWithChecksum(chksumtype.GSSAPI, testGSSAPIChecksum(bound))))
	})

	t.Run("BoundAndAdvertisedIsAccepted", func(t *testing.T) {
		t.Parallel()

		assert.NoError(t, verifyChannelBindingSupport(testAPReqAdvertisingCBT(t, bound)))
	})
}

// TestVerifyChannelBindingShouldStillRefuseAnAdvertisedButUnboundRequest is the guard on the distinction between
// the two modes. The strict setting must NOT inherit MS-KILE's leniency: a peer that advertises CBT and then sends
// no binding is the stripped-binding downgrade RequireChannelBinding exists to prevent.
func TestVerifyChannelBindingShouldStillRefuseAnAdvertisedButUnboundRequest(t *testing.T) {
	t.Parallel()

	want := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:want")}

	err := verifyChannelBinding(testAPReqAdvertisingCBT(t, nil), want)

	require.ErrorIs(t, err, ErrBadChannelBinding)
	assert.Contains(t, err.Error(), "channel binding mismatch")
}

// TestSettingsRequireChannelBindingSupportShouldDefaultToFalse asserts the weaker mode is opt-in.
func TestSettingsRequireChannelBindingSupportShouldDefaultToFalse(t *testing.T) {
	t.Parallel()

	assert.False(t, NewSettings(nil).RequireChannelBindingSupport())
	assert.True(t, NewSettings(nil, RequireChannelBindingSupport(true)).RequireChannelBindingSupport())
}

func TestVerifyAPREQWithUnparseableAuthorizationDataAndNoLogger(t *testing.T) {
	t.Parallel()

	cl := getClient(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}

	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	st := time.Now().UTC()

	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	require.NoError(t, err)

	require.NoError(t, tkt.DecryptEncPart(kt, &sname))

	etp := tkt.DecryptedEncPart
	etp.AuthorizationData = types.AuthorizationData{
		{ADType: adtype.ADIfRelevant, ADData: []byte{0xFF, 0xFF, 0xFF}},
	}
	tkt.EncPart = resealEncTicketPart(t, etp, kt, sname)

	APReq, err := messages.NewAPReq(tkt, sessionKey, newTestAuthenticator(t, *cl.Credentials))
	require.NoError(t, err)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h)) // no Logger option: the documented default

	require.NotPanics(t, func() {
		ok, _, err := VerifyAPREQ(&APReq, s)

		assert.True(t, ok)
		assert.NoError(t, err)
	})
}

func resealEncTicketPart(t *testing.T, etp messages.EncTicketPart, kt *keytab.Keytab, sname types.PrincipalName) types.EncryptedData {
	t.Helper()

	b, err := asn1.Marshal(etp, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	b = asn1tools.AddASNAppTag(b, asn1apptag.EncTicketPart)

	key, _, err := kt.GetEncryptionKey(sname, "TEST.GOKRB5", 1, 18)
	require.NoError(t, err)

	ed, err := crypto.GetEncryptedData(b, key, keyusage.KDC_REP_TICKET, 1)
	require.NoError(t, err)

	return ed
}
