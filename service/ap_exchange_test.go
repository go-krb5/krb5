package service

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/flags"
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
