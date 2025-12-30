package service

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
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

	ok, _, err := VerifyAPREQ(&APReq, s)
	assert.True(t, ok)
	assert.NoError(t, err)
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
