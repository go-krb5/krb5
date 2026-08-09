package client

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

// TestForwardedTGTShouldRefuseANonForwardableSession asserts the local pre-check. Without it the KDC answers
// KDC_ERR_BADOPTION, which names nothing the operator can act on; forwardable defaults to false in this library, so
// this is the failure an unmodified deployment hits first.
//
// The fixture session is given realistic, currently-valid times (authTime in the recent past, endTime comfortably
// in the future) so that ensureValidSession's fast path applies and ForwardedTGT never dials the KDC: sessionTGT is
// called before the forwardable check specifically so a stale session can re-login and pick up a newly-forwardable
// TGT, and a fixture with zero times would exercise that re-login path instead of the check this test targets.
func TestForwardedTGTShouldRefuseANonForwardableSession(t *testing.T) {
	t.Parallel()

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	cl := NewWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue", c)

	now := time.Now().UTC()
	cl.sessions.update(&session{
		realm:     "TEST.GOKRB5",
		authTime:  now.Add(-1 * time.Hour),
		endTime:   now.Add(9 * time.Hour),
		renewTill: now.Add(7 * 24 * time.Hour),
		tgt: messages.Ticket{
			Realm: "TEST.GOKRB5",
			SName: types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", "TEST.GOKRB5"}},
		},
		sessionKey: types.EncryptionKey{
			KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
			KeyValue: []byte("0123456789abcdef0123456789abcdef"),
		},
		flags: types.NewKrbFlags(),
	})

	svcKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x0B}, 32)}
	spn := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"HTTP", "host.test.gokrb5"}}

	start := time.Now()
	_, _, err = cl.ForwardedTGT(spn, svcKey)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, ErrNotForwardable)
	assert.Contains(t, err.Error(), "forwardable = true",
		"the error must name the setting that fixes it")
	// Against Active Directory the local setting is often already correct and the KDC is withholding FORWARDABLE
	// on account policy, so naming only krb5.conf would send an operator to change something that is not wrong.
	assert.Contains(t, err.Error(), "ADS_UF_NOT_DELEGATED",
		"the error must also name the Active Directory account flag that withholds the flag")
	assert.Contains(t, err.Error(), "Protected Users")
	assert.Less(t, elapsed, 1*time.Second,
		"a valid, non-forwardable session must be rejected locally, without a KDC round trip")
}

// ccacheWithCurrentTGT parses the captured credential cache test vector and shifts every credential forward by one
// offset so that the TGT it carries is currently valid.
//
// The vector was captured in 2017, and an expired session sends ensureValidSession down refreshSession rather than
// its fast path, which is not the state delegation is used in. Only the times are moved: the ticket flags stay
// exactly as the KDC issued them (0x40c10000, FORWARDABLE set), which is the value under test.
func ccacheWithCurrentTGT(t *testing.T) *credentials.CCache {
	t.Helper()

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)

	cc := new(credentials.CCache)
	require.NoError(t, cc.Unmarshal(b))

	spn := types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", "TEST.GOKRB5"}}

	tgt, ok := cc.GetEntry(spn)
	require.True(t, ok, "the ccache test vector must contain a TGT")
	require.True(t, types.IsFlagSet(&tgt.TicketFlags, flags.Forwardable),
		"the ccache test vector's TGT must be forwardable for this fixture to mean anything")

	offset := time.Now().UTC().Add(-1 * time.Hour).Sub(tgt.AuthTime)

	for _, cred := range cc.Credentials {
		cred.AuthTime = cred.AuthTime.Add(offset)
		cred.StartTime = cred.StartTime.Add(offset)
		cred.EndTime = cred.EndTime.Add(offset)
		cred.RenewTill = cred.RenewTill.Add(offset)
	}

	return cc
}

// configWithoutKDCs parses the test krb5.conf and removes the KDCs of the realm the fixtures authenticate against,
// so that anything reaching the network fails locally rather than dialling.
func configWithoutKDCs(t *testing.T) *config.Config {
	t.Helper()

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	var cleared bool

	for i := range c.Realms {
		if c.Realms[i].Realm == "TEST.GOKRB5" {
			c.Realms[i].KDC = nil
			cleared = true

			break
		}
	}

	require.True(t, cleared, "test fixture must clear the KDC list of the realm it authenticates against")

	return c
}

// TestNewFromCCacheShouldCarryTheTicketFlagsIntoTheSession pins the session population that NewFromCCache performs
// against the two other population sites, addSession and session.update. A client built from a ccache is the normal
// way a delegating service acts as its user, and the session it builds has to answer the same questions as one built
// by an AS exchange: the flags field left zeroed made session.forwardable panic in types.IsFlagSet, and merely
// bounds-guarding that would have turned the panic into every ccache client being refused ErrNotForwardable while
// holding a forwardable TGT.
//
// The client is built through NewFromCCache rather than by setting session fields directly, because a hand-built
// session sets flags explicitly and so cannot observe a constructor that fails to.
func TestNewFromCCacheShouldCarryTheTicketFlagsIntoTheSession(t *testing.T) {
	t.Parallel()

	cl, err := NewFromCCache(ccacheWithCurrentTGT(t), configWithoutKDCs(t))
	require.NoError(t, err)

	s, ok := cl.sessions.get("TEST.GOKRB5")
	require.True(t, ok, "NewFromCCache must establish a session for the ccache's realm")

	assert.True(t, s.forwardable(),
		"a forwardable TGT loaded from a ccache must be recognised as forwardable")
	assert.False(t, s.addressed(),
		"the ccache test vector's TGT is addressless, so the session must be too")
}

// TestForwardedTGTShouldNotPanicForACCacheClient exercises the delegation entry point on a client built the way
// spnego.Delegation() callers build one. With a still-valid ccache TGT, ensureValidSession's fast path returns
// without touching the session, so session.forwardable is the first thing to read the flags; before the flags were
// populated this panicked with "index out of range [0] with length 0" inside types.IsFlagSet.
func TestForwardedTGTShouldNotPanicForACCacheClient(t *testing.T) {
	t.Parallel()

	cl, err := NewFromCCache(ccacheWithCurrentTGT(t), configWithoutKDCs(t))
	require.NoError(t, err)

	svcKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x0B}, 32)}
	spn := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"HTTP", "host.test.gokrb5"}}

	require.NotPanics(t, func() {
		_, _, err = cl.ForwardedTGT(spn, svcKey)
	})

	require.Error(t, err, "the fixture config has no KDCs, so the exchange itself cannot succeed")
	assert.NotErrorIs(t, err, ErrNotForwardable,
		"a forwardable ccache TGT must get past the forwardable check")
	assert.ErrorContains(t, err, "error requesting a forwarded TGT",
		"the request must fail at the KDC exchange, which is past every local check")
}

// TestForwardedTGTIntegration obtains a real forwarded TGT from the KDC. This is the only proof that the KDC
// accepts the options NewForwardedTGSReq sends, and it does not run in CI.
func TestForwardedTGTIntegration(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	c.LibDefaults.Forwardable = true

	cl := NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	require.NoError(t, cl.Login())

	svcKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x0B}, 32)}
	spn := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"HTTP", "host.test.gokrb5"}}

	tkt, dep, err := cl.ForwardedTGT(spn, svcKey)
	require.NoError(t, err)

	assert.Equal(t, []string{"krbtgt", "TEST.GOKRB5"}, tkt.SName.NameString)
	assert.True(t, types.IsFlagSet(&dep.Flags, flags.Forwarded),
		"the KDC must mark the issued ticket FORWARDED")
	assert.NotEmpty(t, dep.Key.KeyValue)

	_, _, cached := cl.GetCachedTicket("krbtgt/TEST.GOKRB5")
	assert.False(t, cached, "a forwarded TGT must not enter the ticket cache")
}
