package spnego

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

const (
	KRB5TokenHex = "6082026306092a864886f71201020201006e8202523082024ea003020105a10302010ea20703050000000000a382015d6182015930820155a003020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b10686f73742e746573742e676f6b726235a382011830820114a003020112a103020103a28201060482010230621d868c97f30bf401e03bbffcd724bd9d067dce2afc31f71a356449b070cdafcc1ff372d0eb1e7a708b50c0152f3996c45b1ea312a803907fb97192d39f20cdcaea29876190f51de6e2b4a4df0460122ed97f363434e1e120b0e76c172b4424a536987152ac0b73013ab88af4b13a3fcdc63f739039dd46d839709cf5b51bb0ce6cb3af05fab3844caac280929955495235e9d0424f8a1fb9b4bd4f6bba971f40b97e9da60b9dabfcf0b1feebfca02c9a19b327a0004aa8e19192726cf347561fa8ac74afad5d6a264e50cf495b93aac86c77b2bc2d184234f6c2767dbea431485a25687b9044a20b601e968efaefffa1fc5283ff32aa6a53cb6c5cdd2eddcb26a481d73081d4a003020112a103020103a281c70481c4a1b29e420324f7edf9efae39df7bcaaf196a3160cf07e72f52a4ef8a965721b2f3343719c50699046e4fcc18ca26c2bfc7e4a9eddfc9d9cfc57ff2f6bdbbd1fc40ac442195bc669b9a0dbba12563b3e4cac9f4022fc01b8aa2d1ab84815bb078399ff7f4d5f9815eef896a0c7e3c049e6fd9932b97096cdb5861425b9d81753d0743212ded1a0fb55a00bf71a46be5ce5e1c8a5cc327b914347d9efcb6cb31ca363b1850d95c7b6c4c3cc6301615ad907318a0c5379d343610fab17eca9c7dc0a5a60658"
	AuthChksum   = "100000000000000000000000000000000000000030000000"
)

func TestKRB5Token_Unmarshal(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(KRB5TokenHex)
	require.NoError(t, err)

	var mt KRB5Token

	require.NoError(t, mt.Unmarshal(b))

	assert.Equal(t, gssapi.OIDKRB5.OID(), mt.OID)
	assert.Equal(t, []byte{1, 0}, mt.tokID)
	assert.Equal(t, msgtype.KRB_AP_REQ, mt.APReq.MsgType)
	assert.Equal(t, int32(0), mt.KRBError.ErrorCode)
	assert.Equal(t, int32(18), mt.APReq.EncryptedAuthenticator.EType)
}

func TestKRB5Token_newAuthenticatorChksum(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(AuthChksum)
	require.NoError(t, err)

	cb, err := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, b, cb)
}

// Test with explicit subkey generation.
func TestKRB5Token_newAuthenticatorWithSubkeyGeneration(t *testing.T) {
	t.Parallel()

	var etypeID int32 = 18

	keyLen := 32

	a, err := krb5TokenAuthenticator(getClient(t), messages.Ticket{}, types.EncryptionKey{},
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
	require.NoError(t, err)

	require.NoError(t, a.GenerateSeqNumberAndSubKey(etypeID, keyLen))
	assert.Equal(t, int32(32771), a.Cksum.CksumType)
	assert.Equal(t, etypeID, a.SubKey.KeyType)
	assert.Equal(t, keyLen, len(a.SubKey.KeyValue))

	var nz bool

	for _, b := range a.SubKey.KeyValue {
		if b != byte(0) {
			nz = true
		}
	}

	assert.True(t, nz)

	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber > 0
	}))

	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber <= math.MaxUint32
	}))
}

// Test without subkey generation.
func TestKRB5Token_newAuthenticator(t *testing.T) {
	t.Parallel()

	a, err := krb5TokenAuthenticator(getClient(t), messages.Ticket{}, types.EncryptionKey{},
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
	require.NoError(t, err)

	assert.Equal(t, int32(32771), a.Cksum.CksumType)
	assert.Equal(t, int32(0), a.SubKey.KeyType)
	assert.Nil(t, a.SubKey.KeyValue)

	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber > 0
	}))

	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber <= math.MaxUint32
	}))
}

func TestNewAPREQKRB5Token_and_Marshal(t *testing.T) {
	t.Parallel()

	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})
	cl := client.Client{
		Credentials: creds,
	}

	var tkt messages.Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)

	require.NoError(t, tkt.Unmarshal(b))

	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: make([]byte, 32),
	}

	mt, err := NewKRB5TokenAPREQ(&cl, tkt, key, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, []int{})
	require.NoError(t, err)

	mb, err := mt.Marshal()
	require.NoError(t, err)

	require.NoError(t, mt.Unmarshal(mb))

	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}, mt.OID)
	assert.Equal(t, []byte{1, 0}, mt.tokID)
	assert.Equal(t, msgtype.KRB_AP_REQ, mt.APReq.MsgType)
	assert.Equal(t, int32(0), mt.KRBError.ErrorCode)
	assert.Equal(t, testdata.TEST_REALM, mt.APReq.Ticket.Realm)
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, mt.APReq.Ticket.SName.NameString)
	assert.Equal(t, int32(18), mt.APReq.EncryptedAuthenticator.EType)
}

// TestNewNegTokenInitKRB5ShouldForwardChannelBindingToTheSealedAPREQ asserts that a ChannelBinding option supplied
// to NewNegTokenInitKRB5 actually reaches the AP_REQ it seals, exercising both the negotiation_token.go ->
// NewKRB5TokenAPREQ forwarding hop and the krb5TokenAuthenticator -> newAuthenticatorChksum hop beneath it.
//
// A bare inequality between the two calls' MechTokenBytes would not prove this: types.NewAuthenticator embeds a
// fresh random SeqNumber and a CTime with microsecond resolution on every call, so the two AP_REQs (and therefore
// their encrypted, and marshalled, bytes) are all but certain to differ regardless of whether the channel binding
// is forwarded at all. Instead this decrypts each authenticator with the same session key used to seal it and reads
// the Bnd field out of its GSS-API checksum directly, which isolates exactly the value the binding option controls.
func TestNewNegTokenInitKRB5ShouldForwardChannelBindingToTheSealedAPREQ(t *testing.T) {
	t.Parallel()

	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})
	cl := &client.Client{Credentials: creds}

	var tkt messages.Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(b))

	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: make([]byte, 32),
	}

	cb := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:test")}

	// sealedBnd unmarshals the NegTokenInit's MechTokenBytes, decrypts the authenticator sealed inside it with the
	// same session key used to seal it, and returns the Bnd bytes carried in its GSS-API checksum.
	sealedBnd := func(t *testing.T, nti NegTokenInit) []byte {
		t.Helper()

		var mt KRB5Token

		require.NoError(t, mt.Unmarshal(nti.MechTokenBytes))
		require.NoError(t, mt.APReq.DecryptAuthenticator(key))
		require.Equal(t, chksumtype.GSSAPI, mt.APReq.Authenticator.Cksum.CksumType)
		require.Len(t, mt.APReq.Authenticator.Cksum.Checksum, 24)

		return mt.APReq.Authenticator.Cksum.Checksum[4:20]
	}

	bound, err := NewNegTokenInitKRB5(cl, tkt, key, ChannelBinding(cb))
	require.NoError(t, err)

	unbound, err := NewNegTokenInitKRB5(cl, tkt, key)
	require.NoError(t, err)

	boundBnd := sealedBnd(t, bound)
	unboundBnd := sealedBnd(t, unbound)

	bnd := cb.Bnd()
	assert.Equal(t, bnd[:], boundBnd, "the AP_REQ sealed with ChannelBinding must carry the binding's Bnd hash")
	assert.Equal(t, make([]byte, 16), unboundBnd, "the AP_REQ sealed without ChannelBinding must carry the all-zero Bnd meaning no channel bindings")
	assert.NotEqual(t, boundBnd, unboundBnd)
}

func TestNewAuthenticatorChksumShouldEmbedTheChannelBinding(t *testing.T) {
	t.Parallel()

	cb := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:test")}

	c, err := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, cb, nil)
	require.NoError(t, err)

	require.Len(t, c, 24)
	assert.Equal(t, uint32(16), binary.LittleEndian.Uint32(c[:4]))

	bnd := cb.Bnd()
	assert.Equal(t, bnd[:], c[4:20])

	assert.Equal(t, uint32(gssapi.ContextFlagInteg|gssapi.ContextFlagConf), binary.LittleEndian.Uint32(c[20:24]))
}

// TestNewAuthenticatorChksumShouldZeroBndWithoutAChannelBinding is the regression guard for the default path: with
// no binding the checksum must be byte for byte what it was before this feature existed.
func TestNewAuthenticatorChksumShouldZeroBndWithoutAChannelBinding(t *testing.T) {
	t.Parallel()

	c, err := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil, nil)
	require.NoError(t, err)

	require.Len(t, c, 24)
	assert.Equal(t, uint32(16), binary.LittleEndian.Uint32(c[:4]))
	assert.Equal(t, make([]byte, 16), c[4:20])
	assert.Equal(t, uint32(gssapi.ContextFlagInteg|gssapi.ContextFlagConf), binary.LittleEndian.Uint32(c[20:24]))
}

// TestNewAuthenticatorChksumShouldCarryTheDelegatedCredential asserts the delegation fields of RFC 4121 Section
// 4.1.1 follow Flags when a credential is supplied. The refusal this replaces existed because those fields used to
// be emitted zeroed.
func TestNewAuthenticatorChksumShouldCarryTheDelegatedCredential(t *testing.T) {
	t.Parallel()

	deleg := []byte("a marshalled KRB_CRED")

	c, err := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg}, nil, deleg)
	require.NoError(t, err)

	require.Len(t, c, 28+len(deleg))
	assert.Equal(t, uint32(gssapi.ContextFlagInteg|gssapi.ContextFlagDeleg), binary.LittleEndian.Uint32(c[20:24]))
	assert.Equal(t, uint16(1), binary.LittleEndian.Uint16(c[24:26]))
	assert.Equal(t, deleg, c[28:])
}

// TestNewAuthenticatorChksumShouldStillRefuseTheFlagWithoutACredential asserts the original defect stays
// unrepresentable now that the flag is honoured rather than refused.
func TestNewAuthenticatorChksumShouldStillRefuseTheFlagWithoutACredential(t *testing.T) {
	t.Parallel()

	c, err := newAuthenticatorChksum([]int{gssapi.ContextFlagDeleg}, nil, nil)

	require.ErrorIs(t, err, gssapi.ErrDelegationMissing)
	assert.Nil(t, c)
}

// TestNewKRB5TokenAPREQShouldSurfaceADelegationFailure covers the propagation hop rather than only the leaf: the
// error has to travel delegatedCredential -> krb5TokenAuthenticator -> NewKRB5TokenAPREQ to reach a caller. This
// matters because, unlike MIT, which silently clears GSS_C_DELEG_FLAG when forwarding fails, this library returns
// the failure; a caller that never sees it would believe a delegation had happened that had not.
//
// A bare client.Client{Credentials: creds} literal cannot exercise this: its unexported *sessions field is a nil
// pointer rather than a nil-safe map, so cl.ForwardedTGT panics inside sessions.get before it ever returns an
// error. client.NewWithPassword initialises that field properly. To still fail locally, without a KDC round trip,
// the realm's KDC list is cleared after parsing testdata.KRB5_CONF: client.Client.IsConfigured then rejects the
// login synchronously with "client krb5 config does not have any defined KDCs for the default realm", before any
// socket is opened. This is the same local-failure shape TestForwardedTGTShouldRefuseANonForwardableSession in
// client/forwarding_test.go exploits, one layer up: the config check rather than the forwardable check.
func TestNewKRB5TokenAPREQShouldSurfaceADelegationFailure(t *testing.T) {
	t.Parallel()

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

	cl := client.NewWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue", c)

	var tkt messages.Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(b))

	key := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}

	start := time.Now()
	mt, err := NewKRB5TokenAPREQ(cl, tkt, key, []int{gssapi.ContextFlagDeleg}, []int{})
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorContains(t, err, "obtaining a forwarded TGT to delegate",
		"the error must name the propagation hop it travelled, not just any failure")
	assert.ErrorContains(t, err, "does not have any defined KDCs",
		"the error must name the underlying cause")
	// The underlying failure is a configuration error with no sentinel of its own, so it is matched on its text.
	// What errors.Is can say about it is that it is not the one delegation failure that does have a sentinel, which
	// is what a caller deciding whether to tell the operator about forwardable = true needs to know.
	assert.NotErrorIs(t, err, client.ErrNotForwardable,
		"a missing KDC must not be classified as a non-forwardable TGT")
	assert.Empty(t, mt.APReq.Ticket.Realm, "no usable token is returned alongside the error")
	assert.Less(t, elapsed, 1*time.Second,
		"a client with no KDCs configured must be rejected locally, without attempting a KDC round trip")
}

// ccacheClient builds a client the way a delegating caller does, from a credential cache, with the captured test
// vector's credential times shifted forward so the TGT is currently valid and no KDC exchange is needed to establish
// the session. forwardable selects whether the TGT keeps the FORWARDABLE flag the KDC issued it with.
//
// The realm's KDCs are cleared so that anything reaching the network fails locally rather than dialling.
func ccacheClient(t *testing.T, forwardable bool) *client.Client {
	t.Helper()

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)

	cc := new(credentials.CCache)
	require.NoError(t, cc.Unmarshal(b))

	spn := types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", "TEST.GOKRB5"}}

	tgt, ok := cc.GetEntry(spn)
	require.True(t, ok, "the ccache test vector must contain a TGT")
	require.True(t, types.IsFlagSet(&tgt.TicketFlags, flags.Forwardable),
		"the ccache test vector's TGT must be forwardable for this fixture to control the flag")

	if !forwardable {
		types.UnsetFlag(&tgt.TicketFlags, flags.Forwardable)
	}

	offset := time.Now().UTC().Add(-1 * time.Hour).Sub(tgt.AuthTime)

	for _, cred := range cc.Credentials {
		cred.AuthTime = cred.AuthTime.Add(offset)
		cred.StartTime = cred.StartTime.Add(offset)
		cred.EndTime = cred.EndTime.Add(offset)
		cred.RenewTill = cred.RenewTill.Add(offset)
	}

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

	cl, err := client.NewFromCCache(cc, c)
	require.NoError(t, err)

	return cl
}

// TestNewKRB5TokenAPREQShouldHonourTheDelegationOption pins the option on the entry point that consumes it. The
// option used to be read only by NewNegTokenInitKRB5, so passing Delegation() here returned a perfectly valid
// 24 octet non-delegating checksum and no error: an unobservable downgrade for a caller that believed it had
// delegated. Reaching the forwarding exchange at all is the proof the option was honoured; the exchange itself
// cannot succeed against a fixture with no KDCs.
func TestNewKRB5TokenAPREQShouldHonourTheDelegationOption(t *testing.T) {
	t.Parallel()

	cl := ccacheClient(t, true)

	var tkt messages.Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(b))

	key := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}

	_, err = NewKRB5TokenAPREQ(cl, tkt, key, []int{gssapi.ContextFlagInteg}, nil, Delegation())

	require.Error(t, err)
	assert.ErrorContains(t, err, "obtaining a forwarded TGT to delegate",
		"Delegation() passed to NewKRB5TokenAPREQ must reach the forwarding exchange")
}

// TestNewKRB5TokenAPREQShouldNotDelegateWithoutTheOption is the counterpart: without Delegation() and without
// gssapi.ContextFlagDeleg no forwarding is attempted and the checksum is the 24 octet form.
func TestNewKRB5TokenAPREQShouldNotDelegateWithoutTheOption(t *testing.T) {
	t.Parallel()

	cl := ccacheClient(t, true)

	var tkt messages.Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(b))

	key := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}

	mt, err := NewKRB5TokenAPREQ(cl, tkt, key, []int{gssapi.ContextFlagInteg}, nil)
	require.NoError(t, err)

	// The authenticator is sealed under the same session key it was encrypted with, so the checksum has to be
	// decrypted back out to be read.
	require.NoError(t, mt.APReq.DecryptAuthenticator(key))

	assert.Equal(t, chksumtype.GSSAPI, mt.APReq.Authenticator.Cksum.CksumType)
	assert.Len(t, mt.APReq.Authenticator.Cksum.Checksum, 24,
		"a token that was not asked to delegate must carry no delegation fields")
}

// TestNewKRB5TokenAPREQShouldReturnAMatchableErrNotForwardable asserts the one delegation failure with an
// operator-actionable remedy stays classifiable at the outermost public call. It used to be wrapped with
// krberror.Errorf, which flattens what it wraps into strings and has no Unwrap, so errors.Is failed and a caller
// could only tell "the operator needs forwardable = true" from any other KDC failure by matching on substrings.
func TestNewKRB5TokenAPREQShouldReturnAMatchableErrNotForwardable(t *testing.T) {
	t.Parallel()

	cl := ccacheClient(t, false)

	var tkt messages.Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(b))

	key := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}

	_, err = NewKRB5TokenAPREQ(cl, tkt, key, []int{gssapi.ContextFlagDeleg}, nil)

	require.Error(t, err)
	require.ErrorIs(t, err, client.ErrNotForwardable,
		"the sentinel must survive every wrap between client.ForwardedTGT and NewKRB5TokenAPREQ")
	assert.ErrorContains(t, err, "forwardable = true",
		"the error must still name the setting that fixes it")
}

// TestNewNegTokenInitKRB5ShouldReturnAMatchableErrNotForwardable covers the SPNEGO entry point, which wraps once
// more on the way out.
func TestNewNegTokenInitKRB5ShouldReturnAMatchableErrNotForwardable(t *testing.T) {
	t.Parallel()

	cl := ccacheClient(t, false)

	var tkt messages.Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(b))

	key := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}

	_, err = NewNegTokenInitKRB5(cl, tkt, key, Delegation())

	require.Error(t, err)
	require.ErrorIs(t, err, client.ErrNotForwardable)
}

// TestDelegationRequestedShouldTestTheBit pins that callers may combine GSS-API context flags into one slice
// element, which is what the flags are: a bitmask. delegationRequested is the only thing deciding whether a KDC
// round trip happens, so a value comparison here would silently skip the forwarding exchange for a caller passing
// ContextFlagDeleg|ContextFlagInteg and produce the non-delegating token that this branch exists to prevent.
func TestDelegationFlaggedShouldTestTheBit(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		flags    []int
		expected bool
	}{
		{"ShouldDetectTheFlagOnItsOwn", []int{gssapi.ContextFlagDeleg}, true},
		{"ShouldDetectTheFlagCombinedIntoOneElement", []int{gssapi.ContextFlagDeleg | gssapi.ContextFlagInteg}, true},
		{"ShouldDetectTheFlagAlongsideOthers", []int{gssapi.ContextFlagInteg, gssapi.ContextFlagDeleg}, true},
		{"ShouldNotDetectOtherFlagsCombined", []int{gssapi.ContextFlagInteg | gssapi.ContextFlagConf}, false},
		{"ShouldNotDetectOtherFlags", []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, false},
		{"ShouldNotDetectAnythingInNoFlags", nil, false},
		{"ShouldDetectThePolicyFlagOnItsOwn", []int{gssapi.ContextFlagDelegPolicy}, true},
		{"ShouldDetectThePolicyFlagCombinedIntoOneElement", []int{gssapi.ContextFlagDelegPolicy | gssapi.ContextFlagInteg}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, delegationFlagged(tc.flags))
		})
	}
}

func TestNewKRB5TokenOptionsShouldDefaultToNoChannelBinding(t *testing.T) {
	t.Parallel()

	assert.Nil(t, newKRB5TokenOptions().channelBinding)
}

func TestChannelBindingOptionShouldSetTheBinding(t *testing.T) {
	t.Parallel()

	cb := &gssapi.ChannelBinding{ApplicationData: []byte("tls-exporter:test")}

	assert.Same(t, cb, newKRB5TokenOptions(ChannelBinding(cb)).channelBinding)
}

// TestKRB5TokenVerifyShouldReportChannelBindingFailuresAsBadBindings asserts the GSS-API major status an acceptor
// reports for each outcome. RFC 2743 Section 2.2.2 gives channel binding failures their own status,
// GSS_S_BAD_BINDINGS, so that an initiator can tell "your credential is fine but you are on the wrong channel" from
// "your token is malformed". Collapsing both onto GSS_S_DEFECTIVE_TOKEN loses exactly the signal that distinguishes
// a misconfigured proxy from an attacker relaying a captured token onto another channel.
func TestKRB5TokenVerifyShouldReportChannelBindingFailuresAsBadBindings(t *testing.T) {
	t.Parallel()

	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}

	b, err := hex.DecodeString(testdata.HTTP_KEYTAB)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	sent := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:sent")}
	want := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:want")}

	// newTokenWithTicketTimes seals an AP_REQ carrying the Bnd of the binding provided (or the sixteen zero bytes
	// meaning "no channel bindings" when it is nil) into a KRB5Token whose acceptor settings require want. The
	// ticket's StartTime and EndTime are caller controlled so that tests can produce a ticket APReq.Verify rejects
	// for reasons other than channel binding, such as expiry.
	newTokenWithTicketTimes := func(t *testing.T, cb *gssapi.ChannelBinding, start, end time.Time) *KRB5Token {
		t.Helper()

		cl := getClient(t)
		st := time.Now().UTC()

		tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
			sname, "TEST.GOKRB5", types.NewKrbFlags(), kt, 18, 1,
			st, start, end, st.Add(48*time.Hour),
		)
		require.NoError(t, err)

		auth, err := types.NewAuthenticator(cl.Credentials.Domain(), cl.Credentials.CName())
		require.NoError(t, err)
		require.NoError(t, auth.GenerateSeqNumberAndSubKey(18, 32))

		chksum, err := newAuthenticatorChksum(nil, cb, nil)
		require.NoError(t, err)

		auth.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: chksum}

		apreq, err := messages.NewAPReq(tkt, sessionKey, auth)
		require.NoError(t, err)

		tb, err := hex.DecodeString(TOK_ID_KRB_AP_REQ)
		require.NoError(t, err)

		return &KRB5Token{
			tokID:    tb,
			APReq:    apreq,
			settings: service.NewSettings(kt, service.RequireChannelBinding(want)),
		}
	}

	// newToken is newTokenWithTicketTimes with a ticket that is valid now, for the subtests below that exercise
	// channel binding rather than ticket validity.
	newToken := func(t *testing.T, cb *gssapi.ChannelBinding) *KRB5Token {
		t.Helper()

		st := time.Now().UTC()

		return newTokenWithTicketTimes(t, cb, st, st.Add(24*time.Hour))
	}

	t.Run("MismatchedBinding", func(t *testing.T) {
		t.Parallel()

		ok, status := newToken(t, sent).Verify()
		assert.False(t, ok)
		assert.Equal(t, gssapi.StatusBadBindings, status.Code)
		assert.Contains(t, status.Message, "channel binding mismatch")
	})

	// An initiator that sent no bindings at all is still a bad-bindings failure rather than a defective token: the
	// token is well formed, it simply does not match the bindings the acceptor supplied.
	t.Run("NoBindingSent", func(t *testing.T) {
		t.Parallel()

		ok, status := newToken(t, nil).Verify()
		assert.False(t, ok)
		assert.Equal(t, gssapi.StatusBadBindings, status.Code)
	})

	t.Run("MatchingBinding", func(t *testing.T) {
		t.Parallel()

		ok, status := newToken(t, want).Verify()
		assert.True(t, ok)
		assert.Equal(t, gssapi.StatusComplete, status.Code)
	})

	// A VerifyAPREQ failure that is not a channel binding failure must still surface as GSS_S_DEFECTIVE_TOKEN even
	// when the binding sent matches the binding required. An expired ticket exercises this: APReq.Verify rejects it
	// in messages.Ticket.Valid before verifyChannelBinding is ever reached, so the only way this subtest could see
	// StatusBadBindings is if the errors.Is(err, service.ErrBadChannelBinding) discrimination in KRB5Token.Verify were
	// broadened to match unconditionally.
	t.Run("ExpiredTicketWithMatchingBindingIsNotABadBindingsFailure", func(t *testing.T) {
		t.Parallel()

		past := time.Now().UTC().Add(-24 * time.Hour)

		ok, status := newTokenWithTicketTimes(t, want, past, past.Add(time.Hour)).Verify()
		assert.False(t, ok)
		assert.Equal(t, gssapi.StatusDefectiveToken, status.Code)
		assert.NotEqual(t, gssapi.StatusBadBindings, status.Code)
	})
}

// TestKrb5TokenAuthenticatorShouldAdvertiseCBTWhenBound asserts MS-KILE Section 3.2.5.2: a client supplying
// channel bindings also sends AD-AUTH-DATA-AP-OPTIONS with KERB_AP_OPTIONS_CBT in the first AD-IF-RELEVANT
// element. That advertisement, not the Bnd field, is what a Windows acceptor with ApplicationRequiresCBT uses to
// tell a binding-capable client from one predating the feature.
func TestKrb5TokenAuthenticatorShouldAdvertiseCBTWhenBound(t *testing.T) {
	t.Parallel()

	cl := getClient(t)
	cb := &gssapi.ChannelBinding{ApplicationData: []byte("tls-server-end-point:test")}

	bound, err := krb5TokenAuthenticator(cl, messages.Ticket{}, types.EncryptionKey{},
		[]int{gssapi.ContextFlagInteg}, cb)
	require.NoError(t, err)

	assert.True(t, types.ADAPOptionsFromAuthorizationData(bound.AuthorizationData).Has(types.ADAPOptionsCBT))

	// Without a binding there is nothing to advertise, and the authenticator must be what it was before.
	unbound, err := krb5TokenAuthenticator(cl, messages.Ticket{}, types.EncryptionKey{},
		[]int{gssapi.ContextFlagInteg}, nil)
	require.NoError(t, err)

	assert.Empty(t, unbound.AuthorizationData)
}

// krb5TokenWithOID re-stamps the sample KRB5 token with the mechanism OID given, leaving the token ID and the
// AP_REQ that follow it untouched.
func krb5TokenWithOID(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()

	b, err := hex.DecodeString(KRB5TokenHex)
	require.NoError(t, err)

	var original asn1.ObjectIdentifier

	rest, err := asn1.UnmarshalWithParams(b, &original, "application,explicit,tag:0")
	require.NoError(t, err)

	ob, err := asn1.Marshal(oid, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	return asn1tools.AddASNAppTag(append(ob, rest...), 0)
}

func TestKRB5Token_UnmarshalAcceptsTheMechanismsSPNEGONegotiates(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"KRB5", gssapi.OIDKRB5.OID()},
		{"MS legacy KRB5", gssapi.OIDMSLegacyKRB5.OID()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var mt KRB5Token

			require.NoError(t, mt.Unmarshal(krb5TokenWithOID(t, tc.oid)))

			assert.True(t, mt.IsAPReq())
			assert.Equal(t, tc.oid, mt.OID)

			mb, err := mt.Marshal()
			require.NoError(t, err)
			assert.Equal(t, krb5TokenWithOID(t, tc.oid), mb)
		})
	}
}

func TestKRB5Token_UnmarshalRejectsAnUnrelatedMechanism(t *testing.T) {
	t.Parallel()

	var mt KRB5Token

	assert.Error(t, mt.Unmarshal(krb5TokenWithOID(t, gssapi.OIDGSSIAKerb.OID())))
}

// krbErrorMechToken builds a Kerberos GSS-API mech token whose TOK_ID is TOK_ID_KRB_ERROR, which is what a peer
// sends to report that it could not authenticate the exchange.
func krbErrorMechToken(t *testing.T) []byte {
	t.Helper()

	kerr := messages.NewKRBError(
		types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"HTTP", "host.test.gokrb5"}},
		"TEST.GOKRB5", errorcode.KDC_ERR_PREAUTH_FAILED, "nothing to see here")

	eb, err := kerr.Marshal()
	require.NoError(t, err)

	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID(),
		asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	tokID, err := hex.DecodeString(TOK_ID_KRB_ERROR)
	require.NoError(t, err)

	b := append(append(append([]byte{}, oid...), tokID...), eb...)

	return asn1tools.AddASNAppTag(b, 0)
}

// A KRB_ERROR is the peer reporting that it could not authenticate the exchange. It is never an authentication, so
// Verify must not report one: RFC 2743 Section 2.2.1 has an acceptor establish a context only on GSS_S_COMPLETE.
func TestKRB5Token_VerifyShouldNotAuthenticateAKRBError(t *testing.T) {
	t.Parallel()

	var mt KRB5Token

	require.NoError(t, mt.Unmarshal(krbErrorMechToken(t)))
	require.True(t, mt.IsKRBError(), "the token under test must be a KRB_ERROR")

	ok, status := mt.Verify()

	assert.False(t, ok, "a KRB_ERROR reports that authentication failed, so it cannot authenticate anyone")
	assert.Equal(t, gssapi.StatusUnavailable, status.Code,
		"the status still distinguishes a KRB_ERROR from a defective token")
}

// The same thing through the exported GSS-API entry point an acceptor uses, which is where a caller branching on the
// success indication rather than the status code would admit the request.
func TestAcceptSecContextShouldNotAuthenticateAKRBError(t *testing.T) {
	t.Parallel()

	nt := NegTokenInit{
		MechTypes:      []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
		MechTokenBytes: krbErrorMechToken(t),
	}

	ntb, err := nt.Marshal()
	require.NoError(t, err)

	spOID, err := asn1.Marshal(gssapi.OIDSPNEGO.OID(),
		asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	var st SPNEGOToken

	require.NoError(t, st.Unmarshal(asn1tools.AddASNAppTag(append(spOID, ntb...), 0)))

	authed, ctx, status := SPNEGOService(keytab.New()).AcceptSecContext(&st)

	assert.False(t, authed, "a token carrying only a KRB_ERROR must not report an authenticated context")
	assert.Nil(t, ctx, "and it establishes no context to carry an identity")
	assert.NotEqual(t, gssapi.StatusComplete, status.Code)
}
