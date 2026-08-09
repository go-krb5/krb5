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

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
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

	cb, err := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
	require.NoError(t, err)
	assert.Equal(t, b, cb)
}

// Test with explicit subkey generation.
func TestKRB5Token_newAuthenticatorWithSubkeyGeneration(t *testing.T) {
	t.Parallel()

	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})

	var etypeID int32 = 18

	keyLen := 32

	a, err := krb5TokenAuthenticator(creds, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
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

	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})

	a, err := krb5TokenAuthenticator(creds, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
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

	c, err := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, cb)
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

	c, err := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
	require.NoError(t, err)

	require.Len(t, c, 24)
	assert.Equal(t, uint32(16), binary.LittleEndian.Uint32(c[:4]))
	assert.Equal(t, make([]byte, 16), c[4:20])
	assert.Equal(t, uint32(gssapi.ContextFlagInteg|gssapi.ContextFlagConf), binary.LittleEndian.Uint32(c[20:24]))
}

// TestNewAuthenticatorChksumShouldRefuseDelegation asserts the library refuses to claim a delegation it cannot
// perform. RFC 4121 Section 4.1.1 requires DlgOpt to carry the delegation option identifier 1 and Deleg to carry a
// KRB_CRED whenever the delegation flag is set. This library implements neither, and the 28 zeroed octets it used to
// emit are rejected by MIT with GSS_S_FAILURE once it reads DlgOpt as 0. Failing here names the cause at the call
// site instead.
func TestNewAuthenticatorChksumShouldRefuseDelegation(t *testing.T) {
	t.Parallel()

	c, err := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagDeleg}, nil)

	require.ErrorIs(t, err, ErrDelegationUnimplemented)
	assert.Nil(t, c, "no checksum is returned when the flags cannot be honoured")
	assert.Contains(t, err.Error(), "RFC 4121")
}

// TestNewAuthenticatorChksumShouldRefuseCombinedDelegationBitmask asserts the guard tests the bit rather than the
// value. The flags loop below the guard accumulates ORed values with f |= uint32(i), so a caller passing a combined
// bitmask in a single slice element is an invited call style, not a misuse. A guard written as i ==
// gssapi.ContextFlagDeleg misses that case: ContextFlagDeleg|ContextFlagInteg reaches the flags loop unrefused and
// sets GSS_C_DELEG_FLAG in the emitted checksum with none of the delegation fields populated, which is exactly the
// false claim of delegation this refusal exists to prevent.
func TestNewAuthenticatorChksumShouldRefuseCombinedDelegationBitmask(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		flags       []int
		wantRefused bool
	}{
		{
			name:        "DelegationAlone",
			flags:       []int{gssapi.ContextFlagDeleg},
			wantRefused: true,
		},
		{
			name:        "DelegationCombinedWithIntegInOneElement",
			flags:       []int{gssapi.ContextFlagDeleg | gssapi.ContextFlagInteg},
			wantRefused: true,
		},
		{
			name:        "IntegAndConfCombinedWithoutDelegationMustStillSucceed",
			flags:       []int{gssapi.ContextFlagInteg | gssapi.ContextFlagConf},
			wantRefused: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, err := newAuthenticatorChksum(tt.flags, nil)

			if tt.wantRefused {
				require.ErrorIs(t, err, ErrDelegationUnimplemented)
				assert.Nil(t, c, "no checksum is returned when the flags cannot be honoured")

				return
			}

			require.NoError(t, err)
			assert.Len(t, c, 24)
		})
	}
}

// TestNewKRB5TokenAPREQShouldSurfaceDelegationRefusal covers the propagation hop rather than only the leaf: the error
// has to travel newAuthenticatorChksum -> krb5TokenAuthenticator -> NewKRB5TokenAPREQ to reach a caller.
func TestNewKRB5TokenAPREQShouldSurfaceDelegationRefusal(t *testing.T) {
	t.Parallel()

	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})
	cl := &client.Client{Credentials: creds}

	var tkt messages.Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(b))

	key := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}

	_, err = NewKRB5TokenAPREQ(cl, tkt, key, []int{gssapi.ContextFlagDeleg}, []int{})
	require.ErrorIs(t, err, ErrDelegationUnimplemented)
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

		chksum, err := newAuthenticatorChksum(nil, cb)
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
