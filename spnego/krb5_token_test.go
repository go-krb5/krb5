package spnego

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
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

	cb := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
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

	c := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, cb)

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

	c := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)

	require.Len(t, c, 24)
	assert.Equal(t, uint32(16), binary.LittleEndian.Uint32(c[:4]))
	assert.Equal(t, make([]byte, 16), c[4:20])
	assert.Equal(t, uint32(gssapi.ContextFlagInteg|gssapi.ContextFlagConf), binary.LittleEndian.Uint32(c[20:24]))
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
