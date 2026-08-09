package messages

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/addrtype"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestUnmarshalKRBCred(t *testing.T) {
	t.Parallel()

	var a KRBCred

	b, err := hex.DecodeString(testdata.MarshaledKRB5cred)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_CRED, a.MsgType)
	assert.Equal(t, 2, len(a.Tickets))

	for _, tkt := range a.Tickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO)
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm)
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType)
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString)
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType)
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO)
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher)
	}

	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher)
}

func TestUnmarshalEncCredPart(t *testing.T) {
	t.Parallel()

	var a EncKrbCredPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_cred_part)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, 2, len(a.TicketInfo))

	for _, tkt := range a.TicketInfo {
		assert.Equal(t, int32(1), tkt.Key.KeyType)
		assert.Equal(t, []byte("12345678"), tkt.Key.KeyValue)
		assert.Equal(t, testdata.TEST_REALM, tkt.PRealm)
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.PName.NameType)
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.PName.NameString))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.PName.NameString)
		assert.Equal(t, "fedcba98", hex.EncodeToString(tkt.Flags.Bytes))
		assert.Equal(t, tt, tkt.AuthTime)
		assert.Equal(t, tt, tkt.StartTime)
		assert.Equal(t, tt, tkt.EndTime)
		assert.Equal(t, tt, tkt.RenewTill)
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType)
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString)
		assert.Equal(t, 2, len(tkt.CAddr))

		for _, addr := range tkt.CAddr {
			assert.Equal(t, addrtype.IPv4, addr.AddrType)
			assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address))
		}
	}

	assert.Equal(t, testdata.TEST_NONCE, a.Nouce)
	assert.Equal(t, tt, a.Timestamp)
	assert.Equal(t, 123456, a.Usec)
	assert.Equal(t, addrtype.IPv4, a.SAddress.AddrType)
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SAddress.Address))
	assert.Equal(t, addrtype.IPv4, a.RAddress.AddrType)
	assert.Equal(t, "12d00023", hex.EncodeToString(a.RAddress.Address))
}

func TestUnmarshalEncCredPart_optionalsNULL(t *testing.T) {
	t.Parallel()

	var a EncKrbCredPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_cred_partOptionalsNULL)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, 2, len(a.TicketInfo))

	assert.Equal(t, int32(1), a.TicketInfo[0].Key.KeyType)
	assert.Equal(t, []byte("12345678"), a.TicketInfo[0].Key.KeyValue)

	assert.Equal(t, int32(1), a.TicketInfo[1].Key.KeyType)
	assert.Equal(t, []byte("12345678"), a.TicketInfo[1].Key.KeyValue)
	assert.Equal(t, testdata.TEST_REALM, a.TicketInfo[1].PRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.TicketInfo[1].PName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.TicketInfo[1].PName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.TicketInfo[1].PName.NameString)
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.TicketInfo[1].Flags.Bytes))
	assert.Equal(t, tt, a.TicketInfo[1].AuthTime)
	assert.Equal(t, tt, a.TicketInfo[1].StartTime)
	assert.Equal(t, tt, a.TicketInfo[1].EndTime)
	assert.Equal(t, tt, a.TicketInfo[1].RenewTill)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.TicketInfo[1].SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.TicketInfo[1].SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.TicketInfo[1].SName.NameString)
	assert.Equal(t, 2, len(a.TicketInfo[1].CAddr))

	for _, addr := range a.TicketInfo[1].CAddr {
		assert.Equal(t, addrtype.IPv4, addr.AddrType)
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address))
	}
}

// testCredKey returns a deterministic aes256-cts-hmac-sha1-96 key for KRB_CRED round trips.
func testCredKey() types.EncryptionKey {
	return types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0B}, 32)}
}

// testKrbCredInfo returns a KrbCredInfo with every field this library populates set to a distinguishable value.
func testKrbCredInfo() KrbCredInfo {
	return KrbCredInfo{
		Key:      types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0C}, 32)},
		PRealm:   "TEST.GOKRB5",
		PName:    types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser1"}},
		SRealm:   "TEST.GOKRB5",
		SName:    types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", "TEST.GOKRB5"}},
		EndTime:  time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
		AuthTime: time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC),
	}
}

// TestKRBCredShouldRoundTrip asserts a KRB_CRED this library builds can be read back by the unmarshalling that
// already existed, which is the only in-tree evidence that the encoding is right.
func TestKRBCredShouldRoundTrip(t *testing.T) {
	t.Parallel()

	key := testCredKey()
	info := testKrbCredInfo()
	tkt := Ticket{TktVNO: iana.PVNO, Realm: info.SRealm, SName: info.SName}

	cred, err := NewKRBCred([]Ticket{tkt}, []KrbCredInfo{info}, key)
	require.NoError(t, err)

	assert.Equal(t, msgtype.KRB_CRED, cred.MsgType)
	assert.Equal(t, iana.PVNO, cred.PVNO)

	b, err := cred.Marshal()
	require.NoError(t, err)

	var out KRBCred

	require.NoError(t, out.Unmarshal(b))
	require.NoError(t, out.DecryptEncPart(key))

	require.Len(t, out.DecryptedEncPart.TicketInfo, 1)
	got := out.DecryptedEncPart.TicketInfo[0]
	assert.Equal(t, info.PRealm, got.PRealm)
	assert.Equal(t, info.PName, got.PName)
	assert.Equal(t, info.SRealm, got.SRealm)
	assert.Equal(t, info.SName, got.SName)
	assert.Equal(t, info.Key, got.Key)
	assert.True(t, info.EndTime.Equal(got.EndTime))
}

// TestKRBCredEncPartShouldUseKeyUsage14 asserts RFC 4120 Section 5.8.1: the enc-part is "encrypted under the
// session key shared by the sender and the intended recipient, with a key usage value of 14". A different usage
// would still round trip through our own code and fail against every other implementation.
func TestKRBCredEncPartShouldUseKeyUsage14(t *testing.T) {
	t.Parallel()

	key := testCredKey()
	info := testKrbCredInfo()
	tkt := Ticket{TktVNO: iana.PVNO, Realm: info.SRealm, SName: info.SName}

	cred, err := NewKRBCred([]Ticket{tkt}, []KrbCredInfo{info}, key)
	require.NoError(t, err)

	_, err = crypto.DecryptEncPart(cred.EncPart, key, keyusage.KRB_CRED_ENCPART)
	require.NoError(t, err)

	_, err = crypto.DecryptEncPart(cred.EncPart, key, keyusage.KRB_PRIV_ENCPART)
	require.Error(t, err, "decrypting under the wrong usage must fail, proving the usage is not incidental")
}

// TestEncKrbCredPartShouldOmitTheOptionalFields asserts nonce, timestamp, usec, s-address and r-address are absent
// when unset. They are OPTIONAL in RFC 4120 Section 5.8.1, and MIT clears KRB5_AUTH_CONTEXT_DO_TIME on both sides
// of the GSS forwarding path, so emitting a timestamp buys no freshness check any peer performs while risking a
// clock skew rejection.
func TestEncKrbCredPartShouldOmitTheOptionalFields(t *testing.T) {
	t.Parallel()

	p := &EncKrbCredPart{TicketInfo: []KrbCredInfo{testKrbCredInfo()}}

	b, err := p.Marshal()
	require.NoError(t, err)

	var out EncKrbCredPart

	require.NoError(t, out.Unmarshal(b))
	assert.Zero(t, out.Nouce)
	assert.True(t, out.Timestamp.IsZero())
	assert.Zero(t, out.Usec)
	assert.Empty(t, out.SAddress.Address)
	assert.Empty(t, out.RAddress.Address)
}

// TestKRBCredDecryptEncPartShouldAcceptAnUnencryptedEncPart covers the RFC 4120 Section 5.8.1 implementation note:
// "Implementations of certain applications, most notably certain implementations of the Kerberos GSS-API
// mechanism, do not separately encrypt the contents of the EncKrbCredPart". No confidentiality is lost because the
// whole message travels inside the already encrypted authenticator. We accept this and never emit it.
func TestKRBCredDecryptEncPartShouldAcceptAnUnencryptedEncPart(t *testing.T) {
	t.Parallel()

	info := testKrbCredInfo()

	plain, err := (&EncKrbCredPart{TicketInfo: []KrbCredInfo{info}}).Marshal()
	require.NoError(t, err)

	cred := KRBCred{EncPart: types.EncryptedData{EType: 0, Cipher: plain}}

	require.NoError(t, cred.DecryptEncPart(testCredKey()))
	require.Len(t, cred.DecryptedEncPart.TicketInfo, 1)
	assert.Equal(t, info.PName, cred.DecryptedEncPart.TicketInfo[0].PName)
}

// TestKRBCredDecryptEncPartShouldRejectAShortCipher pins the acceptor side of the delegation path against a peer
// that sends a KRB_CRED whose EncPart declares a real encryption type over a few bytes of Cipher. Any client
// holding a valid service ticket can send one, and the ciphertext used to be sliced to strip its integrity hash
// with no length check, panicking the acceptor process. Found by fuzzing.
func TestKRBCredDecryptEncPartShouldRejectAShortCipher(t *testing.T) {
	t.Parallel()

	for _, etype := range []int32{17, 18, 19, 20} {
		cred := KRBCred{EncPart: types.EncryptedData{EType: etype, Cipher: []byte{1, 2, 3, 4, 5, 6}}}

		assert.NotPanics(t, func() {
			err := cred.DecryptEncPart(testCredKey())

			require.Error(t, err)
			assert.Contains(t, err.Error(), "too short")
		}, "etype %d must reject a six byte cipher with an error, not a panic", etype)
	}
}

// TestNewKrbCredInfoShouldCopyTheTicketFields asserts the KrbCredInfo mirrors the TGS_REP, as RFC 4120 Section
// 5.8.1 requires: "These fields contain the values of the corresponding fields from the ticket found in the ticket
// field."
func TestNewKrbCredInfoShouldCopyTheTicketFields(t *testing.T) {
	t.Parallel()

	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser1"}}
	dep := EncKDCRepPart{
		Key:      types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x0D}, 32)},
		Flags:    asn1.BitString{Bytes: []byte{0x40, 0x00, 0x00, 0x00}, BitLength: 32},
		AuthTime: time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC),
		EndTime:  time.Date(2026, 8, 9, 20, 0, 0, 0, time.UTC),
		SRealm:   "TEST.GOKRB5",
		SName:    types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", "TEST.GOKRB5"}},
	}

	info := NewKrbCredInfo(dep, cname, "TEST.GOKRB5")

	assert.Equal(t, dep.Key, info.Key)
	assert.Equal(t, dep.Flags, info.Flags)
	assert.Equal(t, dep.SRealm, info.SRealm)
	assert.Equal(t, dep.SName, info.SName)
	assert.Equal(t, cname, info.PName)
	assert.Equal(t, "TEST.GOKRB5", info.PRealm)
	assert.True(t, dep.EndTime.Equal(info.EndTime))
}

// TestKRBCredCCacheShouldPairTicketsWithTheirInfo asserts the conversion an acceptor uses to turn a delegated
// credential into something client.NewFromCCache can consume.
func TestKRBCredCCacheShouldPairTicketsWithTheirInfo(t *testing.T) {
	t.Parallel()

	info := testKrbCredInfo()
	tkt := Ticket{
		TktVNO: iana.PVNO,
		Realm:  info.SRealm,
		SName:  info.SName,
	}

	cred, err := NewKRBCred([]Ticket{tkt}, []KrbCredInfo{info}, testCredKey())
	require.NoError(t, err)

	cc, err := cred.CCache()
	require.NoError(t, err)

	assert.Equal(t, uint8(4), cc.Version)
	assert.Equal(t, info.PName, cc.GetClientPrincipalName())
	assert.Equal(t, info.PRealm, cc.GetClientRealm())

	require.Len(t, cc.Credentials, 1)
	got := cc.Credentials[0]
	assert.Equal(t, info.Key, got.Key)
	assert.Equal(t, info.SName, got.Server.PrincipalName)
	assert.Equal(t, info.SRealm, got.Server.Realm)
	assert.True(t, info.EndTime.Equal(got.EndTime))
	assert.NotEmpty(t, got.Ticket, "the marshalled ticket must be carried so the cache is usable")
}

// TestKRBCredCCacheShouldRejectAMismatchedCount asserts the pairing RFC 4120 Section 5.8.1 requires is checked
// rather than assumed. A KRB_CRED from a peer can carry any counts at all.
func TestKRBCredCCacheShouldRejectAMismatchedCount(t *testing.T) {
	t.Parallel()

	cred := KRBCred{
		Tickets:          []Ticket{{Realm: "TEST.GOKRB5"}, {Realm: "TEST.GOKRB5"}},
		DecryptedEncPart: EncKrbCredPart{TicketInfo: []KrbCredInfo{testKrbCredInfo()}},
	}

	cc, err := cred.CCache()

	require.Error(t, err)
	assert.Nil(t, cc)
	assert.Contains(t, err.Error(), "they must correspond")
}

// TestKRBCredCCacheShouldRejectAnEmptyCredential asserts a KRB_CRED conveying nothing is an error rather than an
// empty cache, which a caller would otherwise use as though a delegation had happened.
func TestKRBCredCCacheShouldRejectAnEmptyCredential(t *testing.T) {
	t.Parallel()

	cc, err := (&KRBCred{}).CCache()

	require.Error(t, err)
	assert.Nil(t, cc)
	assert.Contains(t, err.Error(), "no credentials")
}
