package messages

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/addrtype"
	"github.com/go-krb5/krb5/iana/adtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/trtype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestUnmarshalTicket(t *testing.T) {
	t.Parallel()

	var a Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, iana.PVNO, a.TktVNO)
	assert.Equal(t, testdata.TEST_REALM, a.Realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType)
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString))
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString)
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher)
}

func TestUnmarshalEncTicketPart(t *testing.T) {
	t.Parallel()

	var a EncTicketPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_tkt_part)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes))
	assert.Equal(t, int32(1), a.Key.KeyType)
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue)
	assert.Equal(t, testdata.TEST_REALM, a.CRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType)
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString)
	assert.Equal(t, trtype.DOMAIN_X500_COMPRESS, a.Transited.TRType)
	assert.Equal(t, []byte("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."), a.Transited.Contents)
	assert.Equal(t, tt, a.AuthTime)
	assert.Equal(t, tt, a.StartTime)
	assert.Equal(t, tt, a.EndTime)
	assert.Equal(t, tt, a.RenewTill)
	assert.Equal(t, 2, len(a.CAddr))

	for _, addr := range a.CAddr {
		assert.Equal(t, addrtype.IPv4, addr.AddrType)
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address))
	}

	for _, ele := range a.AuthorizationData {
		assert.Equal(t, adtype.ADIfRelevant, ele.ADType)
		assert.Equal(t, []byte(testdata.TEST_AUTHORIZATION_DATA_VALUE), ele.ADData)
	}
}

func TestUnmarshalEncTicketPart_optionalsNULL(t *testing.T) {
	t.Parallel()

	var a EncTicketPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_tkt_partOptionalsNULL)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	tt, err := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)
	require.NoError(t, err)

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes))
	assert.Equal(t, int32(1), a.Key.KeyType)
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue)
	assert.Equal(t, testdata.TEST_REALM, a.CRealm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType)
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString)
	assert.Equal(t, trtype.DOMAIN_X500_COMPRESS, a.Transited.TRType)
	assert.Equal(t, []byte("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."), a.Transited.Contents)
	assert.Equal(t, tt, a.AuthTime)
	assert.Equal(t, tt, a.EndTime)
}

func TestMarshalTicket(t *testing.T) {
	t.Parallel()

	var a Ticket

	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	mb, err := a.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)
}

func TestAuthorizationData_GetPACType_GOKRB5TestData(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_AuthorizationData_GOKRB5)
	require.NoError(t, err)

	var a types.AuthorizationData

	require.NoError(t, a.Unmarshal(b))

	tkt := Ticket{
		Realm: "TEST.GOKRB5",
		EncPart: types.EncryptedData{
			EType: 18,
			KVNO:  2,
		},
		DecryptedEncPart: EncTicketPart{
			AuthorizationData: a,
		},
	}

	b, err = hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()

	require.NoError(t, kt.Unmarshal(b))

	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"sysHTTP"}}
	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)

	isPAC, pac, err := tkt.GetPACType(kt, &sname, l)
	if err != nil {
		require.NoError(t, err)
	}

	assert.True(t, isPAC)
	assert.Equal(t, 5, len(pac.Buffers))
	assert.Equal(t, uint32(5), pac.CBuffers)
	assert.Equal(t, uint32(0), pac.Version)
	assert.NotNil(t, pac.KerbValidationInfo)
	assert.NotNil(t, pac.ClientInfo)
	assert.NotNil(t, pac.UPNDNSInfo)
	assert.NotNil(t, pac.KDCChecksum)
	assert.NotNil(t, pac.ServerChecksum)
}

func TestGetPACType_EmptyIfRelevant(t *testing.T) {
	t.Parallel()

	empty, err := asn1.Marshal(types.AuthorizationData{},
		asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	tkt := Ticket{
		Realm: "TEST.GOKRB5",
		DecryptedEncPart: EncTicketPart{
			AuthorizationData: types.AuthorizationData{
				{ADType: adtype.ADIfRelevant, ADData: empty},
			},
		},
	}

	w := bytes.NewBufferString("")

	require.NotPanics(t, func() {
		isPAC, _, err := tkt.GetPACType(keytab.New(), nil, log.New(w, "", 0))

		assert.False(t, isPAC)
		assert.NoError(t, err)
	})
}

func TestGetPACType_PACNotFirstInIfRelevant(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_AuthorizationData_GOKRB5)
	require.NoError(t, err)

	var a types.AuthorizationData

	require.NoError(t, a.Unmarshal(b))
	require.Equal(t, adtype.ADIfRelevant, a[0].ADType)

	var inner types.AuthorizationData

	require.NoError(t, inner.Unmarshal(a[0].ADData))
	require.NotEmpty(t, inner)

	// Push the PAC behind an element this library does not recognise.
	inner = append(types.AuthorizationData{
		{ADType: adtype.ADIntendedForServer, ADData: []byte{0x01, 0x02, 0x03}},
	}, inner...)

	a[0].ADData, err = asn1.Marshal(inner,
		asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	tkt := Ticket{
		Realm: "TEST.GOKRB5",
		EncPart: types.EncryptedData{
			EType: 18,
			KVNO:  2,
		},
		DecryptedEncPart: EncTicketPart{
			AuthorizationData: a,
		},
	}

	b, err = hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()

	require.NoError(t, kt.Unmarshal(b))

	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"sysHTTP"}}
	w := bytes.NewBufferString("")

	isPAC, p, err := tkt.GetPACType(kt, &sname, log.New(w, "", 0))

	require.NoError(t, err)
	assert.True(t, isPAC)
	assert.NotNil(t, p.KerbValidationInfo)
	assert.NotNil(t, p.ServerChecksum)
}

func TestGetPACType_NilLogger(t *testing.T) {
	t.Parallel()

	tkt := Ticket{
		Realm: "TEST.GOKRB5",
		DecryptedEncPart: EncTicketPart{
			AuthorizationData: types.AuthorizationData{
				{ADType: adtype.ADIfRelevant, ADData: []byte{0xFF, 0xFF, 0xFF}},
			},
		},
	}

	require.NotPanics(t, func() {
		isPAC, _, err := tkt.GetPACType(keytab.New(), nil, nil)

		assert.False(t, isPAC)
		assert.NoError(t, err)
	})
}

// appendToSequence returns b, an [APPLICATION n] wrapping a SEQUENCE, with extra appended inside that SEQUENCE. It
// is how a peer smuggles an element the type does not define past a decoder that tolerates trailing data.
func appendToSequence(t *testing.T, b, extra []byte) []byte {
	t.Helper()

	lenBytes := func(n int) []byte {
		if n < 128 {
			//nolint:gosec // G115: guarded by the branch, n is below 128.
			return []byte{byte(n)}
		}

		var l []byte
		for m := n; m > 0; m >>= 8 {
			l = append([]byte{byte(m & 0xff)}, l...)
		}

		//nolint:gosec // G115: l holds one octet per byte of an int, so its length cannot exceed 8.
		return append([]byte{byte(0x80 | len(l))}, l...)
	}

	hdr := func(p int) int {
		if b[p] < 0x80 {
			return 1
		}

		return 1 + int(b[p]&0x7f)
	}

	p := 1 + hdr(1)
	seqTag := b[p]
	p++
	p += hdr(p)

	inner := append(append([]byte{}, b[p:]...), extra...)
	seq := append([]byte{seqTag}, lenBytes(len(inner))...)
	seq = append(seq, inner...)

	out := append([]byte{b[0]}, lenBytes(len(seq))...)

	return append(out, seq...)
}

// A Ticket's DecryptedEncPart is filled in by Decrypt, never by the peer. RFC 4120 Section 5.3 defines the wire
// Ticket as four fields, so an element appended past them must not reach it: a caller reading DecryptedEncPart is
// entitled to assume the KDC sealed what it finds there.
func TestTicketUnmarshalShouldNotAcceptADecryptedEncPart(t *testing.T) {
	t.Parallel()

	tkt := testWireTicket()

	b, err := tkt.Marshal()
	require.NoError(t, err)

	forged, err := asn1.Marshal(EncTicketPart{
		Flags:     types.NewKrbFlags(),
		Key:       types.EncryptionKey{KeyType: 18, KeyValue: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		CRealm:    "EVIL.REALM",
		CName:     types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"administrator"}},
		Transited: TransitedEncoding{TRType: trtype.DOMAIN_X500_COMPRESS},
		AuthTime:  time.Now().UTC(),
		EndTime:   time.Now().UTC().Add(time.Hour),
	}, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	var got Ticket

	// Whether the trailing element is rejected or ignored is the decoder's business; what matters is that it
	// never becomes the ticket's decrypted part.
	if err := got.Unmarshal(appendToSequence(t, b, forged)); err == nil {
		assert.Empty(t, got.DecryptedEncPart.CName.NameString,
			"a client name appended to the wire ticket became its decrypted part")
		assert.Empty(t, got.DecryptedEncPart.CRealm)
		assert.Empty(t, got.DecryptedEncPart.Key.KeyValue,
			"a session key appended to the wire ticket became its decrypted part")
	}
}

func TestTicketMarshalShouldNotEmitTheDecryptedEncPart(t *testing.T) {
	t.Parallel()

	tkt := testWireTicket()

	clean, err := tkt.Marshal()
	require.NoError(t, err)

	sessionKey := []byte("SUPER-SECRET-SESSION-KEY-32BYTES")
	tkt.DecryptedEncPart = EncTicketPart{
		Flags:     types.NewKrbFlags(),
		Key:       types.EncryptionKey{KeyType: 18, KeyValue: sessionKey},
		CRealm:    testRealm,
		CName:     types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"testuser"}},
		Transited: TransitedEncoding{TRType: trtype.DOMAIN_X500_COMPRESS},
		AuthTime:  time.Now().UTC(),
		EndTime:   time.Now().UTC().Add(time.Hour),
	}

	decrypted, err := tkt.Marshal()
	require.NoError(t, err)

	assert.NotContains(t, string(decrypted), string(sessionKey),
		"marshalling a decrypted ticket put its session key on the wire")
	assert.Equal(t, clean, decrypted,
		"decrypting a ticket must not change the bytes it marshals to")
}

func testWireTicket() Ticket {
	return Ticket{
		TktVNO:  iana.PVNO,
		Realm:   testRealm,
		SName:   types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"HTTP", "host.test.gokrb5"}},
		EncPart: types.EncryptedData{EType: 18, KVNO: 1, Cipher: []byte{1, 2, 3, 4}},
	}
}
