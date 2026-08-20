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
