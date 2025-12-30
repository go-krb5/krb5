package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/addrtype"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/test/testdata"
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
