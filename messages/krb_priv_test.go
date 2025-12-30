package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/addrtype"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestUnmarshalKRBPriv(t *testing.T) {
	t.Parallel()

	var a KRBPriv

	b, err := hex.DecodeString(testdata.MarshaledKRB5priv)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}

	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	assert.Equal(t, iana.PVNO, a.PVNO)
	assert.Equal(t, msgtype.KRB_PRIV, a.MsgType)
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO)
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType)
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher, "Cipher text of EncPart not as expected")
}

func TestUnmarshalEncPrivPart(t *testing.T) {
	t.Parallel()

	var a EncKrbPrivPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_priv_part)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}

	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	// Parse the test time value into a time.Time type.
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "krb5data", string(a.UserData), "User data not as expected")
	assert.Equal(t, tt, a.Timestamp)
	assert.Equal(t, 123456, a.Usec)
	assert.Equal(t, int64(17), a.SequenceNumber, "Sequence number not as expected")
	assert.Equal(t, addrtype.IPv4, a.SAddress.AddrType)
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SAddress.Address), "Address not as expected for SAddress")
	assert.Equal(t, addrtype.IPv4, a.RAddress.AddrType)
	assert.Equal(t, "12d00023", hex.EncodeToString(a.RAddress.Address), "Address not as expected for RAddress")
}

func TestUnmarshalEncPrivPart_optionalsNULL(t *testing.T) {
	t.Parallel()

	var a EncKrbPrivPart

	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_priv_partOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}

	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	assert.Equal(t, "krb5data", string(a.UserData), "User data not as expected")
	assert.Equal(t, addrtype.IPv4, a.SAddress.AddrType)
	assert.Equal(t, "12d00023", hex.EncodeToString(a.SAddress.Address), "Address not as expected for SAddress")
}

func TestMarshalKRBPriv(t *testing.T) {
	t.Parallel()

	var a KRBPriv

	b, err := hex.DecodeString(testdata.MarshaledKRB5priv)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}

	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("error marshaling KRBPriv: %v", err)
	}

	assert.Equal(t, b, mb)

	be, err := hex.DecodeString(testdata.MarshaledKRB5enc_priv_part)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}

	err = a.DecryptedEncPart.Unmarshal(be)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	mb, err = a.Marshal()
	if err != nil {
		t.Fatalf("error marshaling KRBPriv: %v", err)
	}

	assert.Equal(t, b, mb)
}

func TestKRBPriv_EncryptEncPart(t *testing.T) {
	t.Parallel()

	var a KRBPriv

	b, err := hex.DecodeString(testdata.MarshaledKRB5priv)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}

	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	b, err = hex.DecodeString(testdata.MarshaledKRB5enc_priv_part)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}

	err = a.DecryptedEncPart.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	key := types.EncryptionKey{
		KeyType:  int32(18),
		KeyValue: []byte("12345678901234567890123456789012"),
	}

	err = a.EncryptEncPart(key)
	if err != nil {
		t.Fatalf("error encrypting encpart: %v", err)
	}
}
