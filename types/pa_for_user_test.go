package types

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // G501: KERB_CHECKSUM_HMAC_MD5 is what MS-SFU pins PA-FOR-USER to.
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
)

const testPAForUserName = "alice"

func testSessionKey(fill byte) EncryptionKey {
	k := EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	for i := range k.KeyValue {
		k.KeyValue[i] = fill + byte(i)
	}

	return k
}

// TestPAForUserChecksumIsTheOneMSSFUDescribes recomputes the checksum from the layout MS-SFU Section 2.2.1 gives,
// written out byte by byte, and the RFC 4757 Section 4 HMAC-MD5 written out step by step, rather than through the
// code under test. A KDC verifies exactly these bytes, so agreeing with the implementation's own helpers would prove
// nothing.
func TestPAForUserChecksumIsTheOneMSSFUDescribes(t *testing.T) {
	t.Parallel()

	key := testSessionKey(7)
	user := PrincipalName{NameType: nametype.KRB_NT_ENTERPRISE, NameString: []string{testPAForUserName, "admin"}}

	p, err := NewPAForUser(user, "EXAMPLE.COM", key)
	require.NoError(t, err)

	data := make([]byte, 0, 33)
	data = append(data, byte(nametype.KRB_NT_ENTERPRISE), 0, 0, 0)
	data = append(data, "aliceadmin"...)
	data = append(data, "EXAMPLE.COM"...)
	data = append(data, "Kerberos"...)

	sign := hmac.New(md5.New, key.KeyValue)
	sign.Write([]byte("signaturekey\x00"))
	ksign := sign.Sum(nil)

	inner := md5.New() //nolint:gosec // G401: see the import.
	inner.Write(binary.LittleEndian.AppendUint32(nil, 17))
	inner.Write(data)

	outer := hmac.New(md5.New, ksign)
	outer.Write(inner.Sum(nil))

	assert.Equal(t, chksumtype.KERB_CHECKSUM_HMAC_MD5, p.Cksum.CksumType)
	assert.Equal(t, outer.Sum(nil), p.Cksum.Checksum)
	assert.Equal(t, "Kerberos", p.AuthPackage)
}

func TestPAForUserRoundTripsAndVerifies(t *testing.T) {
	t.Parallel()

	key := testSessionKey(1)
	user := NewPrincipalName(nametype.KRB_NT_PRINCIPAL, testPAForUserName)

	p, err := NewPAForUser(user, "EXAMPLE.COM", key)
	require.NoError(t, err)

	pa, err := p.PAData()
	require.NoError(t, err)
	assert.Equal(t, patype.PA_FOR_USER, pa.PADataType)

	var got PAForUser
	require.NoError(t, got.Unmarshal(pa.PADataValue))

	assert.True(t, got.UserName.Equal(user))
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, got.UserName.NameType)
	assert.Equal(t, "EXAMPLE.COM", got.UserRealm)
	assert.Equal(t, PAForUserAuthPackage, got.AuthPackage)
	assert.NoError(t, got.Verify(key))
}

// TestPAForUserVerifyRefusesAnotherKeyOrUser covers the two ways a request is forged: signed by something that does
// not hold the TGT session key, and a signed request with the user swapped afterwards.
func TestPAForUserVerifyRefusesAnotherKeyOrUser(t *testing.T) {
	t.Parallel()

	key := testSessionKey(1)

	p, err := NewPAForUser(NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"), "EXAMPLE.COM", key)
	require.NoError(t, err)

	assert.Error(t, p.Verify(testSessionKey(2)))

	swapped := p
	swapped.UserName = NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "mallory")
	assert.Error(t, swapped.Verify(key))

	other := p
	other.Cksum.CksumType = chksumtype.HMAC_SHA1_96_AES256
	assert.Error(t, other.Verify(key))
}

// TestPAForUserStringsAreGeneralStrings pins the DER string type. userRealm and auth-package are KerberosStrings, and
// MIT's decoder refuses anything but a GeneralString there (KRB_ERR_GENERIC, DECODE_PA_FOR_USER), while a lenient
// decoder, this library's included, reads a PrintableString without complaint; so only the bytes catch it.
func TestPAForUserStringsAreGeneralStrings(t *testing.T) {
	t.Parallel()

	p, err := NewPAForUser(NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"), "EXAMPLE.COM", testSessionKey(3))
	require.NoError(t, err)

	b, err := p.Marshal()
	require.NoError(t, err)

	const generalString = 0x1b

	for _, s := range []string{"alice", "EXAMPLE.COM", "Kerberos"} {
		want := append([]byte{generalString, byte(len(s))}, s...) //nolint:gosec // G115: the strings are a few bytes long.
		assert.True(t, bytes.Contains(b, want), "%q is not encoded as a GeneralString in % x", s, b)
	}
}
