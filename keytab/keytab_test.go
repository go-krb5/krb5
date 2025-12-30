package keytab

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestUnmarshal(t *testing.T) {
	t.Parallel()

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := New()

	require.NoError(t, kt.Unmarshal(b))

	assert.Equal(t, uint8(2), kt.version)
	assert.Equal(t, uint32(1), kt.Entries[0].KVNO)
	assert.Equal(t, uint8(1), kt.Entries[0].KVNO8)
	assert.Equal(t, time.Unix(1505669592, 0), kt.Entries[0].Timestamp)
	assert.Equal(t, int32(17), kt.Entries[0].Key.KeyType)
	assert.Equal(t, "698c4df8e9f60e7eea5a21bf4526ad25", hex.EncodeToString(kt.Entries[0].Key.KeyValue))
	assert.Equal(t, int16(1), kt.Entries[0].Principal.NumComponents)
	assert.Equal(t, int32(1), kt.Entries[0].Principal.NameType)
	assert.Equal(t, "TEST.GOKRB5", kt.Entries[0].Principal.Realm)
	assert.Equal(t, "testuser1", kt.Entries[0].Principal.Components[0])
}

func TestMarshal(t *testing.T) {
	t.Parallel()

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := New()

	require.NoError(t, kt.Unmarshal(b))

	mb, err := kt.Marshal()
	require.NoError(t, err)

	assert.Equal(t, b, mb)

	require.NoError(t, kt.Unmarshal(mb))
}

func TestLoad(t *testing.T) {
	t.Parallel()

	f := "test/testdata/testuser1.testtab"
	cwd, _ := os.Getwd()

	dir := os.Getenv("TRAVIS_BUILD_DIR")
	if dir != "" {
		f = dir + "/" + f
	} else if filepath.Base(cwd) == "keytab" {
		f = "../" + f
	}

	kt, err := Load(f)
	require.NoError(t, err)

	assert.Equal(t, uint8(2), kt.version)
	assert.Equal(t, 12, len(kt.Entries), "keytab entry count not as expected: %+v", *kt)

	for _, e := range kt.Entries {
		if e.Principal.Realm != "TEST.GOKRB5" {
			t.Error("principal realm not as expected")
		}

		if e.Principal.NameType != int32(1) {
			t.Error("name type not as expected")
		}

		if e.Principal.NumComponents != int16(1) {
			t.Error("number of component not as expected")
		}

		if len(e.Principal.Components) != 1 {
			t.Error("number of component not as expected")
		}

		if e.Principal.Components[0] != "testuser1" {
			t.Error("principal components not as expected")
		}

		if e.Timestamp.IsZero() {
			t.Error("entry timestamp incorrect")
		}

		if e.KVNO == uint32(0) {
			t.Error("entry kvno not as expected")
		}

		if e.KVNO8 == uint8(0) {
			t.Error("entry kvno8 not as expected")
		}
	}
}

// This test provides inputs to readBytes that previously
// caused a panic.
func TestReadBytes(t *testing.T) {
	var endian binary.ByteOrder = binary.BigEndian

	p := 0

	var err error

	_, err = readBytes(nil, &p, 1, &endian)
	assert.EqualError(t, err, "'s length is greater than 1")

	_, err = readBytes(nil, &p, -1, &endian)
	assert.EqualError(t, err, "-1 cannot be less than zero")
}

func TestUnmarshalPotentialPanics(t *testing.T) {
	kt := New()

	assert.EqualError(t, kt.Unmarshal(nil), "byte array is less than 2 bytes: 0")
	assert.EqualError(t, kt.Unmarshal([]byte{}), "byte array is less than 2 bytes: 0")
	assert.EqualError(t, kt.Unmarshal([]byte{4}), "byte array is less than 2 bytes: 1")
	assert.EqualError(t, kt.Unmarshal([]byte{5}), "byte array is less than 2 bytes: 1")
}

// cxf testing stuff.
func TestBadKeytabs(t *testing.T) {
	badPayloads := make([]string, 0, 2)
	badPayloads = append(badPayloads, "BQIwMDAwMDA=")
	badPayloads = append(badPayloads, "BQIAAAAwAAEACjAwMDAwMDAwMDAAIDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw")

	for i, v := range badPayloads {
		decodedKt, _ := base64.StdEncoding.DecodeString(v)
		parsedKt := new(Keytab)
		// TODO: Check actual error returns here.
		assert.Error(t, parsedKt.Unmarshal(decodedKt), "invalid keytab %d", i)
	}

	// TODO: investigate why this doesn't error when it was in the list.
	decodedKt, _ := base64.StdEncoding.DecodeString("BQKAAAAA")
	parsedKt := new(Keytab)
	assert.NoError(t, parsedKt.Unmarshal(decodedKt))
}

func TestKeytabEntriesUser(t *testing.T) {
	ktutilb64 := "BQIAAABGAAEAC0VYQU1QTEUuT1JHAAR1c2VyAAAAAV5ePQAfABIAIG6I6ys5Me8XyS54Ck7kIfFBH/WxBOP3W1DdE/ntBPnGAAAAHwAAADYAAQALRVhBTVBMRS5PUkcABHVzZXIAAAABXl49AB8AEQAQm7fVug9VRBJVhEGjHyN3EgAAAB8AAAA2AAEAC0VYQU1QTEUuT1JHAAR1c2VyAAAAAV5ePQAfABcAEBENDFHhRNNvt+T54BL7uIgAAAAf"

	ktutilbytes, err := base64.StdEncoding.DecodeString(ktutilb64)
	require.NoError(t, err)

	ktutil := new(Keytab)

	require.NoError(t, ktutil.Unmarshal(ktutilbytes))

	var (
		ts       = ktutil.Entries[0].Timestamp
		encTypes = []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC}
	)

	kt := New()

	for _, et := range encTypes {
		require.NoError(t, kt.AddEntry("user", "EXAMPLE.ORG", "hello123", ts, uint8(31), et))
	}

	generated, err := kt.Marshal()
	require.NoError(t, err)

	assert.Equal(t, generated, ktutilbytes)
}

func TestKeytabEntriesService(t *testing.T) {
	ktutilb64 := "BQIAAABXAAIAC0VYQU1QTEUuT1JHAARIVFRQAA93d3cuZXhhbXBsZS5vcmcAAAABXl49ggoAEgAgOCSpM5CdiZQn1+rUtLtt6sTrg5Saw1DXJMai7vDWJ0QAAAAKAAAARwACAAtFWEFNUExFLk9SRwAESFRUUAAPd3d3LmV4YW1wbGUub3JnAAAAAV5ePYIKABEAEDpczoDyER1jscz0RWkThCMAAAAKAAAARwACAAtFWEFNUExFLk9SRwAESFRUUAAPd3d3LmV4YW1wbGUub3JnAAAAAV5ePYIKABcAELP27YfH0Th5rD+GtJkQmXQAAAAK"

	ktutilbytes, err := base64.StdEncoding.DecodeString(ktutilb64)
	require.NoError(t, err)

	ktutil := new(Keytab)

	require.NoError(t, ktutil.Unmarshal(ktutilbytes))

	var (
		ts       = ktutil.Entries[0].Timestamp
		encTypes = []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC}
	)

	kt := New()

	for _, et := range encTypes {
		require.NoError(t, kt.AddEntry("HTTP/www.example.org", "EXAMPLE.ORG", "hello456", ts, uint8(10), et))
	}

	generated, err := kt.Marshal()
	require.NoError(t, err)

	assert.Equal(t, generated, ktutilbytes)
}

func TestKeytab_GetEncryptionKey(t *testing.T) {
	princ := "HTTP/princ.test.gokrb5"
	realm := "TEST.GOKRB5"

	kt := New()
	require.NoError(t, kt.AddEntry(princ, realm, "abcdefg", time.Unix(100, 0), 1, 18))
	require.NoError(t, kt.AddEntry(princ, realm, "abcdefg", time.Unix(200, 0), 2, 18))
	require.NoError(t, kt.AddEntry(princ, realm, "abcdefg", time.Unix(300, 0), 3, 18))
	require.NoError(t, kt.AddEntry(princ, realm, "abcdefg", time.Unix(400, 0), 4, 18))
	require.NoError(t, kt.AddEntry(princ, realm, "abcdefg", time.Unix(350, 0), 5, 18))
	require.NoError(t, kt.AddEntry("HTTP/other.test.gokrb5", realm, "abcdefg", time.Unix(500, 0), 5, 18))

	pn := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, princ)

	_, kvno, err := kt.GetEncryptionKey(pn, realm, 0, 18)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, 4, kvno)

	_, kvno, err = kt.GetEncryptionKey(pn, realm, 3, 18)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, 3, kvno)
}
