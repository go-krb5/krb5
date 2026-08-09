package crypto

import (
	"maps"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/crypto/etype"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/types"
)

// etypeIDCustom is an ID from the unassigned range, used to prove an application can register an implementation of an
// encryption type this library does not know about.
const etypeIDCustom int32 = 4096

func TestGetETypeShouldResolveDefaults(t *testing.T) {
	restoreRegistries(t)

	testCases := []struct {
		name string
		id   int32
		want etype.EType
	}{
		{"AES128_CTS_HMAC_SHA1_96", etypeID.AES128_CTS_HMAC_SHA1_96, &Aes128CtsHmacSha96{}},
		{"AES256_CTS_HMAC_SHA1_96", etypeID.AES256_CTS_HMAC_SHA1_96, &Aes256CtsHmacSha96{}},
		{"AES128_CTS_HMAC_SHA256_128", etypeID.AES128_CTS_HMAC_SHA256_128, &Aes128CtsHmacSha256128{}},
		{"AES256_CTS_HMAC_SHA384_192", etypeID.AES256_CTS_HMAC_SHA384_192, &Aes256CtsHmacSha384192{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := GetEType(tc.id)
			require.NoError(t, err)
			assert.IsType(t, tc.want, e)
			assert.Equal(t, tc.id, e.GetETypeID())
		})
	}

	assert.Equal(t, []int32{
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA256_128,
		etypeID.AES256_CTS_HMAC_SHA384_192,
	}, ETypeIDs())
}

// TestGetETypeShouldNotResolveDeprecatedByDefault asserts RFC 8429 deprecated encryption types are implemented but not
// enabled, and that opting back in works.
func TestGetETypeShouldNotResolveDeprecatedByDefault(t *testing.T) {
	restoreRegistries(t)

	for _, tc := range []struct {
		name       string
		id         int32
		chksum     int32
		register   func()
		wantEType  etype.EType
		wantChksum etype.EType
	}{
		{"RC4_HMAC", etypeID.RC4_HMAC, chksumtype.KERB_CHECKSUM_HMAC_MD5, RegisterDeprecatedRC4HMAC, &RC4HMAC{}, &RC4HMAC{}},
		{"DES3_CBC_SHA1_KD", etypeID.DES3_CBC_SHA1_KD, chksumtype.HMAC_SHA1_DES3_KD, RegisterDeprecatedDes3CbcSha1Kd, &Des3CbcSha1Kd{}, &Des3CbcSha1Kd{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restoreRegistries(t)

			_, err := GetEType(tc.id)
			assert.EqualError(t, err, "unknown or unsupported EType: "+itoa(tc.id))

			_, err = GetChecksumEType(tc.chksum)
			assert.EqualError(t, err, "unknown or unsupported checksum type: "+itoa(tc.chksum))

			tc.register()

			e, err := GetEType(tc.id)
			require.NoError(t, err)
			assert.IsType(t, tc.wantEType, e)

			c, err := GetChecksumEType(tc.chksum)
			require.NoError(t, err)
			assert.IsType(t, tc.wantChksum, c)
		})
	}
}

func TestGetChecksumETypeShouldResolveDefaults(t *testing.T) {
	restoreRegistries(t)

	testCases := []struct {
		name string
		id   int32
		want etype.EType
	}{
		{"HMAC_SHA1_96_AES128", chksumtype.HMAC_SHA1_96_AES128, &Aes128CtsHmacSha96{}},
		{"HMAC_SHA1_96_AES256", chksumtype.HMAC_SHA1_96_AES256, &Aes256CtsHmacSha96{}},
		{"HMAC_SHA256_128_AES128", chksumtype.HMAC_SHA256_128_AES128, &Aes128CtsHmacSha256128{}},
		{"HMAC_SHA384_192_AES256", chksumtype.HMAC_SHA384_192_AES256, &Aes256CtsHmacSha384192{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := GetChecksumEType(tc.id)
			require.NoError(t, err)
			assert.IsType(t, tc.want, e)
		})
	}

	assert.Equal(t, []int32{
		chksumtype.HMAC_SHA1_96_AES128,
		chksumtype.HMAC_SHA1_96_AES256,
		chksumtype.HMAC_SHA256_128_AES128,
		chksumtype.HMAC_SHA384_192_AES256,
	}, ChecksumETypeIDs())
}

func TestAddEType(t *testing.T) {
	t.Run("ShouldRejectNil", func(t *testing.T) {
		restoreRegistries(t)

		assert.EqualError(t, AddEType(etypeIDCustom, nil), "no EType provided")
		assert.NotContains(t, ETypeIDs(), etypeIDCustom)
	})

	t.Run("ShouldRejectReservedID", func(t *testing.T) {
		restoreRegistries(t)

		assert.EqualError(t, AddEType(0, &Aes256CtsHmacSha96{}), "cannot register reserved EType: 0")

		_, err := GetEType(0)
		assert.EqualError(t, err, "unknown or unsupported EType: 0")
	})

	t.Run("ShouldRegisterUnassignedID", func(t *testing.T) {
		restoreRegistries(t)

		require.NoError(t, AddEType(etypeIDCustom, &Aes256CtsHmacSha96{}))

		e, err := GetEType(etypeIDCustom)
		require.NoError(t, err)
		assert.IsType(t, &Aes256CtsHmacSha96{}, e)
		assert.Contains(t, ETypeIDs(), etypeIDCustom)
	})

	t.Run("ShouldReplaceExistingID", func(t *testing.T) {
		restoreRegistries(t)

		require.NoError(t, AddEType(etypeID.AES256_CTS_HMAC_SHA1_96, &Aes128CtsHmacSha96{}))

		e, err := GetEType(etypeID.AES256_CTS_HMAC_SHA1_96)
		require.NoError(t, err)
		assert.IsType(t, &Aes128CtsHmacSha96{}, e)
		assert.Len(t, ETypeIDs(), 4)
	})
}

func TestAddChecksumEType(t *testing.T) {
	t.Run("ShouldRejectNil", func(t *testing.T) {
		restoreRegistries(t)

		assert.EqualError(t, AddChecksumEType(etypeIDCustom, nil), "no EType provided")
		assert.NotContains(t, ChecksumETypeIDs(), etypeIDCustom)
	})

	t.Run("ShouldRejectReservedID", func(t *testing.T) {
		restoreRegistries(t)

		assert.EqualError(t, AddChecksumEType(0, &Aes256CtsHmacSha96{}), "cannot register reserved checksum type: 0")

		_, err := GetChecksumEType(0)
		assert.EqualError(t, err, "unknown or unsupported checksum type: 0")
	})

	// Checksum type IDs are not constrained to positive values: kerb-checksum-hmac-md5 is -138.
	t.Run("ShouldRegisterNegativeID", func(t *testing.T) {
		restoreRegistries(t)

		require.NoError(t, AddChecksumEType(chksumtype.KERB_CHECKSUM_HMAC_MD5, &RC4HMAC{}))

		e, err := GetChecksumEType(chksumtype.KERB_CHECKSUM_HMAC_MD5)
		require.NoError(t, err)
		assert.IsType(t, &RC4HMAC{}, e)
	})
}

func TestDeleteEType(t *testing.T) {
	t.Run("ShouldUnregister", func(t *testing.T) {
		restoreRegistries(t)

		DeleteEType(etypeID.AES128_CTS_HMAC_SHA1_96)

		_, err := GetEType(etypeID.AES128_CTS_HMAC_SHA1_96)
		assert.EqualError(t, err, "unknown or unsupported EType: 17")
		assert.NotContains(t, ETypeIDs(), etypeID.AES128_CTS_HMAC_SHA1_96)

		// Unrelated encryption types are unaffected.
		_, err = GetEType(etypeID.AES256_CTS_HMAC_SHA1_96)
		require.NoError(t, err)
	})

	t.Run("ShouldIgnoreUnregistered", func(t *testing.T) {
		restoreRegistries(t)

		DeleteEType(etypeIDCustom)
		assert.Len(t, ETypeIDs(), 4)
	})
}

func TestDeleteChecksumEType(t *testing.T) {
	t.Run("ShouldUnregister", func(t *testing.T) {
		restoreRegistries(t)

		DeleteChecksumEType(chksumtype.HMAC_SHA1_96_AES128)

		_, err := GetChecksumEType(chksumtype.HMAC_SHA1_96_AES128)
		assert.EqualError(t, err, "unknown or unsupported checksum type: 15")
		assert.NotContains(t, ChecksumETypeIDs(), chksumtype.HMAC_SHA1_96_AES128)
	})

	t.Run("ShouldIgnoreUnregistered", func(t *testing.T) {
		restoreRegistries(t)

		DeleteChecksumEType(etypeIDCustom)
		assert.Len(t, ChecksumETypeIDs(), 4)
	})
}

// TestUnregisteredETypeShouldFailClearly asserts the callers of the registry surface an actionable error rather than
// panicking or silently falling back to another encryption type, which is the point of being able to unregister one.
func TestUnregisteredETypeShouldFailClearly(t *testing.T) {
	restoreRegistries(t)

	DeleteEType(etypeID.AES256_CTS_HMAC_SHA1_96)

	key := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: make([]byte, 32),
	}

	t.Run("GetKeyFromPassword", func(t *testing.T) {
		_, _, err := GetKeyFromPassword("password", types.PrincipalName{NameString: []string{"user"}}, "EXAMPLE.ORG", key.KeyType, types.PADataSequence{})
		assert.EqualError(t, err, "error getting encryption type: unknown or unsupported EType: 18")
	})

	t.Run("GetEncryptedData", func(t *testing.T) {
		_, err := GetEncryptedData([]byte("secret"), key, 1, 1)
		assert.EqualError(t, err, "error getting etype: unknown or unsupported EType: 18")
	})

	t.Run("DecryptMessage", func(t *testing.T) {
		_, err := DecryptMessage([]byte("ciphertext"), key, 1)
		assert.EqualError(t, err, "error decrypting: unknown or unsupported EType: 18")
	})
}

// TestRegistryShouldBeConcurrencySafe is meaningful under -race: mutating a registry while it is being read must not
// trip the runtime's concurrent map access detection.
func TestRegistryShouldBeConcurrencySafe(t *testing.T) {
	restoreRegistries(t)

	var wg sync.WaitGroup

	for range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for range 100 {
				_, _ = GetEType(etypeID.AES256_CTS_HMAC_SHA1_96)
				_, _ = GetChecksumEType(chksumtype.HMAC_SHA1_96_AES256)
				_ = ETypeIDs()
				_ = ChecksumETypeIDs()
			}
		}()
	}

	for range 4 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for range 100 {
				_ = AddEType(etypeIDCustom, &Aes256CtsHmacSha96{})
				_ = AddChecksumEType(etypeIDCustom, &Aes256CtsHmacSha96{})
				DeleteEType(etypeIDCustom)
				DeleteChecksumEType(etypeIDCustom)
			}
		}()
	}

	wg.Wait()
}

// restoreRegistries takes a copy of both registries and restores them when the test finishes, so a test that mutates
// the process wide registry cannot affect any other.
func restoreRegistries(t *testing.T) {
	t.Helper()

	var etypes, chksums map[int32]etype.EType

	muRegistryEType.RLock()

	etypes = maps.Clone(registryEType)

	muRegistryEType.RUnlock()

	muRegistryChecksumEType.RLock()

	chksums = maps.Clone(registryChecksumEType)

	muRegistryChecksumEType.RUnlock()

	t.Cleanup(func() {
		muRegistryEType.Lock()
		registryEType = etypes
		muRegistryEType.Unlock()

		muRegistryChecksumEType.Lock()
		registryChecksumEType = chksums
		muRegistryChecksumEType.Unlock()
	})
}

func itoa(id int32) string {
	return strconv.FormatInt(int64(id), 10)
}
