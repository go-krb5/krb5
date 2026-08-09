package crypto

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/go-krb5/krb5/crypto/etype"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/etypeID"
)

// AddEType registers an etype.EType implementation against an encryption type ID, replacing any implementation
// previously registered against that ID. It allows an application to support encryption types this library does not
// implement, or to substitute its own implementation of one that it does.
//
// The encryption type ID 0 is reserved by RFC 3961 and cannot be registered.
//
// The registered value is shared by every caller of GetEType, so implementations must be stateless and safe for
// concurrent use. Registration is safe to perform concurrently with use of the registry, though changing the registry
// while Kerberos exchanges are in flight may cause those exchanges to fail.
func AddEType(id int32, e etype.EType) (err error) {
	if e == nil {
		return errors.New("no EType provided")
	}

	if id == etypeIDReserved {
		return fmt.Errorf("cannot register reserved EType: %d", id)
	}

	muRegistryEType.Lock()
	defer muRegistryEType.Unlock()

	registryEType[id] = e

	return nil
}

// DeleteEType unregisters the encryption type ID so that GetEType no longer resolves it. Deleting an ID that is not
// registered is a no-op. This is the mechanism by which an application restricts itself to a set of encryption types
// it considers acceptable.
func DeleteEType(id int32) {
	muRegistryEType.Lock()
	defer muRegistryEType.Unlock()

	delete(registryEType, id)
}

// ETypeIDs returns the encryption type IDs currently registered, in ascending order.
func ETypeIDs() (ids []int32) {
	muRegistryEType.RLock()
	defer muRegistryEType.RUnlock()

	return sortedKeys(registryEType)
}

// GetEType returns an instances of the required etype struct for the etype ID.
func GetEType(id int32) (e etype.EType, err error) {
	muRegistryEType.RLock()
	defer muRegistryEType.RUnlock()

	var ok bool

	if e, ok = registryEType[id]; !ok {
		return nil, fmt.Errorf("unknown or unsupported EType: %d", id)
	}

	return e, nil
}

// AddChecksumEType registers an etype.EType implementation against a checksum type ID, replacing any implementation
// previously registered against that ID.
//
// The checksum type ID 0 is reserved by RFC 3961 and cannot be registered.
//
// The same concurrency requirements as AddEType apply to the registered value.
func AddChecksumEType(id int32, e etype.EType) (err error) {
	if e == nil {
		return errors.New("no EType provided")
	}

	if id == chksumtypeIDReserved {
		return fmt.Errorf("cannot register reserved checksum type: %d", id)
	}

	muRegistryChecksumEType.Lock()
	defer muRegistryChecksumEType.Unlock()

	registryChecksumEType[id] = e

	return nil
}

// DeleteChecksumEType unregisters the checksum type ID so that GetChecksumEType no longer resolves it. Deleting an ID that
// is not registered is a no-op.
func DeleteChecksumEType(id int32) {
	muRegistryChecksumEType.Lock()
	defer muRegistryChecksumEType.Unlock()

	delete(registryChecksumEType, id)
}

// ChecksumETypeIDs returns the checksum type IDs currently registered, in ascending order.
func ChecksumETypeIDs() (ids []int32) {
	muRegistryChecksumEType.RLock()
	defer muRegistryChecksumEType.RUnlock()

	return sortedKeys(registryChecksumEType)
}

// GetChecksumEType returns an instances of the required etype struct for the checksum ID.
func GetChecksumEType(id int32) (e etype.EType, err error) {
	muRegistryChecksumEType.RLock()
	defer muRegistryChecksumEType.RUnlock()

	var ok bool

	if e, ok = registryChecksumEType[id]; !ok {
		return nil, fmt.Errorf("unknown or unsupported checksum type: %d", id)
	}

	return e, nil
}

// RegisterDeprecatedRC4HMAC registers rc4-hmac and its kerb-checksum-hmac-md5 checksum type, neither of which is
// registered by default. RFC 8429 deprecates rc4-hmac and it should not be used, however some Active Directory
// deployments still require it. Call this during application start up if such a deployment must be supported.
func RegisterDeprecatedRC4HMAC() {
	e := &RC4HMAC{}

	_ = AddEType(etypeID.RC4_HMAC, e)
	_ = AddChecksumEType(chksumtype.KERB_CHECKSUM_HMAC_MD5, e)
}

// RegisterDeprecatedDes3CbcSha1Kd registers des3-cbc-sha1-kd and its hmac-sha1-des3-kd checksum type, neither of which
// is registered by default. RFC 8429 deprecates des3-cbc-sha1-kd and it should not be used. Call this during
// application start up if a realm that still requires it must be supported.
func RegisterDeprecatedDes3CbcSha1Kd() {
	e := &Des3CbcSha1Kd{}

	_ = AddEType(etypeID.DES3_CBC_SHA1_KD, e)
	_ = AddChecksumEType(chksumtype.HMAC_SHA1_DES3_KD, e)
}

func sortedKeys(registry map[int32]etype.EType) (ids []int32) {
	ids = make([]int32, 0, len(registry))

	for id := range registry {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	return ids
}

// Encryption type and checksum type ID 0 is reserved by RFC 3961 and must never resolve to an implementation.
const (
	etypeIDReserved      int32 = 0
	chksumtypeIDReserved int32 = 0
)

var (
	muRegistryEType sync.RWMutex

	// registryEType holds only the encryption types RFC 8429 does not deprecate. des3-cbc-sha1-kd and rc4-hmac are
	// implemented by this library but are not registered by default; see the RegisterDeprecated* helpers.
	registryEType = map[int32]etype.EType{
		etypeID.AES128_CTS_HMAC_SHA1_96:    &Aes128CtsHmacSha96{},
		etypeID.AES256_CTS_HMAC_SHA1_96:    &Aes256CtsHmacSha96{},
		etypeID.AES128_CTS_HMAC_SHA256_128: &Aes128CtsHmacSha256128{},
		etypeID.AES256_CTS_HMAC_SHA384_192: &Aes256CtsHmacSha384192{},
	}

	muRegistryChecksumEType sync.RWMutex

	// registryChecksumEType mirrors registryEType: the checksum types belonging to the deprecated encryption types are
	// not registered by default.
	registryChecksumEType = map[int32]etype.EType{
		chksumtype.HMAC_SHA1_96_AES128:    &Aes128CtsHmacSha96{},
		chksumtype.HMAC_SHA1_96_AES256:    &Aes256CtsHmacSha96{},
		chksumtype.HMAC_SHA256_128_AES128: &Aes128CtsHmacSha256128{},
		chksumtype.HMAC_SHA384_192_AES256: &Aes256CtsHmacSha384192{},
	}
)
