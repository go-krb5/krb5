// Package crypto implements cryptographic functions for Kerberos 5 implementation.
package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/go-krb5/krb5/crypto/etype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/types"
)

// GetKeyFromPassword generates an encryption key from the principal's password.
func GetKeyFromPassword(passwd string, cname types.PrincipalName, realm string, etypeID int32, pas types.PADataSequence) (types.EncryptionKey, etype.EType, error) {
	var key types.EncryptionKey

	et, err := GetEType(etypeID)
	if err != nil {
		return key, et, fmt.Errorf("error getting encryption type: %w", err)
	}

	var (
		salt string
		sk2p string
		paID int32
	)

	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_PW_SALT:
			if paID > pa.PADataType {
				continue
			}

			salt = string(pa.PADataValue)
			paID = pa.PADataType
		case patype.PA_ETYPE_INFO:
			if paID > pa.PADataType {
				continue
			}

			var eti types.ETypeInfo

			if err = eti.Unmarshal(pa.PADataValue); err != nil {
				return key, et, fmt.Errorf("error unmarshaling PA Data to PA-ETYPE-INFO2: %w", err)
			}

			// ETYPE-INFO is a SEQUENCE OF and reaches here from an unauthenticated KRB-ERROR, so an empty one
			// decodes to no entries rather than to an error. The first entry whose encryption type this library
			// supports is taken, rather than the first entry outright.
			i := firstSupported(eti.ETypes())
			if i < 0 {
				continue
			}

			if etypeID != eti[i].EType {
				et, err = GetEType(eti[i].EType)
				if err != nil {
					return key, et, fmt.Errorf("error getting encryption type: %w", err)
				}
			}

			salt = string(eti[i].Salt)
			paID = pa.PADataType
		case patype.PA_ETYPE_INFO2:
			if paID > pa.PADataType {
				continue
			}

			var et2 types.ETypeInfo2

			if err = et2.Unmarshal(pa.PADataValue); err != nil {
				return key, et, fmt.Errorf("error unmarshalling PA Data to PA-ETYPE-INFO2: %w", err)
			}

			i := firstSupported(et2.ETypes())
			if i < 0 {
				continue
			}

			if etypeID != et2[i].EType {
				et, err = GetEType(et2[i].EType)
				if err != nil {
					return key, et, fmt.Errorf("error getting encryption type: %w", err)
				}
			}

			if len(et2[i].S2KParams) == 4 {
				sk2p = hex.EncodeToString(et2[i].S2KParams)
			}

			salt = et2[i].Salt
			paID = pa.PADataType
		}
	}

	if salt == "" {
		salt = cname.GetSalt(realm)
	}

	if sk2p == "" {
		sk2p = et.GetDefaultStringToKeyParams()
	}

	k, err := et.StringToKey(passwd, salt, sk2p)
	if err != nil {
		return key, et, fmt.Errorf("error deriving key from string: %+v", err)
	}

	key = types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: k,
	}

	return key, et, nil
}

// firstSupported returns the index of the first encryption type in ids that is registered, or -1 when none is.
func firstSupported(ids []int32) int {
	for i, id := range ids {
		if _, err := GetEType(id); err == nil {
			return i
		}
	}

	return -1
}

// GetEncryptedData encrypts the data provided and returns and EncryptedData type.
//
// The usage must be one of the key usage numbers RFC 4120 Section 7.5.1 assigns. Zero is not among them, and this
// previously promised to encrypt with the key undivided, which is not a Kerberos operation and was never
// implemented: it produced an empty derived key and an error about the key size.
func GetEncryptedData(plainBytes []byte, key types.EncryptionKey, usage uint32, kvno int) (types.EncryptedData, error) {
	var ed types.EncryptedData

	et, err := GetEType(key.KeyType)
	if err != nil {
		return ed, fmt.Errorf("error getting etype: %w", err)
	}

	_, b, err := et.EncryptMessage(key.KeyValue, plainBytes, usage)
	if err != nil {
		return ed, err
	}

	ed = types.EncryptedData{
		EType:  key.KeyType,
		Cipher: b,
		KVNO:   kvno,
	}

	return ed, nil
}

// DecryptEncPart decrypts the EncryptedData.
func DecryptEncPart(ed types.EncryptedData, key types.EncryptionKey, usage uint32) ([]byte, error) {
	return DecryptMessage(ed.Cipher, key, usage)
}

// DecryptMessage decrypts the ciphertext and verifies the integrity.
func DecryptMessage(ciphertext []byte, key types.EncryptionKey, usage uint32) ([]byte, error) {
	et, err := GetEType(key.KeyType)
	if err != nil {
		return []byte{}, fmt.Errorf("error decrypting: %w", err)
	}

	b, err := et.DecryptMessage(key.KeyValue, ciphertext, usage)
	if err != nil {
		return nil, fmt.Errorf("error decrypting: %w", err)
	}

	return b, nil
}
