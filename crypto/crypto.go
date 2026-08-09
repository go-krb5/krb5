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

	sk2p := et.GetDefaultStringToKeyParams()

	var (
		salt string
		paID int32
	)

	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_PW_SALT:
			if paID > pa.PADataType {
				continue
			}

			salt = string(pa.PADataValue)
		case patype.PA_ETYPE_INFO:
			if paID > pa.PADataType {
				continue
			}

			var eti types.ETypeInfo

			err := eti.Unmarshal(pa.PADataValue)
			if err != nil {
				return key, et, fmt.Errorf("error unmashaling PA Data to PA-ETYPE-INFO2: %w", err)
			}

			if etypeID != eti[0].EType {
				et, err = GetEType(eti[0].EType)
				if err != nil {
					return key, et, fmt.Errorf("error getting encryption type: %w", err)
				}
			}

			salt = string(eti[0].Salt)
		case patype.PA_ETYPE_INFO2:
			if paID > pa.PADataType {
				continue
			}

			var et2 types.ETypeInfo2

			err := et2.Unmarshal(pa.PADataValue)
			if err != nil {
				return key, et, fmt.Errorf("error unmashalling PA Data to PA-ETYPE-INFO2: %w", err)
			}

			if etypeID != et2[0].EType {
				et, err = GetEType(et2[0].EType)
				if err != nil {
					return key, et, fmt.Errorf("error getting encryption type: %w", err)
				}
			}

			if len(et2[0].S2KParams) == 4 {
				sk2p = hex.EncodeToString(et2[0].S2KParams)
			}

			salt = et2[0].Salt
		}
	}

	if salt == "" {
		salt = cname.GetSalt(realm)
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

// GetEncryptedData encrypts the data provided and returns and EncryptedData type.
// Pass a usage value of zero to use the key provided directly rather than deriving one.
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
