// Package rfc3962 provides encryption and checksum methods as specified in RFC 3962.
package rfc3962

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/go-krb5/x/aescts"

	"github.com/go-krb5/krb5/crypto/common"
	"github.com/go-krb5/krb5/crypto/etype"
)

// EncryptData encrypts the data provided using methods specific to the etype provided as defined in RFC 3962.
func EncryptData(key, data []byte, e etype.EType) ([]byte, []byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return []byte{}, []byte{}, fmt.Errorf("incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}

	ivz := make([]byte, e.GetCypherBlockBitLength()/8)

	return aescts.Encrypt(key, ivz, data)
}

// EncryptMessage encrypts the message provided using the methods specific to the etype provided as defined in RFC 3962.
// The encrypted data is concatenated with its integrity hash to create an encrypted message.
func EncryptMessage(key, message []byte, usage uint32, e etype.EType) ([]byte, []byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return []byte{}, []byte{}, fmt.Errorf("incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}

	c := make([]byte, e.GetConfounderByteSize())

	_, err := rand.Read(c)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("could not generate random confounder: %w", err)
	}

	plainBytes := append(c, message...)

	// RFC 4120 Section 7.5.1 assigns no key usage number zero, and decryption derives unconditionally, so a
	// message encrypted without deriving could never be decrypted by this library.
	if usage == 0 {
		return []byte{}, []byte{}, errors.New("key usage 0 is not assigned by RFC 4120 section 7.5.1")
	}

	k, err := e.DeriveKey(key, common.GetUsageKe(usage))
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("error deriving key for encryption: %w", err)
	}

	// Encrypt the data.
	iv, b, err := e.EncryptData(k, plainBytes)
	if err != nil {
		return iv, b, fmt.Errorf("error encrypting data: %w", err)
	}

	// Generate and append integrity hash.
	ih, err := common.GetIntegrityHash(plainBytes, key, usage, e)
	if err != nil {
		return iv, b, fmt.Errorf("error encrypting data: %w", err)
	}

	b = append(b, ih...)

	return iv, b, nil
}

// DecryptData decrypts the data provided using the methods specific to the etype provided as defined in RFC 3962.
func DecryptData(key, data []byte, e etype.EType) ([]byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return []byte{}, fmt.Errorf("incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}

	ivz := make([]byte, e.GetCypherBlockBitLength()/8)

	return aescts.Decrypt(key, ivz, data)
}

// DecryptMessage decrypts the message provided using the methods specific to the etype provided as defined in RFC 3962.
// The integrity of the message is also verified.
func DecryptMessage(key, ciphertext []byte, usage uint32, e etype.EType) ([]byte, error) {
	// An encrypted message is a confounder and the message, encrypted, followed by the integrity hash. Anything
	// shorter than a confounder plus a hash cannot be one, and slicing the hash off it would index out of range.
	// The length is chosen by whoever encoded the message: the EncryptedData of a ticket, or of the KRB_CRED a peer
	// delegates, arrives with whatever Cipher the peer sent, so this has to be a returned error rather than a panic.
	if min := e.GetConfounderByteSize() + e.GetHMACBitLength()/8; len(ciphertext) < min {
		return nil, fmt.Errorf("ciphertext is too short to be an encrypted message: %d bytes, need at least %d", len(ciphertext), min)
	}

	// Derive the key.
	k, err := e.DeriveKey(key, common.GetUsageKe(usage))
	if err != nil {
		return nil, fmt.Errorf("error deriving key: %w", err)
	}
	// Strip off the checksum from the end.
	b, err := e.DecryptData(k, ciphertext[:len(ciphertext)-e.GetHMACBitLength()/8])
	if err != nil {
		return nil, err
	}
	// Verify checksum.
	if !e.VerifyIntegrity(key, ciphertext, b, usage) {
		return nil, errors.New("integrity verification failed")
	}
	// Remove the confounder bytes.
	return b[e.GetConfounderByteSize():], nil
}
