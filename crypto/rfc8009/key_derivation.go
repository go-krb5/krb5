package rfc8009

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"

	"github.com/go-krb5/krb5/crypto/common"
	"github.com/go-krb5/krb5/crypto/etype"
)

const (
	defaultIterations       = 32768
	s2kParamsZeroIterations = 1 << 32
	s2kParamsHexLen         = 8
	kerberosLabel           = "kerberos"
	labelSuffixKe           = 0xAA
	prfLabel                = "prf"
)

// DeriveRandom for key derivation as defined in RFC 8009.
func DeriveRandom(protocolKey, usage []byte, e etype.EType) ([]byte, error) {
	h := e.GetHashFunc()()
	return KDF_HMAC_SHA2(protocolKey, []byte(prfLabel), usage, h.Size()*8, e), nil
}

// DeriveKey derives a key from the protocol key based on the usage and the etype's specific methods.
//
// https://tools.ietf.org/html/rfc8009#section-5
func DeriveKey(protocolKey, label []byte, e etype.EType) []byte {
	kl := e.GetHMACBitLength()
	if isKeyLengthLabel(label) {
		kl = e.GetKeySeedBitLength()
	}

	return e.RandomToKey(KDF_HMAC_SHA2(protocolKey, label, nil, kl, e))
}

// isKeyLengthLabel reports whether the label selects a key derived at the encryption key length rather than at the
// truncated HMAC length: the encryption key Ke of RFC 8009 Section 5, whose label ends in 0xAA, or the base key of
// Section 4, whose label is "kerberos".
func isKeyLengthLabel(label []byte) bool {
	if bytes.Equal(label, []byte(kerberosLabel)) {
		return true
	}

	return len(label) > 0 && label[len(label)-1] == labelSuffixKe
}

// RandomToKey returns a key from the bytes provided according to the definition in RFC 8009.
func RandomToKey(b []byte) []byte {
	return b
}

// StringToKey returns a key derived from the string provided according to the definition in RFC 8009.
func StringToKey(secret, salt, s2kparams string, e etype.EType) ([]byte, error) {
	i, err := S2KparamsToItertions(s2kparams)
	if err != nil {
		return nil, err
	}

	return StringToKeyIter(secret, salt, i, e)
}

// StringToKeyIter returns a key derived from the string provided according to the definition in RFC 8009.
func StringToKeyIter(secret, salt string, iterations int, e etype.EType) ([]byte, error) {
	tkey := e.RandomToKey(StringToPBKDF2(secret, salt, iterations, e))
	return e.DeriveKey(tkey, []byte("kerberos"))
}

// StringToPBKDF2 generates an encryption key from a pass phrase and salt string using the PBKDF2 function from PKCS #5 v2.0.
func StringToPBKDF2(secret, salt string, iterations int, e etype.EType) []byte {
	return pbkdf2.Key([]byte(secret), []byte(salt), iterations, e.GetKeyByteSize(), e.GetHashFunc())
}

// KDF_HMAC_SHA2 key derivation: https://tools.ietf.org/html/rfc8009#section-3
func KDF_HMAC_SHA2(protocolKey, label, context []byte, kl int, e etype.EType) []byte {
	//k: Length in bits of the key to be outputted, expressed in big-endian binary representation in 4 bytes.
	k := make([]byte, 4)
	binary.BigEndian.PutUint32(k, uint32(kl))

	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, uint32(1))
	c = append(c, label...)

	c = append(c, byte(0))
	if len(context) > 0 {
		c = append(c, context...)
	}

	c = append(c, k...)

	mac := hmac.New(e.GetHashFunc(), protocolKey)
	mac.Write(c)

	return mac.Sum(nil)[:(kl / 8)]
}

// GetSaltP returns the salt value based on the etype name: https://tools.ietf.org/html/rfc8009#section-4
func GetSaltP(salt, ename string) string {
	b := []byte(ename)
	b = append(b, byte(0))
	b = append(b, []byte(salt)...)

	return string(b)
}

// S2KparamsToItertions converts the string representation of iterations to an integer for RFC 8009.
func S2KparamsToItertions(s2kparams string) (int, error) {
	if len(s2kparams) != s2kParamsHexLen {
		return 0, errors.New("invalid s2kparams length")
	}

	b, err := hex.DecodeString(s2kparams)
	if err != nil {
		return 0, errors.New("invalid s2kparams, cannot decode string to bytes")
	}

	i := int64(binary.BigEndian.Uint32(b))
	if i == 0 {
		i = s2kParamsZeroIterations
	}

	if i > common.MaxS2KIterations {
		return 0, fmt.Errorf("s2kparams requests %d iterations, which exceeds the maximum of %d",
			i, common.MaxS2KIterations)
	}

	return int(i), nil
}
