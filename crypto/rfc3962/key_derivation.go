package rfc3962

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-crypt/x/pbkdf2"

	"github.com/go-krb5/krb5/crypto/common"
	"github.com/go-krb5/krb5/crypto/etype"
)

const (
	// s2kParamsZeroIterations is the count RFC 3962 Section 4 assigns to a parameter of 00 00 00 00.
	s2kParamsZeroIterations = 1 << 32

	// s2kParamsHexLen is the width of the parameter in hex digits: four octets.
	s2kParamsHexLen = 8
)

// StringToKey returns a key derived from the string provided according to the definition in RFC 3961.
func StringToKey(secret, salt, s2kparams string, e etype.EType) ([]byte, error) {
	i, err := S2KparamsToItertions(s2kparams)
	if err != nil {
		return nil, err
	}

	return StringToKeyIter(secret, salt, i, e)
}

// StringToPBKDF2 generates an encryption key from a pass phrase and salt string using the PBKDF2 function from PKCS #5 v2.0.
func StringToPBKDF2(secret, salt string, iterations int64, e etype.EType) []byte {
	return pbkdf2.KeyExtended([]byte(secret), []byte(salt), iterations, int64(e.GetKeyByteSize()), e.GetHashFunc())
}

// StringToKeyIter returns a key derived from the string provided according to the definition in RFC 3961.
func StringToKeyIter(secret, salt string, iterations int64, e etype.EType) ([]byte, error) {
	tkey := e.RandomToKey(StringToPBKDF2(secret, salt, iterations, e))
	return e.DeriveKey(tkey, []byte("kerberos"))
}

// S2KparamsToItertions converts the string representation of iterations to an integer.
func S2KparamsToItertions(s2kparams string) (int64, error) {
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

	return i, nil
}
