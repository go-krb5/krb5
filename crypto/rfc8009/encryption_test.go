package rfc8009_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/crypto/common"
	"github.com/go-krb5/krb5/crypto/rfc8009"
)

func TestStringToKey(t *testing.T) {
	t.Parallel()
	r, _ := hex.DecodeString("10DF9DD783E5BC8ACEA1730E74355F61")
	randomSalt := string(r)

	var tests = []struct {
		name       string
		iterations uint32
		passphrase string
		salt       string
		saltp128   string
		baseKey128 string
		saltp256   string
		baseKey256 string
	}{
		{
			name:       "RFC 8009 Appendix A - AES128",
			iterations: 32768,
			passphrase: "password",
			salt:       randomSalt + "ATHENA.MIT.EDUraeburn",
			saltp128:   "6165733132382d6374732d686d61632d7368613235362d3132380010df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e",
			baseKey128: "089bca48b105ea6ea77ca5d2f39dc5e7",
			saltp256:   "6165733235362d6374732d686d61632d7368613338342d3139320010df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e",
			baseKey256: "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467",
		},
	}

	for _, test := range tests {
		var e crypto.Aes128CtsHmacSha256128
		t.Run("AES128", func(t *testing.T) {
			t.Run(test.name, func(t *testing.T) {
				saltp := rfc8009.GetSaltP(test.salt, "aes128-cts-hmac-sha256-128")
				assert.Equal(t, test.saltp128, hex.EncodeToString([]byte(saltp)), "SaltP not as expected")

				k, err := e.StringToKey(test.passphrase, test.salt, common.IterationsToS2Kparams(test.iterations))
				if err != nil {
					t.Fatalf("StringToKey failed: %v", err)
				}
				assert.Equal(t, test.baseKey128, hex.EncodeToString(k), "Base key not as expected")
			})
		})
	}

	for _, test := range tests {
		var e crypto.Aes256CtsHmacSha384192
		t.Run("AES256", func(t *testing.T) {
			t.Run(test.name, func(t *testing.T) {
				saltp := rfc8009.GetSaltP(test.salt, "aes256-cts-hmac-sha384-192")
				assert.Equal(t, test.saltp256, hex.EncodeToString([]byte(saltp)), "SaltP not as expected")

				k, err := e.StringToKey(test.passphrase, test.salt, common.IterationsToS2Kparams(test.iterations))
				if err != nil {
					t.Fatalf("StringToKey failed: %v", err)
				}
				assert.Equal(t, test.baseKey256, hex.EncodeToString(k), "Base key not as expected")
			})
		})
	}
}

func TestDeriveKey(t *testing.T) {
	t.Parallel()
	protocolBaseKey128, _ := hex.DecodeString("3705d96080c17728a0e800eab6e0d23c")
	protocolBaseKey256, _ := hex.DecodeString("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52")
	testUsage := uint32(2)

	var tests = []struct {
		name        string
		keyType     string // "Kc", "Ke", or "Ki"
		expected128 string
		expected256 string
	}{
		{
			name:        "Kc derivation for usage 2",
			keyType:     "Kc",
			expected128: "b31a018a48f54776f403e9a396325dc3",
			expected256: "ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d",
		},
		{
			name:        "Ke derivation for usage 2",
			keyType:     "Ke",
			expected128: "9b197dd1e8c5609d6e67c3e37c62c72e",
			expected256: "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
		},
		{
			name:        "Ki derivation for usage 2",
			keyType:     "Ki",
			expected128: "9fda0e56ab2d85e1569a688696c26a6c",
			expected256: "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f",
		},
	}

	for _, test := range tests {
		var e crypto.Aes128CtsHmacSha256128
		t.Run("AES128", func(t *testing.T) {
			t.Run(test.name, func(t *testing.T) {
				var k []byte
				var err error

				switch test.keyType {
				case "Kc":
					k, err = e.DeriveKey(protocolBaseKey128, common.GetUsageKc(testUsage))
				case "Ke":
					k, err = e.DeriveKey(protocolBaseKey128, common.GetUsageKe(testUsage))
				case "Ki":
					k, err = e.DeriveKey(protocolBaseKey128, common.GetUsageKi(testUsage))
				}

				if err != nil {
					t.Fatalf("Error deriving %s key: %v", test.keyType, err)
				}
				assert.Equal(t, test.expected128, hex.EncodeToString(k), "%s derived key not as expected", test.keyType)
			})
		})
	}

	for _, test := range tests {
		var e crypto.Aes256CtsHmacSha384192
		t.Run("AES256", func(t *testing.T) {
			t.Run(test.name, func(t *testing.T) {
				var k []byte
				var err error

				switch test.keyType {
				case "Kc":
					k, err = e.DeriveKey(protocolBaseKey256, common.GetUsageKc(testUsage))
				case "Ke":
					k, err = e.DeriveKey(protocolBaseKey256, common.GetUsageKe(testUsage))
				case "Ki":
					k, err = e.DeriveKey(protocolBaseKey256, common.GetUsageKi(testUsage))
				}

				if err != nil {
					t.Fatalf("Error deriving %s key: %v", test.keyType, err)
				}
				assert.Equal(t, test.expected256, hex.EncodeToString(k), "%s derived key not as expected", test.keyType)
			})
		})
	}
}

func TestEncryptDecrypt_AES128(t *testing.T) {
	t.Parallel()
	//RFC 8009 input-key value/HMAC-SHA256 key. Page 18
	protocolBaseKey, _ := hex.DecodeString("3705d96080c17728a0e800eab6e0d23c")
	testUsage := uint32(2)

	var tests = []struct {
		name       string
		plaintext  string
		confounder string
		ke         string
		ki         string
		aesOutput  string
		hmacOutput string
		ciphertext string
	}{
		{
			name:       "Empty plaintext",
			plaintext:  "",
			confounder: "7e5895eaf2672435bad817f545a37148",
			ke:         "9b197dd1e8c5609d6e67c3e37c62c72e",
			ki:         "9fda0e56ab2d85e1569a688696c26a6c",
			aesOutput:  "ef85fb890bb8472f4dab20394dca781d",
			hmacOutput: "ad877eda39d50c870c0d5a0a8e48c718",
			ciphertext: "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718",
		},
		{
			name:       "Length less than block size",
			plaintext:  "000102030405",
			confounder: "7bca285e2fd4130fb55b1a5c83bc5b24",
			ke:         "9b197dd1e8c5609d6e67c3e37c62c72e",
			ki:         "9fda0e56ab2d85e1569a688696c26a6c",
			aesOutput:  "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6",
			hmacOutput: "877ce99e247e52d16ed4421dfdf8976c",
			ciphertext: "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877ce99e247e52d16ed4421dfdf8976c",
		},
		{
			name:       "Length equals block size",
			plaintext:  "000102030405060708090a0b0c0d0e0f",
			confounder: "56ab21713ff62c0a1457200f6fa9948f",
			ke:         "9b197dd1e8c5609d6e67c3e37c62c72e",
			ki:         "9fda0e56ab2d85e1569a688696c26a6c",
			aesOutput:  "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc2",
			hmacOutput: "95fb4852e7d83e1e7c48c37eebe6b0d3",
			ciphertext: "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc295fb4852e7d83e1e7c48c37eebe6b0d3",
		},
		{
			name:       "Length greater than block size",
			plaintext:  "000102030405060708090a0b0c0d0e0f1011121314",
			confounder: "a7a4e29a4728ce10664fb64e49ad3fac",
			ke:         "9b197dd1e8c5609d6e67c3e37c62c72e",
			ki:         "9fda0e56ab2d85e1569a688696c26a6c",
			aesOutput:  "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c1",
			hmacOutput: "86b39a413c2f92ca9b8334a287ffcbfc",
			ciphertext: "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c186b39a413c2f92ca9b8334a287ffcbfc",
		},
	}

	var e crypto.Aes128CtsHmacSha256128
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plaintext, _ := hex.DecodeString(test.plaintext)
			confounder, _ := hex.DecodeString(test.confounder)
			ke, _ := hex.DecodeString(test.ke)
			aesOutput, _ := hex.DecodeString(test.aesOutput)
			ciphertext, _ := hex.DecodeString(test.ciphertext)

			confPlaintext := append(confounder, plaintext...)
			_, encryptedData, err := e.EncryptData(ke, confPlaintext)
			if err != nil {
				t.Fatalf("EncryptData failed: %v", err)
			}
			assert.Equal(t, test.aesOutput, hex.EncodeToString(encryptedData), "AES output not as expected")

			decryptedData, err := e.DecryptData(ke, aesOutput)
			if err != nil {
				t.Fatalf("DecryptData failed: %v", err)
			}

			decryptedPlaintext := decryptedData[e.GetConfounderByteSize():]
			assert.Equal(t, test.plaintext, hex.EncodeToString(decryptedPlaintext), "Decrypted plaintext not as expected")

			assert.True(t, e.VerifyIntegrity(protocolBaseKey, ciphertext, ciphertext, testUsage), "Integrity verification failed")

			_, encryptedMessage, err := e.EncryptMessage(protocolBaseKey, plaintext, testUsage)
			if err != nil {
				t.Fatalf("EncryptMessage failed: %v", err)
			}

			decryptedMessage, err := e.DecryptMessage(protocolBaseKey, encryptedMessage, testUsage)
			if err != nil {
				t.Fatalf("DecryptMessage failed: %v", err)
			}
			assert.Equal(t, plaintext, decryptedMessage, "Round-trip encrypt/decrypt failed")

			ivz := make([]byte, e.GetConfounderByteSize())
			integrityInput := append(ivz, aesOutput...)
			mac, err := common.GetIntegrityHash(integrityInput, protocolBaseKey, testUsage, e)
			if err != nil {
				t.Fatalf("GetIntegrityHash failed: %v", err)
			}
			assert.Equal(t, test.hmacOutput, hex.EncodeToString(mac), "HMAC output not as expected")
		})
	}
}

func TestEncryptDecrypt_AES256(t *testing.T) {
	t.Parallel()
	//RFC 8009 input-key value/HMAC-SHA384 key. Page 18
	protocolBaseKey, _ := hex.DecodeString("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52")
	testUsage := uint32(2)

	var tests = []struct {
		name       string
		plaintext  string
		confounder string
		ke         string
		ki         string
		aesOutput  string
		hmacOutput string
		ciphertext string
	}{
		{
			name:       "Empty plaintext",
			plaintext:  "",
			confounder: "f764e9fa15c276478b2c7d0c4e5f58e4",
			ke:         "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
			ki:         "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f",
			aesOutput:  "41f53fa5bfe7026d91faf9be959195a0",
			hmacOutput: "58707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c",
			ciphertext: "41f53fa5bfe7026d91faf9be959195a058707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c",
		},
		{
			name:       "Length less than block size",
			plaintext:  "000102030405",
			confounder: "b80d3251c1f6471494256ffe712d0b9a",
			ke:         "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
			ki:         "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f",
			aesOutput:  "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9",
			hmacOutput: "f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2",
			ciphertext: "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2",
		},
		{
			name:       "Length equals block size",
			plaintext:  "000102030405060708090a0b0c0d0e0f",
			confounder: "53bf8a0d105265d4e276428624ce5e63",
			ke:         "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
			ki:         "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f",
			aesOutput:  "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f6",
			hmacOutput: "8cf51f14d798c2273f35df574d1f932e40c4ff255b36a266",
			ciphertext: "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f68cf51f14d798c2273f35df574d1f932e40c4ff255b36a266",
		},
		{
			name:       "Length greater than block size",
			plaintext:  "000102030405060708090a0b0c0d0e0f1011121314",
			confounder: "763e65367e864f02f55153c7e3b58af1",
			ke:         "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
			ki:         "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f",
			aesOutput:  "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86",
			hmacOutput: "fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62",
			ciphertext: "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62",
		},
	}

	var e crypto.Aes256CtsHmacSha384192
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plaintext, _ := hex.DecodeString(test.plaintext)
			confounder, _ := hex.DecodeString(test.confounder)
			ke, _ := hex.DecodeString(test.ke)
			aesOutput, _ := hex.DecodeString(test.aesOutput)
			ciphertext, _ := hex.DecodeString(test.ciphertext)

			confPlaintext := append(confounder, plaintext...)
			_, encryptedData, err := e.EncryptData(ke, confPlaintext)
			if err != nil {
				t.Fatalf("EncryptData failed: %v", err)
			}
			assert.Equal(t, test.aesOutput, hex.EncodeToString(encryptedData), "AES output not as expected")

			decryptedData, err := e.DecryptData(ke, aesOutput)
			if err != nil {
				t.Fatalf("DecryptData failed: %v", err)
			}

			decryptedPlaintext := decryptedData[e.GetConfounderByteSize():]
			assert.Equal(t, test.plaintext, hex.EncodeToString(decryptedPlaintext), "Decrypted plaintext not as expected")

			assert.True(t, e.VerifyIntegrity(protocolBaseKey, ciphertext, ciphertext, testUsage), "Integrity verification failed")

			_, encryptedMessage, err := e.EncryptMessage(protocolBaseKey, plaintext, testUsage)
			if err != nil {
				t.Fatalf("EncryptMessage failed: %v", err)
			}

			decryptedMessage, err := e.DecryptMessage(protocolBaseKey, encryptedMessage, testUsage)
			if err != nil {
				t.Fatalf("DecryptMessage failed: %v", err)
			}
			assert.Equal(t, plaintext, decryptedMessage, "Round-trip encrypt/decrypt failed")

			ivz := make([]byte, e.GetConfounderByteSize())
			integrityInput := append(ivz, aesOutput...)
			mac, err := common.GetIntegrityHash(integrityInput, protocolBaseKey, testUsage, e)
			if err != nil {
				t.Fatalf("GetIntegrityHash failed: %v", err)
			}
			assert.Equal(t, test.hmacOutput, hex.EncodeToString(mac), "HMAC output not as expected")
		})
	}
}

func TestChecksum_AES128(t *testing.T) {
	t.Parallel()
	protocolBaseKey, _ := hex.DecodeString("3705d96080c17728a0e800eab6e0d23c")
	testUsage := uint32(2)

	plaintext, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f1011121314")
	expectedChecksum := "d78367186643d67b411cba9139fc1dee"

	var e crypto.Aes128CtsHmacSha256128
	checksum, err := e.GetChecksumHash(protocolBaseKey, plaintext, testUsage)
	if err != nil {
		t.Fatalf("GetChecksumHash failed: %v", err)
	}

	assert.Equal(t, expectedChecksum, hex.EncodeToString(checksum), "Checksum not as expected")
}

func TestChecksum_AES256(t *testing.T) {
	t.Parallel()
	protocolBaseKey, _ := hex.DecodeString("6d404d37faf79f9df0d33568d3206698" +
		"00eb4836472ea8a026d16b7182460c52")
	testUsage := uint32(2)

	plaintext, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f1011121314")
	expectedChecksum := "45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a"

	var e crypto.Aes256CtsHmacSha384192
	checksum, err := e.GetChecksumHash(protocolBaseKey, plaintext, testUsage)
	if err != nil {
		t.Fatalf("GetChecksumHash failed: %v", err)
	}

	assert.Equal(t, expectedChecksum, hex.EncodeToString(checksum), "Checksum not as expected")
}

// End Test Vectors

func TestEncryptData_InvalidKeySize_AES128(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name          string
		wrongKeySize  int
		plaintext     string
		expectedError string
	}{
		{
			name:          "AES128 with wrong key size",
			wrongKeySize:  24,
			plaintext:     "test data",
			expectedError: "incorrect keysize: expected: 16 actual: 24",
		},
		{
			name:          "AES128 with too small key",
			wrongKeySize:  8,
			plaintext:     "test data",
			expectedError: "incorrect keysize: expected: 16 actual: 8",
		},
	}

	var e crypto.Aes128CtsHmacSha256128
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrongKey := make([]byte, test.wrongKeySize)
			plaintext := []byte(test.plaintext)

			_, _, err := e.EncryptData(wrongKey, plaintext)

			assert.Error(t, err, "Expected an error for invalid key size")
			assert.Contains(t, err.Error(), test.expectedError, "Error message not as expected")
		})
	}
}

func TestEncryptData_InvalidKeySize_AES256(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name          string
		wrongKeySize  int
		plaintext     string
		expectedError string
	}{
		{
			name:          "AES256 with wrong key size",
			wrongKeySize:  16,
			plaintext:     "test data",
			expectedError: "incorrect keysize: expected: 24 actual: 16",
		},
		{
			name:          "AES256 with too large key",
			wrongKeySize:  64,
			plaintext:     "test data",
			expectedError: "incorrect keysize: expected: 24 actual: 64",
		},
	}

	var e crypto.Aes256CtsHmacSha384192
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrongKey := make([]byte, test.wrongKeySize)
			plaintext := []byte(test.plaintext)

			_, _, err := e.EncryptData(wrongKey, plaintext)

			assert.Error(t, err, "Expected an error for invalid key size")
			assert.Contains(t, err.Error(), test.expectedError, "Error message not as expected")
		})
	}
}

func TestEncryptMessage_InvalidKeySize_AES128(t *testing.T) {
	t.Parallel()

	var e crypto.Aes128CtsHmacSha256128

	wrongKey := make([]byte, 24)
	plaintext := []byte("test data")
	testUsage := uint32(2)

	_, _, err := e.EncryptMessage(wrongKey, plaintext, testUsage)

	assert.Error(t, err, "Expected error for invalid key size")
	assert.Contains(t, err.Error(), "incorrect keysize", "Error message should mention keysize")
}

func TestDecryptMessage_InvalidKeySize_AES128(t *testing.T) {
	t.Parallel()

	var e crypto.Aes128CtsHmacSha256128

	wrongKey := make([]byte, 24) // Wrong size
	fakeCiphertext := make([]byte, 32)
	testUsage := uint32(2)

	_, err := e.DecryptMessage(wrongKey, fakeCiphertext, testUsage)

	assert.Error(t, err, "Expected error for invalid key")
	assert.Contains(t, err.Error(), "integrity verification failed",
		"Gets integrity error before keysize check")
}

func TestDecryptMessage_IntegrityVerificationFail_AES128(t *testing.T) {
	t.Parallel()

	var e crypto.Aes128CtsHmacSha256128

	wrongKey := make([]byte, 24)
	fakeCiphertext := make([]byte, 32)
	testUsage := uint32(2)

	_, err := e.DecryptMessage(wrongKey, fakeCiphertext, testUsage)

	assert.Error(t, err, "Expected error for integrity verification fail")
	assert.Contains(t, err.Error(), "integrity verification fail", "Error message should mention integrity verification fail")
}

func TestEncryptMessage_ZeroUsage(t *testing.T) {
	var e crypto.Aes128CtsHmacSha256128
	key := make([]byte, 16)
	message := []byte("test")
	zeroUsage := uint32(0)

	_, _, err := e.EncryptMessage(key, message, zeroUsage)

	assert.Error(t, err, "Expected error when usage is 0")
	assert.Contains(t, err.Error(), "incorrect keysize",
		"Should fail with keysize error because derived key is empty")
}

func TestDecryptData_InvalidKeySize_AES128(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name          string
		wrongKeySize  int
		ciphertext    string
		expectedError string
	}{
		{
			name:          "AES128 with wrong key size",
			wrongKeySize:  24, // Wrong: should be 16
			ciphertext:    "000102030405060708090a0b0c0d0e0f",
			expectedError: "incorrect keysize: expected: 16 actual: 24",
		},
		{
			name:          "AES128 with too small key",
			wrongKeySize:  8,
			ciphertext:    "000102030405060708090a0b0c0d0e0f",
			expectedError: "incorrect keysize: expected: 16 actual: 8",
		},
	}

	var e crypto.Aes128CtsHmacSha256128
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrongKey := make([]byte, test.wrongKeySize)
			ciphertext, _ := hex.DecodeString(test.ciphertext)

			_, err := e.DecryptData(wrongKey, ciphertext)

			assert.Error(t, err, "Expected an error for invalid key size")
			assert.Contains(t, err.Error(), test.expectedError, "Error message not as expected")
		})
	}
}
