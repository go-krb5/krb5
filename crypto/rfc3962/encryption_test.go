package rfc3962_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/crypto/common"
	"github.com/go-krb5/krb5/crypto/rfc3962"
)

func TestStringToKey(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name        string
		iterations  uint32
		passphrase  string
		salt        string
		tempKey128  string // PBKDF2 output for 128-bit
		finalKey128 string // After DK function for AES-128
		tempKey256  string // PBKDF2 output for 256-bit
		finalKey256 string // After DK function for AES-256
	}{
		{
			name:        "RFC 3962 Appendix B - iteration count 1",
			iterations:  1,
			passphrase:  "password",
			salt:        "ATHENA.MIT.EDUraeburn",
			tempKey128:  "cdedb5281bb2f801565a1122b2563515",
			finalKey128: "42263c6e89f4fc28b8df68ee09799f15",
			tempKey256:  "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837",
			finalKey256: "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
		},
		{
			name:        "RFC 3962 Appendix B - iteration count 2",
			iterations:  2,
			passphrase:  "password",
			salt:        "ATHENA.MIT.EDUraeburn",
			tempKey128:  "01dbee7f4a9e243e988b62c73cda935d",
			finalKey128: "c651bf29e2300ac27fa469d693bdda13",
			tempKey256:  "01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86",
			finalKey256: "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff",
		},
		{
			name:        "RFC 3962 Appendix B - iteration count 1200",
			iterations:  1200,
			passphrase:  "password",
			salt:        "ATHENA.MIT.EDUraeburn",
			tempKey128:  "5c08eb61fdf71e4e4ec3cf6ba1f5512b",
			finalKey128: "4c01cd46d632d01e6dbe230a01ed642a",
			tempKey256:  "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13",
			finalKey256: "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
		},
		{
			name:        "RFC 3962 Appendix B - iteration count 5 with binary salt",
			iterations:  5,
			passphrase:  "password",
			salt:        "0x1234567878563412", // 0x1234567878563412 <- raw hex
			tempKey128:  "d1daa78615f287e6a1c8b120d7062a49",
			finalKey128: "e9b23d52273747dd5c35cb55be619d8e",
			tempKey256:  "d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee",
			finalKey256: "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31",
		},
		{
			name:        "RFC 3962 Appendix B - 64 char passphrase",
			iterations:  1200,
			passphrase:  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", //64 chars
			salt:        "pass phrase equals block size",
			tempKey128:  "139c30c0966bc32ba55fdbf212530ac9",
			finalKey128: "59d1bb789a828b1aa54ef9c2883f69ed",
			tempKey256:  "139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1",
			finalKey256: "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34",
		},
		{
			name:        "RFC 3962 Appendix B - 65 char passphrase",
			iterations:  1200,
			passphrase:  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", //65 chars
			salt:        "pass phrase exceeds block size",
			tempKey128:  "9ccad6d468770cd51b10e6a68721be61",
			finalKey128: "cb8005dc5f90179a7f02104c0018751d",
			tempKey256:  "9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a",
			finalKey256: "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b",
		},
		{
			name:        "RFC 3962 Appendix B - UTF-8 passphrase (g-clef)",
			iterations:  50,
			passphrase:  "𝄞", // 0xf09d849e
			salt:        "EXAMPLE.COMpianist",
			tempKey128:  "6b9cf26d45455a43a5b8bb276a403b39",
			finalKey128: "f149c1f2e154a73452d43e7fe62a56e5",
			tempKey256:  "6b9cf26d45455a43a5b8bb276a403b39e7fe37a0c41e02c281ff3069e1e94f52",
			finalKey256: "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e",
		},
	}

	for _, test := range tests {
		t.Run("AES128", func(t *testing.T) {
			t.Run(test.name, func(t *testing.T) {
				var e crypto.Aes128CtsHmacSha96
				salt := decodeHex(test.salt)
				k, err := e.StringToKey(test.passphrase, salt, common.IterationsToS2Kparams(test.iterations))
				if err != nil {
					t.Fatalf("StringToKey failed: %v", err)
				}
				assert.Equal(t, test.finalKey128, hex.EncodeToString(k), "Final key not as expected")
			})

		})
	}

	for _, test := range tests {
		t.Run("AES256", func(t *testing.T) {
			t.Run(test.name, func(t *testing.T) {
				var e crypto.Aes256CtsHmacSha96
				salt := decodeHex(test.salt)
				k, err := e.StringToKey(test.passphrase, salt, common.IterationsToS2Kparams(test.iterations))
				if err != nil {
					t.Fatalf("StringToKey failed: %v", err)
				}
				assert.Equal(t, test.finalKey256, hex.EncodeToString(k), "Final key not as expected")
			})

		})
	}
}

func TestCBCCTS_AES128(t *testing.T) {
	t.Parallel()

	// RFC 3962 Appendix B - CBC with ciphertext stealing test vectors
	aesKey, _ := hex.DecodeString("636869636b656e207465726979616b69")

	var tests = []struct {
		name   string
		input  string
		output string
		nextIV string
	}{
		{
			name:   "17 bytes (1 block + 1 byte)",
			input:  "4920776f756c64206c696b652074686520",
			output: "c6353568f2bf8cb4d8a580362da7ff7f97",
			nextIV: "c6353568f2bf8cb4d8a580362da7ff7f",
		},
		{
			name:   "31 bytes (1 block + 15 bytes)",
			input:  "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
			output: "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
			nextIV: "fc00783e0efdb2c1d445d4c8eff7ed22",
		},
		{
			name:   "32 bytes (2 blocks)",
			input:  "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
			output: "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
			nextIV: "39312523a78662d5be7fcbcc98ebf5a8",
		},
		{
			name:   "47 bytes (2 blocks + 15 bytes)",
			input:  "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c",
			output: "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
			nextIV: "b3fffd940c16a18c1b5549d2f838029e",
		},
		{
			name:   "48 bytes (3 blocks)",
			input:  "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20",
			output: "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
			nextIV: "9dad8bbb96c4cdc03bc103e1a194bbd8",
		},
		{
			name:   "64 bytes (4 blocks)",
			input:  "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
			output: "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
			nextIV: "4807efe836ee89a526730dbc2f7bc840",
		},
	}

	for _, test := range tests {
		var e crypto.Aes128CtsHmacSha96
		t.Run(test.name, func(t *testing.T) {
			input, _ := hex.DecodeString(test.input)
			expectedOutput, _ := hex.DecodeString(test.output)

			actualIV, actualOutput, err := rfc3962.EncryptData(aesKey, input, &e)
			if err != nil {
				t.Fatalf("EncryptData failed: %v", err)
			}

			assert.Equal(t, test.output, hex.EncodeToString(actualOutput), "Ciphertext not as expected")
			assert.Equal(t, test.nextIV, hex.EncodeToString(actualIV), "Next IV not as expected")

			// Test decryption
			decrypted, err := rfc3962.DecryptData(aesKey, expectedOutput, &e)
			if err != nil {
				t.Fatalf("DecryptData failed: %v", err)
			}
			assert.Equal(t, test.input, hex.EncodeToString(decrypted), "Decrypted plaintext not as expected")
		})
	}
}

func TestEncryptDecryptMessage(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name      string
		key128    string
		key256    string
		plaintext string
		usage     uint32
	}{
		{
			name:      "Empty plaintext",
			key128:    "0123456789abcdef0123456789abcdef",
			key256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			plaintext: "",
			usage:     2,
		},
		{
			name:      "Short plaintext",
			key128:    "0123456789abcdef0123456789abcdef",
			key256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			plaintext: "48656c6c6f",
			usage:     2,
		},
		{
			name:      "Block-sized plaintext",
			key128:    "0123456789abcdef0123456789abcdef",
			key256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			plaintext: "0123456789abcdef0123456789abcdef",
			usage:     2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plaintext, _ := hex.DecodeString(test.plaintext)

			t.Run("AES128", func(t *testing.T) {
				var e crypto.Aes128CtsHmacSha96
				key, _ := hex.DecodeString(test.key128)

				// Test full message encryption/decryption round-trip
				_, encryptedMessage, err := rfc3962.EncryptMessage(key, plaintext, test.usage, &e)
				if err != nil {
					t.Fatalf("EncryptMessage failed: %v", err)
				}

				decryptedMessage, err := rfc3962.DecryptMessage(key, encryptedMessage, test.usage, &e)
				if err != nil {
					t.Fatalf("DecryptMessage failed: %v", err)
				}
				assert.Equal(t, plaintext, decryptedMessage, "Round-trip encrypt/decrypt failed")
			})

			t.Run("AES256", func(t *testing.T) {
				var e crypto.Aes256CtsHmacSha96
				key, _ := hex.DecodeString(test.key256)

				_, encryptedMessage, err := rfc3962.EncryptMessage(key, plaintext, test.usage, &e)
				if err != nil {
					t.Fatalf("EncryptMessage failed: %v", err)
				}

				decryptedMessage, err := rfc3962.DecryptMessage(key, encryptedMessage, test.usage, &e)
				if err != nil {
					t.Fatalf("DecryptMessage failed: %v", err)
				}
				assert.Equal(t, plaintext, decryptedMessage, "Round-trip encrypt/decrypt failed")
			})
		})
	}
}

// Error handling tests

func TestEncryptData_InvalidKeySize(t *testing.T) {
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

	var e crypto.Aes128CtsHmacSha96
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrongKey := make([]byte, test.wrongKeySize)
			plaintext := []byte(test.plaintext)

			_, _, err := rfc3962.EncryptData(wrongKey, plaintext, &e)

			assert.Error(t, err, "Expected an error for invalid key size")
			assert.Contains(t, err.Error(), test.expectedError, "Error message not as expected")
		})
	}
}

func TestDecryptMessage_IntegrityVerificationFail(t *testing.T) {
	t.Parallel()

	var e crypto.Aes128CtsHmacSha96

	key := make([]byte, 16)
	fakeCiphertext := make([]byte, 32)
	testUsage := uint32(2)

	_, err := rfc3962.DecryptMessage(key, fakeCiphertext, testUsage, &e)

	assert.Error(t, err, "Expected error for integrity verification fail")
	assert.Contains(t, err.Error(), "integrity verification failed",
		"Error message should mention integrity verification failure")
}

func TestEncryptMessage_InvalidKeySize_AES128(t *testing.T) {
	t.Parallel()

	var e crypto.Aes128CtsHmacSha96

	wrongKey := make([]byte, 24)
	plaintext := []byte("test data")
	testUsage := uint32(2)

	_, _, err := e.EncryptMessage(wrongKey, plaintext, testUsage)

	assert.Error(t, err, "Expected error for invalid key size")
	assert.Contains(t, err.Error(), "incorrect keysize", "Error message should mention keysize")
}

func TestDecryptMessage_InvalidKeySize_AES128(t *testing.T) {
	t.Parallel()

	var e crypto.Aes128CtsHmacSha96

	wrongKey := make([]byte, 24) // Wrong size
	fakeCiphertext := make([]byte, 32)
	testUsage := uint32(2)

	_, err := e.DecryptMessage(wrongKey, fakeCiphertext, testUsage)

	assert.Error(t, err, "Expected error for invalid key")
	assert.Contains(t, err.Error(), "incorrect keysize",
		"Gets integrity error before keysize check")
}

func decodeHex(s string) string {
	if strings.HasPrefix(s, "0x") {
		b, _ := hex.DecodeString(s[2:])
		return string(b)
	}
	return s
}
