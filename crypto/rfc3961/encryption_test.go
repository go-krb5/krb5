package rfc3961_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/crypto/rfc3961"
)

func TestDES3DeriveRandom(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name       string
		key        string // hex string (24 bytes for DES3)
		usage      string // hex string or special value like "kerberos"
		expectedDR string // hex string
		expectedDK string // hex string
	}{
		{
			name:       "Test vector 1",
			key:        "dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92",
			usage:      "0000000155",
			expectedDR: "935079d14490a75c3093c4a6e8c3b049c71e6ee705",
			expectedDK: "925179d04591a79b5d3192c4a7e9c289b049c71f6ee604cd",
		},
		{
			name:       "Test vector 2",
			key:        "5e13d31c70ef765746578531cb51c15bf11ca82c97cee9f2",
			usage:      "00000001aa",
			expectedDR: "9f58e5a047d894101c469845d67ae3c5249ed812f2",
			expectedDK: "9e58e5a146d9942a101c469845d67a20e3c4259ed913f207",
		},
		{
			name:       "kerberos usage",
			key:        "d3f8298ccb166438dcb9b93ee5a7629286a491f838f802fb",
			usage:      "kerberos", // Special string usage
			expectedDR: "2270db565d2a3d64cfbfdc5305d4f778a6de42d9da",
			expectedDK: "2370da575d2a3da864cebfdc5204d56df779a7df43d9da43",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var e crypto.Des3CbcSha1Kd

			key, _ := hex.DecodeString(test.key)
			var usage []byte
			if test.usage == "kerberos" {
				usage = []byte("kerberos")
			} else {
				usage, _ = hex.DecodeString(test.usage)
			}

			// Test DR (derive-random) function
			dr, err := e.DeriveRandom(key, usage)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedDR, hex.EncodeToString(dr), "DR result not as expected")

			// Test DK (derive-key) function
			dk, err := e.DeriveKey(key, usage)
			if err != nil {
				t.Fatalf("DeriveKey failed: %v", err)
			}
			assert.Equal(t, test.expectedDK, hex.EncodeToString(dk), "DK result not as expected")
		})
	}
}

func TestDES3StringToKey(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name     string
		password string
		salt     string
		expected string // hex string (24 bytes for DES3)
	}{
		{
			name:     "password @ ATHENA.MIT.EDUraeburn",
			password: "password",
			salt:     "ATHENA.MIT.EDUraeburn",
			expected: "850bb51358548cd05e86768c313e3bfef7511937dcf72c3e",
		},
		{
			name:     "potatoe @ WHITEHOUSE.GOVdanny",
			password: "potatoe",
			salt:     "WHITEHOUSE.GOVdanny",
			expected: "dfcd233dd0a43204ea6dc437fb15e061b02979c1f74f377a",
		},
		{
			name:     "penny @ EXAMPLE.COMbuckaroo",
			password: "penny",
			salt:     "EXAMPLE.COMbuckaroo",
			expected: "6d2fcdf2d6fbbc3ddcadb5da5710a23489b0d3b69d5d9d4a",
		},
		{
			name:     "UTF-8 eszett",
			password: "ß",
			salt:     "ATHENA.MIT.EDUJuri" + "š" + "i" + "ć",
			expected: "16d5a40e1ce3bacb61b9dce00470324c831973a7b952feb0",
		},
		{
			name:     "UTF-8 g-clef",
			password: "𝄞", // 0xf09d849e
			salt:     "EXAMPLE.COMpianist",
			expected: "85763726585dbc1cce6ec43e1f751f07f1c4cbb098f40b19",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var e crypto.Des3CbcSha1Kd

			key, err := e.StringToKey(test.password, test.salt, "")
			if err != nil {
				t.Fatalf("StringToKey failed: %v", err)
			}

			assert.Equal(t, test.expected, hex.EncodeToString(key), "DES3 key not as expected")
		})
	}
}

func TestDES3EncryptDecryptData(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name      string
		key       string // hex string (24 bytes)
		plaintext string // hex string
	}{
		{
			name:      "Empty plaintext",
			key:       "0123456789abcdef0123456789abcdef0123456789abcdef",
			plaintext: "",
		},
		{
			name:      "8 byte plaintext (1 DES block)",
			key:       "0123456789abcdef0123456789abcdef0123456789abcdef",
			plaintext: "0123456789abcdef",
		},
		{
			name:      "16 byte plaintext (2 DES blocks)",
			key:       "0123456789abcdef0123456789abcdef0123456789abcdef",
			plaintext: "0123456789abcdef0123456789abcdef",
		},
		{
			name:      "24 byte plaintext (3 DES blocks)",
			key:       "fedcba9876543210fedcba9876543210fedcba9876543210",
			plaintext: "0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name:      "Non-block-aligned plaintext (11 bytes)",
			key:       "0123456789abcdef0123456789abcdef0123456789abcdef",
			plaintext: "48656c6c6f20576f726c64", // "Hello World"
		},
		{
			name:      "Single byte",
			key:       "fedcba9876543210fedcba9876543210fedcba9876543210",
			plaintext: "42",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var e crypto.Des3CbcSha1Kd

			key, _ := hex.DecodeString(test.key)
			plaintext, _ := hex.DecodeString(test.plaintext)

			_, ciphertext, err := rfc3961.DES3EncryptData(key, plaintext, &e)
			if err != nil {
				t.Fatalf("DES3EncryptData failed: %v", err)
			}

			decrypted, err := rfc3961.DES3DecryptData(key, ciphertext, &e)
			if err != nil {
				t.Fatalf("DES3DecryptData failed: %v", err)
			}

			// Remove padding and compare
			assert.Equal(t, plaintext, decrypted[:len(plaintext)], "Round-trip encrypt/decrypt failed")
		})
	}
}

func TestDES3EncryptDecryptMessage(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name      string
		key       string // hex string (24 bytes)
		plaintext string // hex string
		usage     uint32
	}{
		{
			name:      "Empty message",
			key:       "0123456789abcdef0123456789abcdef0123456789abcdef",
			plaintext: "",
			usage:     2,
		},
		{
			name:      "Short message",
			key:       "0123456789abcdef0123456789abcdef0123456789abcdef",
			plaintext: "48656c6c6f000000",
			usage:     2,
		},
		{
			name:      "Block-sized message",
			key:       "0123456789abcdef0123456789abcdef0123456789abcdef",
			plaintext: "0123456789abcdef0123456789abcdef",
			usage:     2,
		},
		{
			name:      "Different usage value",
			key:       "0123456789abcdef0123456789abcdef0123456789abcdef",
			plaintext: "48656c6c6f20576f726c640000000000",
			usage:     3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var e crypto.Des3CbcSha1Kd

			key, _ := hex.DecodeString(test.key)
			plaintext, _ := hex.DecodeString(test.plaintext)

			_, encryptedMessage, err := rfc3961.DES3EncryptMessage(key, plaintext, test.usage, &e)
			if err != nil {
				t.Fatalf("DES3EncryptMessage failed: %v", err)
			}

			decryptedMessage, err := rfc3961.DES3DecryptMessage(key, encryptedMessage, test.usage, &e)
			if err != nil {
				t.Fatalf("DES3DecryptMessage failed: %v", err)
			}

			assert.Equal(t, plaintext, decryptedMessage, "Round-trip encrypt/decrypt message failed")
		})
	}
}

// Error handling tests

func TestDES3EncryptData_InvalidKeySize(t *testing.T) {
	t.Parallel()

	var e crypto.Des3CbcSha1Kd
	wrongKey := make([]byte, 16) // Should be 24 bytes
	plaintext := []byte("test data")

	_, _, err := rfc3961.DES3EncryptData(wrongKey, plaintext, &e)

	assert.Error(t, err, "Expected error for invalid key size")
	assert.Contains(t, err.Error(), "incorrect keysize", "Error message should mention keysize")
}

func TestDES3DecryptData_InvalidKeySize(t *testing.T) {
	t.Parallel()

	var e crypto.Des3CbcSha1Kd
	wrongKey := make([]byte, 16) // Should be 24 bytes
	ciphertext := make([]byte, 24)

	_, err := rfc3961.DES3DecryptData(wrongKey, ciphertext, &e)

	assert.Error(t, err, "Expected error for invalid key size")
	assert.Contains(t, err.Error(), "incorrect keysize", "Error message should mention keysize")
}

func TestDES3DecryptMessage_InvalidCiphertextSize(t *testing.T) {
	t.Parallel()

	var e crypto.Des3CbcSha1Kd
	key := make([]byte, 24)
	fakeCiphertext := make([]byte, 48)
	testUsage := uint32(2)

	_, err := rfc3961.DES3DecryptMessage(key, fakeCiphertext, testUsage, &e)

	assert.Error(t, err, "Expected error for ciphertext size")
	assert.Contains(t, err.Error(), "ciphertext is not a multiple of the block size",
		"Error message should mention invalid ciphertext size")
}
