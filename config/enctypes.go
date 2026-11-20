package config

import (
	"slices"
	"strings"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/etypeID"
)

const (
	etypeNameDES3        = "des3-cbc-sha1"
	etypeNameRC4         = "arcfour-hmac"
	etypeNameAES128SHA1  = "aes128-cts-hmac-sha1-96"
	etypeNameAES256SHA1  = "aes256-cts-hmac-sha1-96"
	etypeNameCamellia128 = "camellia128-cts-cmac"
	etypeNameCamellia256 = "camellia256-cts-cmac"
	etypeNameAES128SHA2  = "aes128-cts-hmac-sha256-128"
	etypeNameAES256SHA2  = "aes256-cts-hmac-sha384-192"
)

var mitETypeNames = map[string]int32{
	"des3-cbc-raw":         etypeID.DES3_CBC_RAW,
	etypeNameDES3:          etypeID.DES3_CBC_SHA1_KD,
	"des3-hmac-sha1":       etypeID.DES3_CBC_SHA1_KD,
	"des3-cbc-sha1-kd":     etypeID.DES3_CBC_SHA1_KD,
	etypeNameRC4:           etypeID.RC4_HMAC,
	"rc4-hmac":             etypeID.RC4_HMAC,
	"arcfour-hmac-md5":     etypeID.RC4_HMAC,
	"arcfour-hmac-exp":     etypeID.RC4_HMAC_EXP,
	"rc4-hmac-exp":         etypeID.RC4_HMAC_EXP,
	"arcfour-hmac-md5-exp": etypeID.RC4_HMAC_EXP,
	etypeNameAES128SHA1:    etypeID.AES128_CTS_HMAC_SHA1_96,
	"aes128-cts":           etypeID.AES128_CTS_HMAC_SHA1_96,
	"aes128-sha1":          etypeID.AES128_CTS_HMAC_SHA1_96,
	etypeNameAES256SHA1:    etypeID.AES256_CTS_HMAC_SHA1_96,
	"aes256-cts":           etypeID.AES256_CTS_HMAC_SHA1_96,
	"aes256-sha1":          etypeID.AES256_CTS_HMAC_SHA1_96,
	etypeNameCamellia128:   etypeID.CAMELLIA128_CTS_CMAC,
	"camellia128-cts":      etypeID.CAMELLIA128_CTS_CMAC,
	etypeNameCamellia256:   etypeID.CAMELLIA256_CTS_CMAC,
	"camellia256-cts":      etypeID.CAMELLIA256_CTS_CMAC,
	etypeNameAES128SHA2:    etypeID.AES128_CTS_HMAC_SHA256_128,
	"aes128-sha2":          etypeID.AES128_CTS_HMAC_SHA256_128,
	etypeNameAES256SHA2:    etypeID.AES256_CTS_HMAC_SHA384_192,
	"aes256-sha2":          etypeID.AES256_CTS_HMAC_SHA384_192,
}

var mitETypeFamilies = map[string][]int32{
	"des3":     {etypeID.DES3_CBC_SHA1_KD},
	"aes":      {etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA384_192, etypeID.AES128_CTS_HMAC_SHA256_128},
	"rc4":      {etypeID.RC4_HMAC},
	"camellia": {etypeID.CAMELLIA256_CTS_CMAC, etypeID.CAMELLIA128_CTS_CMAC},
}

var defaultETypeNames = []string{
	etypeNameAES256SHA1,
	etypeNameAES128SHA1,
	etypeNameAES256SHA2,
	etypeNameAES128SHA2,
	etypeNameDES3,
	etypeNameRC4,
	etypeNameCamellia128,
	etypeNameCamellia256,
}

func splitETypeList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == ','
	})
}

func etypeByName(name string) (int32, bool) {
	// MIT krb5's names take precedence over the IANA names because the two disagree: MIT krb5 gives des3-cbc-sha1 and
	// des3-hmac-sha1 to des3-cbc-sha1-kd, the only triple DES type it implements.
	for n, id := range mitETypeNames {
		if strings.EqualFold(n, name) {
			return id, true
		}
	}

	for n, id := range etypeID.ETypesByName {
		if strings.EqualFold(n, name) {
			return id, true
		}
	}

	return 0, false
}

func weakEType(id int32) bool {
	for _, name := range strings.Fields(WeakETypeList) {
		if w, ok := etypeByName(name); ok && w == id {
			return true
		}
	}

	return false
}

func parseETypes(words []string, allowWeak bool) []int32 {
	var ids []int32

	mod := func(id int32, add bool) {
		// The crypto registry, not this package, decides what is supported: an application that unregisters an
		// encryption type must not have it advertised to the KDC, and one that registers an additional
		// implementation must be able to name it here.
		if !allowWeak && weakEType(id) {
			return
		}

		if _, err := crypto.GetEType(id); err != nil {
			return
		}

		i := slices.Index(ids, id)

		switch {
		case add && i < 0:
			ids = append(ids, id)
		case !add && i >= 0:
			ids = slices.Delete(ids, i, i+1)
		}
	}

	for _, word := range words {
		add := true

		if word != "" && (word[0] == '+' || word[0] == '-') {
			add = word[0] == '+'
			word = word[1:]
		}

		for _, id := range etypeWord(word) {
			mod(id, add)
		}
	}

	return ids
}

func etypeWord(word string) []int32 {
	if strings.EqualFold(word, "DEFAULT") {
		ids := make([]int32, 0, len(defaultETypeNames))

		for _, name := range defaultETypeNames {
			id, _ := etypeByName(name)
			ids = append(ids, id)
		}

		return ids
	}

	if family, ok := mitETypeFamilies[strings.ToLower(word)]; ok {
		return family
	}

	if id, ok := etypeByName(word); ok {
		return []int32{id}
	}

	return nil
}
