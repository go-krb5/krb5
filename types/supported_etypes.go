package types

import (
	"encoding/binary"
	"fmt"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/patype"
)

// Supported encryption type bit flags, as carried in the msDS-SupportedEncryptionTypes attribute and in the
// PA-SUPPORTED-ENCTYPES pre-authentication data described by MS-KILE Section 2.2.7. The letters in the comments are
// the labels MS-KILE gives each bit in its diagram.
//
// Only the first eight bits describe encryption types. The remainder advertise unrelated capabilities and are
// preserved but never intersected, since ANDing "claims supported" with another party's value says nothing about
// encryption.
const (
	SupportedETypeDESCBCCRC              uint32 = 0x00000001 // A.
	SupportedETypeDESCBCMD5              uint32 = 0x00000002 // B.
	SupportedETypeRC4HMAC                uint32 = 0x00000004 // C.
	SupportedETypeAES128CTSHMACSHA196    uint32 = 0x00000008 // D.
	SupportedETypeAES256CTSHMACSHA196    uint32 = 0x00000010 // E.
	SupportedETypeAES256CTSHMACSHA196SK  uint32 = 0x00000020 // J.
	SupportedETypeAES128CTSHMACSHA256128 uint32 = 0x00000040 // K.
	SupportedETypeAES256CTSHMACSHA384192 uint32 = 0x00000080 // L.

	SupportedETypeFAST                           uint32 = 0x00010000 // F.
	SupportedETypeCompoundIdentity               uint32 = 0x00020000 // G.
	SupportedETypeClaims                         uint32 = 0x00040000 // H.
	SupportedETypeResourceSIDCompressionDisabled uint32 = 0x00080000 // I.
)

// supportedETypeMask selects the bits that name an encryption type. It excludes AES256CTSHMACSHA196SK, which
// MS-KILE Section 2.2.7 describes as a policy instruction; "Enforce AES session keys when legacy ciphers are in
// use"; rather than as an encryption type the peer can decrypt with. Treating it as one would advertise an
// encryption type that does not exist.
const supportedETypeMask = SupportedETypeDESCBCCRC | SupportedETypeDESCBCMD5 | SupportedETypeRC4HMAC |
	SupportedETypeAES128CTSHMACSHA196 | SupportedETypeAES256CTSHMACSHA196 |
	SupportedETypeAES128CTSHMACSHA256128 | SupportedETypeAES256CTSHMACSHA384192

// supportedETypeLen is the width MS-KILE Section 2.2.7 fixes for the value: a 32 bit unsigned integer.
const supportedETypeLen = 4

// supportedETypeIDs maps each encryption type bit to the encryption type it names.
var supportedETypeIDs = map[uint32]int32{
	SupportedETypeDESCBCCRC:              etypeID.DES_CBC_CRC,
	SupportedETypeDESCBCMD5:              etypeID.DES_CBC_MD5,
	SupportedETypeRC4HMAC:                etypeID.RC4_HMAC,
	SupportedETypeAES128CTSHMACSHA196:    etypeID.AES128_CTS_HMAC_SHA1_96,
	SupportedETypeAES256CTSHMACSHA196:    etypeID.AES256_CTS_HMAC_SHA1_96,
	SupportedETypeAES128CTSHMACSHA256128: etypeID.AES128_CTS_HMAC_SHA256_128,
	SupportedETypeAES256CTSHMACSHA384192: etypeID.AES256_CTS_HMAC_SHA384_192,
}

// SupportedETypes is the value of the PA-SUPPORTED-ENCTYPES pre-authentication data of MS-KILE Section 2.2.7: a
// bitmask of the encryption types and capabilities a party supports.
//
// The zero value means "not advertised", which is distinct from "supports nothing". A party that never sent the
// pre-authentication data cannot be intersected with, so callers check IsZero before acting on one.
type SupportedETypes uint32

// NewSupportedETypesFromIDs builds a bitmask advertising the encryption types given. Encryption types with no bit
// assigned by MS-KILE Section 2.2.7 are skipped: the specification requires that all other bits be zero when sent.
func NewSupportedETypesFromIDs(ids []int32) SupportedETypes {
	var s SupportedETypes

	for _, id := range ids {
		for bit, etype := range supportedETypeIDs {
			if etype == id {
				s |= SupportedETypes(bit)
			}
		}
	}

	return s
}

// UnmarshalSupportedETypes reads the four octet little-endian value MS-KILE Section 2.2.7 defines.
func UnmarshalSupportedETypes(b []byte) (SupportedETypes, error) {
	if len(b) != supportedETypeLen {
		return 0, fmt.Errorf("PA-SUPPORTED-ENCTYPES is %d octets rather than %d", len(b), supportedETypeLen)
	}

	return SupportedETypes(binary.LittleEndian.Uint32(b)), nil
}

// SupportedETypesFromPAData returns the value of the PA-SUPPORTED-ENCTYPES entry in the sequence, or zero when
// there is none. A malformed entry is treated as absent: the data is advisory, used only to hint to a KDC which
// encryption types two other parties share, so refusing the exchange over it would trade a working authentication
// for a hint.
func SupportedETypesFromPAData(pas PADataSequence) SupportedETypes {
	for _, pa := range pas {
		if pa.PADataType != patype.PA_SUPPORTED_ETYPES {
			continue
		}

		s, err := UnmarshalSupportedETypes(pa.PADataValue)
		if err != nil {
			return 0
		}

		return s
	}

	return 0
}

// PAData returns the pre-authentication data entry advertising these encryption types.
func (s SupportedETypes) PAData() PAData {
	return PAData{
		PADataType:  patype.PA_SUPPORTED_ETYPES,
		PADataValue: s.Marshal(),
	}
}

// Marshal returns the four octet little-endian encoding.
func (s SupportedETypes) Marshal() []byte {
	b := make([]byte, supportedETypeLen)
	binary.LittleEndian.PutUint32(b, uint32(s))

	return b
}

// IsZero reports whether nothing was advertised. MS-KILE draws no distinction between an absent
// PA-SUPPORTED-ENCTYPES and one advertising no encryption types, so both mean "unknown" rather than "none".
func (s SupportedETypes) IsZero() bool {
	return s == 0
}

// Contains reports whether the encryption type given is advertised.
func (s SupportedETypes) Contains(id int32) bool {
	for bit, etype := range supportedETypeIDs {
		if etype == id {
			return uint32(s)&bit != 0
		}
	}

	return false
}

// ETypeIDs returns the encryption types advertised, in the order iana/etypeID assigns them so that the result is
// deterministic. Capability bits that name no encryption type are omitted.
func (s SupportedETypes) ETypeIDs() []int32 {
	ids := make([]int32, 0, len(supportedETypeIDs))

	for _, id := range []int32{
		etypeID.DES_CBC_CRC,
		etypeID.DES_CBC_MD5,
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA256_128,
		etypeID.AES256_CTS_HMAC_SHA384_192,
		etypeID.RC4_HMAC,
	} {
		if s.Contains(id) {
			ids = append(ids, id)
		}
	}

	return ids
}

// Intersect returns the encryption types both parties advertise.
//
// Only the encryption type bits participate; the capability bits of MS-KILE Section 2.2.7 are dropped, because
// they describe what each party can do rather than what they have in common, and this library advertises none of
// them.
//
// A zero receiver or argument means that party advertised nothing, so there is nothing to intersect and the other
// party's encryption types are returned unchanged. Returning an empty intersection instead would advertise that no
// encryption type is common, which is a stronger claim than the absence of the data supports.
func (s SupportedETypes) Intersect(o SupportedETypes) SupportedETypes {
	switch {
	case s.IsZero():
		return o & SupportedETypes(supportedETypeMask)
	case o.IsZero():
		return s & SupportedETypes(supportedETypeMask)
	default:
		return s & o & SupportedETypes(supportedETypeMask)
	}
}
