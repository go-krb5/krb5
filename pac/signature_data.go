package pac

import (
	"bytes"

	"github.com/go-krb5/x/rpc/mstypes"

	"github.com/go-krb5/krb5/iana/chksumtype"
)

/*
https://msdn.microsoft.com/en-us/library/cc237955.aspx

The Key Usage Value MUST be KERB_NON_KERB_CKSUM_SALT (17) [MS-KILE] (section 3.1.5.9).

Server Signature (SignatureType = 0x00000006)
https://msdn.microsoft.com/en-us/library/cc237957.aspx

KDC Signature (SignatureType = 0x00000007)
https://msdn.microsoft.com/en-us/library/dd357117.aspx
*/

// SignatureData implements https://msdn.microsoft.com/en-us/library/cc237955.aspx
type SignatureData struct {
	SignatureType  uint32 // A 32-bit unsigned integer value in little-endian format that defines the cryptographic system used to calculate the checksum. This MUST be one of the following checksum types: KERB_CHECKSUM_HMAC_MD5 (signature size = 16), HMAC_SHA1_96_AES128 (signature size = 12), HMAC_SHA1_96_AES256 (signature size = 12).
	Signature      []byte // Size depends on the type. See comment above.
	RODCIdentifier uint16 // A 16-bit unsigned integer value in little-endian format that contains the first 16 bits of the key version number ([MS-KILE] section 3.1.5.8) when the KDC is an RODC. When the KDC is not an RODC, this field does not exist.
}

// Unmarshal bytes into the SignatureData struct.
func (k *SignatureData) Unmarshal(b []byte) (rb []byte, err error) {
	r := mstypes.NewReader(bytes.NewReader(b))

	k.SignatureType, err = r.Uint32()
	if err != nil {
		return rb, err
	}

	var c int

	switch k.SignatureType {
	case chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED:
		c = 16
	case uint32(chksumtype.HMAC_SHA1_96_AES128):
		c = 12
	case uint32(chksumtype.HMAC_SHA1_96_AES256):
		c = 12
	case uint32(chksumtype.HMAC_SHA256_128_AES128):
		c = 16
	case uint32(chksumtype.HMAC_SHA384_192_AES256):
		c = 24
		// The Camellia CMACs (RFC 6803), 16 octets each. A KDC signs the PAC with the strongest key the
		// krbtgt principal holds, and on a FreeIPA 4.13 realm that key set includes camellia256-cts-cmac
		// so its KDC Signature buffer declares CMAC_CAMELLIA256 and carries 16 bytes. Both constants
		// were already in iana/chksumtype; only their lengths were missing here, and a missing length is
		// not inert (see below).
	case uint32(chksumtype.CMAC_CAMELLIA128):
		c = 16
	case uint32(chksumtype.CMAC_CAMELLIA256):
		c = 16
	default:
		// Defence for the next type that is missing rather than for any type known today.
		//
		// A length left at zero here is not merely "the signature could not be read": c also drives
		// the zeroing at the end of this function, so an unlisted type would put the buffer into the
		// caller's verification digest verbatim while the KDC had hashed it as zeros. Every checksum
		// then fails, and it is reported as a bad signature rather than as a missing length — which
		// sends the reader after keys, enctypes and clock skew. That is what the Camellia case above
		// cost to find.
		//
		// A signature buffer is `type (4) + signature (rest)`, so the remainder is the reading to
		// fall back on. No RODCIdentifier is read for such a type: with no known length there is
		// nothing to tell a trailing identifier from signature bytes. Every listed type keeps its
		// exact length and its RODC handling, so nothing that works today changes.
		if len(b) > 4 {
			c = len(b) - 4
		}
	}

	k.Signature, err = r.ReadBytes(c)
	if err != nil {
		return rb, err
	}

	// When the KDC is not an Read Only Domain Controller (RODC), this field does not exist.
	if len(b) >= 4+c+2 {
		k.RODCIdentifier, err = r.Uint16()
		if err != nil {
			return
		}
	}

	// Create bytes with zeroed signature needed for checksum verification.
	rb = make([]byte, len(b))
	copy(rb, b)
	z := make([]byte, len(b))
	copy(rb[4:4+c], z)

	return
}
