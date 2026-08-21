package pac

import (
	"bytes"
	"fmt"

	"github.com/go-krb5/x/rpc/mstypes"
)

// UPNDNSInfo implements https://msdn.microsoft.com/en-us/library/dd240468.aspx
type UPNDNSInfo struct {
	UPNLength           uint16 // An unsigned 16-bit integer in little-endian format that specifies the length, in bytes, of the UPN field.
	UPNOffset           uint16 // An unsigned 16-bit integer in little-endian format that contains the offset to the beginning of the buffer, in bytes, from the beginning of the UPN_DNS_INFO structure.
	DNSDomainNameLength uint16
	DNSDomainNameOffset uint16
	Flags               uint32
	UPN                 string
	DNSDomain           string
}

const (
	upnNoUPNAttr = 31 // The user account object does not have the userPrincipalName attribute ([MS-ADA3] section 2.349) set. A UPN constructed by concatenating the user name with the DNS domain name of the account domain is provided.
)

// Unmarshal bytes into the UPN_DNSInfo struct.
func (k *UPNDNSInfo) Unmarshal(b []byte) (err error) {
	// The UPN_DNS_INFO structure is a simple structure that is not NDR-encoded.
	r := mstypes.NewReader(bytes.NewReader(b))

	k.UPNLength, err = r.Uint16()
	if err != nil {
		return err
	}

	k.UPNOffset, err = r.Uint16()
	if err != nil {
		return err
	}

	k.DNSDomainNameLength, err = r.Uint16()
	if err != nil {
		return err
	}

	k.DNSDomainNameOffset, err = r.Uint16()
	if err != nil {
		return err
	}

	k.Flags, err = r.Uint32()
	if err != nil {
		return err
	}

	if k.UPN, err = utf16StringAt(b, k.UPNOffset, k.UPNLength, "UPN"); err != nil {
		return err
	}

	if k.DNSDomain, err = utf16StringAt(b, k.DNSDomainNameOffset, k.DNSDomainNameLength, "DNS domain name"); err != nil {
		return err
	}

	return nil
}

// utf16StringAt reads the UTF-16 string of length octets that begins at offset within b.
func utf16StringAt(b []byte, offset, length uint16, name string) (string, error) {
	if int(offset)+int(length) > len(b) {
		return "", fmt.Errorf("UPN_DNS_INFO %s lies outside the buffer: offset %d, length %d, buffer is %d bytes",
			name, offset, length, len(b))
	}

	r := mstypes.NewReader(bytes.NewReader(b[offset : int(offset)+int(length)]))
	s := make([]rune, length/2)

	for i := range s {
		u, err := r.Uint16()
		if err != nil {
			return "", err
		}

		s[i] = rune(u)
	}

	return string(s), nil
}
