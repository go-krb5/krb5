package pac

import (
	"bytes"

	"github.com/go-krb5/x/rpc/mstypes"
)

// ClientInfo implements https://msdn.microsoft.com/en-us/library/cc237951.aspx
type ClientInfo struct {
	// A FILETIME structure in little-endian format that contains the Kerberos initial ticket-granting ticket TGT authentication time.
	ClientID mstypes.FileTime

	// An unsigned 16-bit integer in little-endian format that specifies the length, in bytes, of the Name field.
	NameLength uint16

	// An array of 16-bit Unicode characters in little-endian format that contains the client's account name.
	Name string
}

// Unmarshal bytes into the ClientInfo struct.
func (k *ClientInfo) Unmarshal(b []byte) (err error) {
	// The PAC_CLIENT_INFO structure is a simple structure that is not NDR-encoded.
	r := mstypes.NewReader(bytes.NewReader(b))

	k.ClientID, err = r.FileTime()
	if err != nil {
		return
	}

	k.NameLength, err = r.Uint16()
	if err != nil {
		return
	}

	k.Name, err = r.UTF16String(int(k.NameLength))

	return
}
