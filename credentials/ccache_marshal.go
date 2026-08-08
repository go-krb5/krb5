package credentials

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/go-krb5/krb5/types"
)

// NewV4CCache creates a new version 4 credential cache with no credentials.
func NewV4CCache() *CCache {
	return &CCache{
		Version: 4,
		Header:  header{length: 0},
	}
}

// AddCredential appends a credential to the cache.
func (c *CCache) AddCredential(cred *Credential) {
	c.Credentials = append(c.Credentials, cred)
}

// SetDefaultPrincipal sets the cache's default principal.
func (c *CCache) SetDefaultPrincipal(p principal) {
	c.DefaultPrincipal = p
}

// NewPrincipal returns a principal for the given name and realm.
func NewPrincipal(name types.PrincipalName, realm string) principal {
	return principal{Realm: realm, PrincipalName: name}
}

// Marshal serializes the credential cache into its byte representation. It is
// the inverse of Unmarshal: for any cache c parsed from bytes b,
// c.Marshal() reproduces b exactly.
func (c *CCache) Marshal() ([]byte, error) {
	var b bytes.Buffer
	if err := b.WriteByte(5); err != nil {
		return nil, err
	}

	if err := b.WriteByte(c.Version); err != nil {
		return nil, err
	}

	endian := c.getEndian()
	if c.Version == 4 {
		hb, err := c.writeV4Header()
		if err != nil {
			return nil, err
		}

		if _, err := b.Write(hb); err != nil {
			return nil, err
		}
	}

	pb, err := c.writePrincipal(c.DefaultPrincipal, endian)
	if err != nil {
		return nil, err
	}

	if _, err := b.Write(pb); err != nil {
		return nil, err
	}

	for _, cred := range c.Credentials {
		cb, err := c.writeCredential(cred, endian)
		if err != nil {
			return nil, err
		}

		if _, err := b.Write(cb); err != nil {
			return nil, err
		}
	}

	return b.Bytes(), nil
}

func (c *CCache) writeV4Header() ([]byte, error) {
	var b bytes.Buffer

	endian := binary.BigEndian // the v4 header is always big-endian.
	if err := binary.Write(&b, endian, c.Header.length); err != nil {
		return nil, err
	}

	for _, field := range c.Header.fields {
		if err := binary.Write(&b, endian, field.tag); err != nil {
			return nil, err
		}

		if err := binary.Write(&b, endian, field.length); err != nil {
			return nil, err
		}

		if _, err := b.Write(field.value); err != nil {
			return nil, err
		}
	}

	return b.Bytes(), nil
}

func (c *CCache) writePrincipal(p principal, endian *binary.ByteOrder) ([]byte, error) {
	var b bytes.Buffer
	if c.Version != 1 { // version 1 has no name-type field.
		if err := binary.Write(&b, *endian, uint32(p.PrincipalName.NameType)); err != nil {
			return nil, err
		}
	}

	count := len(p.PrincipalName.NameString)
	if c.Version == 1 { // version 1 counts the realm as a component.
		count++
	}

	if err := binary.Write(&b, *endian, uint32(count)); err != nil {
		return nil, err
	}

	if err := writeData(&b, *endian, []byte(p.Realm)); err != nil {
		return nil, err
	}

	for _, part := range p.PrincipalName.NameString {
		if err := writeData(&b, *endian, []byte(part)); err != nil {
			return nil, err
		}
	}

	return b.Bytes(), nil
}

func (c *CCache) writeCredential(cred *Credential, endian *binary.ByteOrder) ([]byte, error) {
	var b bytes.Buffer

	if err := c.writePrincipalTo(&b, cred.Client, endian); err != nil {
		return nil, err
	}

	if err := c.writePrincipalTo(&b, cred.Server, endian); err != nil {
		return nil, err
	}

	if err := c.writeKeyblock(&b, cred.Key, endian); err != nil {
		return nil, err
	}

	for _, t := range []time.Time{cred.AuthTime, cred.StartTime, cred.EndTime, cred.RenewTill} {
		if err := binary.Write(&b, *endian, uint32(t.Unix())); err != nil {
			return nil, err
		}
	}

	isSKey := uint8(0)
	if cred.IsSKey {
		isSKey = 1
	}

	if err := binary.Write(&b, *endian, isSKey); err != nil {
		return nil, err
	}

	// Ticket flags are a fixed 4-byte field (parseCredential reads exactly 4
	// bytes). Emit 4 bytes regardless of TicketFlags.Bytes: a caller-built
	// credential may leave it nil or a non-4-byte length, and writing it raw
	// would misalign every following field.
	var flags [4]byte
	copy(flags[:], cred.TicketFlags.Bytes)
	if _, err := b.Write(flags[:]); err != nil {
		return nil, err
	}

	if err := writeAddresses(&b, *endian, cred.Addresses); err != nil {
		return nil, err
	}

	if err := writeAuthData(&b, *endian, cred.AuthData); err != nil {
		return nil, err
	}

	if err := writeData(&b, *endian, cred.Ticket); err != nil {
		return nil, err
	}

	if err := writeData(&b, *endian, cred.SecondTicket); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// writePrincipalTo serializes p and appends it to b.
func (c *CCache) writePrincipalTo(b *bytes.Buffer, p principal, endian *binary.ByteOrder) error {
	pb, err := c.writePrincipal(p, endian)
	if err != nil {
		return err
	}

	_, err = b.Write(pb)

	return err
}

// writeKeyblock serializes a credential's encryption key: a 16-bit key type
// (repeated as a second 16-bit value in version 3), then a length-prefixed key
// value. This mirrors parseCredential, which reads the key type as two 16-bit
// integers for version 3.
func (c *CCache) writeKeyblock(b *bytes.Buffer, key types.EncryptionKey, endian *binary.ByteOrder) error {
	if err := binary.Write(b, *endian, uint16(key.KeyType)); err != nil {
		return err
	}

	if c.Version == 3 {
		if err := binary.Write(b, *endian, uint16(key.KeyType)); err != nil {
			return err
		}
	}

	return writeData(b, *endian, key.KeyValue)
}

// writeAddresses serializes a credential's host addresses: a uint32 count
// followed by each address's 16-bit type and length-prefixed value.
func writeAddresses(b *bytes.Buffer, endian binary.ByteOrder, addrs []types.HostAddress) error {
	if err := binary.Write(b, endian, uint32(len(addrs))); err != nil {
		return err
	}

	for _, addr := range addrs {
		if err := binary.Write(b, endian, uint16(addr.AddrType)); err != nil {
			return err
		}

		if err := writeData(b, endian, addr.Address); err != nil {
			return err
		}
	}

	return nil
}

// writeAuthData serializes a credential's authorization data: a uint32 count
// followed by each entry's 16-bit type and length-prefixed data.
func writeAuthData(b *bytes.Buffer, endian binary.ByteOrder, ad []types.AuthorizationDataEntry) error {
	if err := binary.Write(b, endian, uint32(len(ad))); err != nil {
		return err
	}

	for _, entry := range ad {
		if err := binary.Write(b, endian, uint16(entry.ADType)); err != nil {
			return err
		}

		if err := writeData(b, endian, entry.ADData); err != nil {
			return err
		}
	}

	return nil
}

// writeData writes a uint32 length prefix followed by the data.
func writeData(b *bytes.Buffer, endian binary.ByteOrder, data []byte) error {
	if err := binary.Write(b, endian, uint32(len(data))); err != nil {
		return err
	}

	_, err := b.Write(data)

	return err
}

// getEndian mirrors Unmarshal's byte-order choice: versions 1 and 2 use the
// machine's native order; versions 3 and 4 are always big-endian.
func (c *CCache) getEndian() *binary.ByteOrder {
	var endian binary.ByteOrder = binary.BigEndian
	if (c.Version == 1 || c.Version == 2) && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}

	return &endian
}
