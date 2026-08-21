package credentials

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/types"
)

const (
	headerFieldTagKDCOffset = 1
)

// CCache is the file credentials cache as define here: https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
type CCache struct {
	Version          uint8
	Header           header
	DefaultPrincipal principal
	Credentials      []*Credential
	Path             string
}

type header struct {
	length uint16
	fields []headerField
}

type headerField struct {
	tag    uint16
	length uint16
	value  []byte
}

// Credential cache entry principal struct.
type principal struct {
	Realm         string
	PrincipalName types.PrincipalName
}

// Credential holds a Kerberos client's ccache credential information.
type Credential struct {
	Client       principal
	Server       principal
	Key          types.EncryptionKey
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	IsSKey       bool
	TicketFlags  asn1.BitString
	Addresses    []types.HostAddress
	AuthData     []types.AuthorizationDataEntry
	Ticket       []byte
	SecondTicket []byte
}

// LoadCCache loads a credential cache file into a CCache type.
func LoadCCache(cpath string) (*CCache, error) {
	c := new(CCache)

	b, err := os.ReadFile(cpath)
	if err != nil {
		return c, err
	}

	if len(b) < 10 {
		return c, errors.New("Invalid credential cache data: file too short")
	}

	err = c.Unmarshal(b)

	return c, err
}

// Unmarshal a byte slice of credential cache data into CCache type.
func (c *CCache) Unmarshal(b []byte) error {
	p := 0

	// A credential cache is read from a path the process does not necessarily control, and this method is
	// exported for arbitrary bytes. Every length and count below is taken from the data itself, so none of them
	// is trusted to index it.
	if len(b) < 2 {
		return fmt.Errorf("invalid credential cache data: %d bytes is shorter than the two byte version header", len(b))
	}

	if int8(b[p]) != 5 {
		return errors.New("Invalid credential cache data. First byte does not equal 5")
	}

	p++

	c.Version = b[p]
	if c.Version < 1 || c.Version > 4 {
		return errors.New("Invalid credential cache data. Keytab version is not within 1 to 4")
	}

	p++

	var endian binary.ByteOrder

	endian = binary.BigEndian
	if (c.Version == 1 || c.Version == 2) && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}

	if c.Version == 4 {
		err := parseHeader(b, &p, c, &endian)
		if err != nil {
			return err
		}
	}

	var err error

	if c.DefaultPrincipal, err = parsePrincipal(b, &p, c, &endian); err != nil {
		return err
	}

	for p < len(b) {
		cred, err := parseCredential(b, &p, c, &endian)
		if err != nil {
			return err
		}

		c.Credentials = append(c.Credentials, cred)
	}

	return nil
}

func parseHeader(b []byte, p *int, c *CCache, e *binary.ByteOrder) error {
	if c.Version != 4 {
		return errors.New("Credentials cache version is not 4 so there is no header to parse.")
	}

	h := header{}

	l, err := readInt16(b, p, e)
	if err != nil {
		return err
	}

	h.length = uint16(l)

	endOfHeader := *p + int(h.length)
	if endOfHeader > len(b) {
		return fmt.Errorf("credential cache header of %d bytes extends beyond the %d bytes available", h.length, len(b)-*p)
	}

	for *p <= endOfHeader-4 {
		f := headerField{}

		t, err := readInt16(b, p, e)
		if err != nil {
			return err
		}

		f.tag = uint16(t)

		fl, err := readInt16(b, p, e)
		if err != nil {
			return err
		}

		f.length = uint16(fl)

		if *p+int(f.length) > endOfHeader {
			return errors.New("credential cache header field extends beyond buffer")
		}

		f.value = b[*p : *p+int(f.length)]

		*p += int(f.length)
		if !f.valid() {
			return errors.New("Invalid credential cache header found")
		}

		h.fields = append(h.fields, f)
	}
	*p = endOfHeader

	c.Header = h

	return nil
}

// Parse the Keytab bytes of a principal into a Keytab entry's principal.
func parsePrincipal(b []byte, p *int, c *CCache, e *binary.ByteOrder) (princ principal, err error) {
	if c.Version != 1 {
		// Name Type is omitted in version 1.
		if princ.PrincipalName.NameType, err = readInt32(b, p, e); err != nil {
			return princ, err
		}
	}

	n, err := readInt32(b, p, e)
	if err != nil {
		return princ, err
	}

	nc := int(n)
	if c.Version == 1 {
		// In version 1 the number of components includes the realm. Minus 1 to make consistent with version 2.
		nc--
	}

	if nc < 0 {
		return princ, fmt.Errorf("credential cache principal declares %d name components", nc)
	}

	realm, err := readData(b, p, e)
	if err != nil {
		return princ, err
	}

	princ.Realm = string(realm)

	// The components are appended rather than pre-allocated from nc, so that a count larger than the remaining
	// data can supply fails on the first read past the end instead of sizing an allocation of its own choosing.
	for i := 0; i < nc; i++ {
		comp, err := readData(b, p, e)
		if err != nil {
			return princ, err
		}

		princ.PrincipalName.NameString = append(princ.PrincipalName.NameString, string(comp))
	}

	return princ, nil
}

func parseCredential(b []byte, p *int, c *CCache, e *binary.ByteOrder) (cred *Credential, err error) {
	cred = new(Credential)

	if cred.Client, err = parsePrincipal(b, p, c, e); err != nil {
		return nil, err
	}

	if cred.Server, err = parsePrincipal(b, p, c, e); err != nil {
		return nil, err
	}

	key := types.EncryptionKey{}

	kt, err := readInt16(b, p, e)
	if err != nil {
		return nil, err
	}

	key.KeyType = int32(kt)

	if c.Version == 3 {
		if kt, err = readInt16(b, p, e); err != nil {
			return nil, err
		}

		key.KeyType = int32(kt)
	}

	if key.KeyValue, err = readData(b, p, e); err != nil {
		return nil, err
	}

	cred.Key = key

	for _, t := range []*time.Time{&cred.AuthTime, &cred.StartTime, &cred.EndTime, &cred.RenewTill} {
		if *t, err = readTimestamp(b, p, e); err != nil {
			return nil, err
		}
	}

	ik, err := readInt8(b, p, e)
	if err != nil {
		return nil, err
	}

	cred.IsSKey = ik != 0

	cred.TicketFlags = types.NewKrbFlags()
	if cred.TicketFlags.Bytes, err = readBytes(b, p, 4, e); err != nil {
		return nil, err
	}

	// The addresses and authorization data are appended rather than pre-allocated from their counts. Both counts
	// are read from the cache, and the largest asks for a slice of two billion elements; appending makes an
	// unsatisfiable count fail on the first read past the end instead.
	l, err := readInt32(b, p, e)
	if err != nil {
		return nil, err
	}

	if l < 0 {
		return nil, fmt.Errorf("credential cache credential declares %d addresses", l)
	}

	for i := 0; i < int(l); i++ {
		a, err := readAddress(b, p, e)
		if err != nil {
			return nil, err
		}

		cred.Addresses = append(cred.Addresses, a)
	}

	if l, err = readInt32(b, p, e); err != nil {
		return nil, err
	}

	if l < 0 {
		return nil, fmt.Errorf("credential cache credential declares %d authorization data entries", l)
	}

	for i := 0; i < int(l); i++ {
		ad, err := readAuthDataEntry(b, p, e)
		if err != nil {
			return nil, err
		}

		cred.AuthData = append(cred.AuthData, ad)
	}

	if cred.Ticket, err = readData(b, p, e); err != nil {
		return nil, err
	}

	if cred.SecondTicket, err = readData(b, p, e); err != nil {
		return nil, err
	}

	return cred, nil
}

// GetClientPrincipalName returns a PrincipalName type for the client the credentials cache is for.
func (c *CCache) GetClientPrincipalName() types.PrincipalName {
	return c.DefaultPrincipal.PrincipalName
}

// GetClientRealm returns the reals of the client the credentials cache is for.
func (c *CCache) GetClientRealm() string {
	return c.DefaultPrincipal.Realm
}

// GetClientCredentials returns a Credentials object representing the client of the credentials cache.
func (c *CCache) GetClientCredentials() *Credentials {
	return &Credentials{
		username: c.DefaultPrincipal.PrincipalName.PrincipalNameString(),
		realm:    c.GetClientRealm(),
		cname:    c.DefaultPrincipal.PrincipalName,
	}
}

// Contains tests if the cache contains a credential for the provided server PrincipalName.
func (c *CCache) Contains(p types.PrincipalName) bool {
	for _, cred := range c.Credentials {
		if cred.Server.PrincipalName.Equal(p) {
			return true
		}
	}

	return false
}

// GetEntry returns a specific credential for the PrincipalName provided.
func (c *CCache) GetEntry(p types.PrincipalName) (*Credential, bool) {
	cred := new(Credential)

	var found bool

	for i := range c.Credentials {
		if c.Credentials[i].Server.PrincipalName.Equal(p) {
			cred = c.Credentials[i]
			found = true

			break
		}
	}

	if !found {
		return cred, false
	}

	return cred, true
}

// GetEntries filters out configuration entries an returns a slice of credentials.
func (c *CCache) GetEntries() []*Credential {
	creds := make([]*Credential, 0)

	for _, cred := range c.Credentials {
		// Filter out configuration entries.
		if strings.HasPrefix(cred.Server.Realm, "X-CACHECONF") {
			continue
		}

		creds = append(creds, cred)
	}

	return creds
}

// Reference: https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
func (h *headerField) valid() bool {
	switch h.tag {
	case headerFieldTagKDCOffset:
		if h.length != 8 || len(h.value) != 8 {
			return false
		}

		return true
	}

	return false
}

// readData reads a length prefixed byte string.
func readData(b []byte, p *int, e *binary.ByteOrder) ([]byte, error) {
	l, err := readInt32(b, p, e)
	if err != nil {
		return nil, err
	}

	return readBytes(b, p, int(l), e)
}

func readAddress(b []byte, p *int, e *binary.ByteOrder) (types.HostAddress, error) {
	a := types.HostAddress{}

	t, err := readInt16(b, p, e)
	if err != nil {
		return a, err
	}

	a.AddrType = int32(t)

	if a.Address, err = readData(b, p, e); err != nil {
		return a, err
	}

	return a, nil
}

func readAuthDataEntry(b []byte, p *int, e *binary.ByteOrder) (types.AuthorizationDataEntry, error) {
	a := types.AuthorizationDataEntry{}

	t, err := readInt16(b, p, e)
	if err != nil {
		return a, err
	}

	a.ADType = int32(t)

	if a.ADData, err = readData(b, p, e); err != nil {
		return a, err
	}

	return a, nil
}

// Read bytes representing a timestamp.
func readTimestamp(b []byte, p *int, e *binary.ByteOrder) (time.Time, error) {
	i, err := readInt32(b, p, e)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(int64(i), 0), nil
}

// Read bytes representing an eight bit integer.
func readInt8(b []byte, p *int, e *binary.ByteOrder) (i int8, err error) {
	if err = checkBounds(b, *p, 1); err != nil {
		return 0, err
	}

	buf := bytes.NewBuffer(b[*p : *p+1])
	if err = binary.Read(buf, *e, &i); err != nil {
		return 0, err
	}

	*p++

	return i, nil
}

// Read bytes representing a sixteen bit integer.
func readInt16(b []byte, p *int, e *binary.ByteOrder) (i int16, err error) {
	if err = checkBounds(b, *p, 2); err != nil {
		return 0, err
	}

	buf := bytes.NewBuffer(b[*p : *p+2])
	if err = binary.Read(buf, *e, &i); err != nil {
		return 0, err
	}

	*p += 2

	return i, nil
}

// Read bytes representing a thirty two bit integer.
func readInt32(b []byte, p *int, e *binary.ByteOrder) (i int32, err error) {
	if err = checkBounds(b, *p, 4); err != nil {
		return 0, err
	}

	buf := bytes.NewBuffer(b[*p : *p+4])
	if err = binary.Read(buf, *e, &i); err != nil {
		return 0, err
	}

	*p += 4

	return i, nil
}

func readBytes(b []byte, p *int, s int, e *binary.ByteOrder) ([]byte, error) {
	if err := checkBounds(b, *p, s); err != nil {
		return nil, err
	}

	r := make([]byte, s)
	copy(r, b[*p:*p+s])

	*p += s

	return r, nil
}

// checkBounds reports whether n bytes can be read from b at offset p.
func checkBounds(b []byte, p, n int) error {
	if p < 0 || n < 0 {
		return fmt.Errorf("invalid credential cache data: cannot read %d bytes at offset %d", n, p)
	}

	if n > len(b)-p {
		return fmt.Errorf("invalid credential cache data: %d bytes needed at offset %d but only %d remain",
			n, p, len(b)-p)
	}

	return nil
}

// TODO: Investigate why this is used and determine if it's necessary and safe.
func isNativeEndianLittle() bool {
	var (
		x  = 0x012345678
		p  = unsafe.Pointer(&x)
		bp = (*[4]byte)(p)
	)

	var endian bool

	if bp[0]&0xff == 0x78&0xff {
		endian = true
	}

	return endian
}
