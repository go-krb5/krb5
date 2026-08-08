package credentials

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestMarshalRoundTrip(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err, "decode test data")

	c := new(CCache)
	require.NoError(t, c.Unmarshal(b), "unmarshal test ccache")

	marshalled, err := c.Marshal()
	require.NoError(t, err, "marshal ccache")

	assert.Equal(t, b, marshalled, "marshalled bytes must equal the original")
}

// TestMarshalRoundTripV3 guards the version-3 keyblock encoding, which parses
// the key type as two 16-bit integers. There is no v3 test vector, so this
// builds a cache, marshals it, and asserts the bytes survive an
// Unmarshal/Marshal round trip and that the key type is recovered intact. A
// width mismatch in the v3 keyblock would misalign the parser and fail here.
func TestMarshalRoundTripV3(t *testing.T) {
	t.Parallel()

	const (
		realm  = "TEST.GOKRB5"
		krbtgt = "krbtgt"
	)

	now := time.Unix(1700000000, 0)
	pn := types.PrincipalName{NameType: 1, NameString: []string{"testuser"}}
	c := &CCache{
		Version:          3,
		DefaultPrincipal: principal{Realm: realm, PrincipalName: pn},
	}
	c.AddCredential(&Credential{
		Client:      principal{Realm: realm, PrincipalName: pn},
		Server:      principal{Realm: realm, PrincipalName: types.PrincipalName{NameType: 2, NameString: []string{krbtgt, realm}}},
		Key:         types.EncryptionKey{KeyType: 18, KeyValue: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		AuthTime:    now,
		StartTime:   now,
		EndTime:     now,
		RenewTill:   now,
		TicketFlags: types.NewKrbFlags(),
		Ticket:      []byte{0xaa, 0xbb, 0xcc},
	})

	b, err := c.Marshal()
	require.NoError(t, err, "marshal v3 ccache")

	c2 := new(CCache)
	require.NoError(t, c2.Unmarshal(b), "unmarshal v3 ccache")

	b2, err := c2.Marshal()
	require.NoError(t, err, "re-marshal v3 ccache")

	assert.Equal(t, b, b2, "v3 marshal must survive an unmarshal/marshal round trip")
	require.Len(t, c2.Credentials, 1, "expected one credential")
	assert.Equal(t, int32(18), c2.Credentials[0].Key.KeyType, "v3 key type must round-trip")
}

// TestMarshalRoundTripUnsetTicketFlags guards the ticket-flags field width. The
// parser reads a fixed 4 bytes for ticket flags, so Marshal must always emit 4
// bytes even when a caller-built credential leaves TicketFlags unset (nil
// Bytes). Writing the raw Bytes instead would emit zero bytes here, shifting
// every following field by four and causing the parser to read a garbage
// authorization-data count — an out-of-range panic in readAuthDataEntry. This
// reproduces a caller-built v4 cache (empty AuthData, unset flags).
func TestMarshalRoundTripUnsetTicketFlags(t *testing.T) {
	t.Parallel()

	const realm = "TEST.GOKRB5"

	now := time.Unix(1700000000, 0)
	pn := types.PrincipalName{NameType: 1, NameString: []string{"testuser"}}
	c := NewV4CCache()
	c.SetDefaultPrincipal(principal{Realm: realm, PrincipalName: pn})
	c.AddCredential(&Credential{
		Client:    principal{Realm: realm, PrincipalName: pn},
		Server:    principal{Realm: realm, PrincipalName: types.PrincipalName{NameType: 2, NameString: []string{"krbtgt", realm}}},
		Key:       types.EncryptionKey{KeyType: 18, KeyValue: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		AuthTime:  now,
		StartTime: now,
		EndTime:   now,
		RenewTill: now,
		// TicketFlags deliberately left zero-value (nil Bytes).
		Ticket: []byte{0xaa, 0xbb, 0xcc},
	})

	b, err := c.Marshal()
	require.NoError(t, err, "marshal v4 ccache")

	c2 := new(CCache)
	require.NoError(t, c2.Unmarshal(b), "unmarshal v4 ccache")

	b2, err := c2.Marshal()
	require.NoError(t, err, "re-marshal v4 ccache")

	assert.Equal(t, b, b2, "marshal must survive an unmarshal/marshal round trip with unset ticket flags")
	require.Len(t, c2.Credentials, 1, "expected one credential")
	assert.Len(t, c2.Credentials[0].TicketFlags.Bytes, 4, "ticket flags must round-trip as a fixed 4 bytes")
	assert.Empty(t, c2.Credentials[0].AuthData, "authorization data must round-trip empty")
	assert.Equal(t, []byte{0xaa, 0xbb, 0xcc}, c2.Credentials[0].Ticket, "ticket bytes must round-trip intact")
}
