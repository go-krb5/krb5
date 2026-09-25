package credentials

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/identity"

	"github.com/go-krb5/krb5/types"
)

func TestImplementsInterface(t *testing.T) {
	t.Parallel()

	u := new(Credentials)
	i := new(identity.Identity)
	assert.Implements(t, i, u)
}

func TestCredentials_Marshal(t *testing.T) {
	var cred Credentials

	b, err := cred.Marshal()
	require.NoError(t, err)

	var credum Credentials

	require.NoError(t, credum.Unmarshal(b))
}

// TestDelegatedCredentialsShouldRoundTrip asserts the accessor pair an acceptor uses to hand a forwarded TGT to
// application code.
func TestDelegatedCredentialsShouldRoundTrip(t *testing.T) {
	t.Parallel()

	c := New("testuser1", "TEST.GOKRB5")

	cc, ok := c.DelegatedCredentials()
	assert.Nil(t, cc)
	assert.False(t, ok, "credentials with no delegation must report none")

	want := NewV4CCache()
	c.SetDelegatedCredentials(want)

	cc, ok = c.DelegatedCredentials()
	require.True(t, ok)
	assert.Same(t, want, cc)
}

func TestMarshalWithDelegatedCredentials(t *testing.T) {
	t.Parallel()

	c := New(delegatingUser, delegatingRealm)
	c.SetADCredentials(ADCredentials{EffectiveName: delegatingUser, UserID: 1234})
	c.SetDelegatedCredentials(delegatedCCache())

	b, err := c.Marshal()
	require.NoError(t, err)

	var back Credentials

	require.NoError(t, back.Unmarshal(b))
	assert.Equal(t, 1234, back.GetADCredentials().UserID)

	cc, ok := back.DelegatedCredentials()
	assert.Nil(t, cc)
	assert.False(t, ok)

	_, ok = c.DelegatedCredentials()
	assert.True(t, ok, "marshalling must not remove the delegated credentials from the original")
}

func TestMarshalLeavesOutTheDelegatedSessionKey(t *testing.T) {
	t.Parallel()

	c := New(delegatingUser, delegatingRealm)
	c.SetDelegatedCredentials(delegatedCCache())

	b, err := c.Marshal()
	require.NoError(t, err)

	assert.False(t, bytes.Contains(b, delegatedKey()))
}

const (
	delegatingUser  = "delegating-user"
	delegatingRealm = "TEST.GOKRB5"
)

func delegatedKey() []byte {
	return bytes.Repeat([]byte{0xd5}, 32)
}

func delegatedCCache() *CCache {
	cc := NewV4CCache()
	cc.AddCredential(&Credential{
		Key:    types.EncryptionKey{KeyType: 18, KeyValue: delegatedKey()},
		Ticket: []byte("forwarded TGT"),
	})

	return cc
}
