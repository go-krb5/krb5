package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/identity"
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
