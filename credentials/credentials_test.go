package credentials

import (
	"testing"

	"github.com/go-krb5/x/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
