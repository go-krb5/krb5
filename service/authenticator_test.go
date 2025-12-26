package service

import (
	"testing"

	"github.com/go-krb5/x/identity"
	"github.com/stretchr/testify/assert"
)

func TestImplementsInterface(t *testing.T) {
	t.Parallel()
	// s := new(SPNEGOAuthenticator).
	var s KRB5BasicAuthenticator

	a := new(identity.Authenticator)
	assert.Implements(t, a, s, "SPNEGOAuthenticator type does not implement the goidentity.Authenticator interface")
}
