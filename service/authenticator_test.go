package service

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/x/identity"
)

func TestImplementsInterface(t *testing.T) {
	t.Parallel()
	// s := new(SPNEGOAuthenticator).
	var s KRB5BasicAuthenticator

	a := new(identity.Authenticator)
	assert.Implements(t, a, s)
}
