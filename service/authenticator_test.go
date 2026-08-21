package service

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/identity"
)

func TestImplementsInterface(t *testing.T) {
	t.Parallel()
	// s := new(SPNEGOAuthenticator).
	var s KRB5BasicAuthenticator

	a := new(identity.Authenticator)
	assert.Implements(t, a, s)
}

func TestParseBasicHeaderValue(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		value    string
		domain   string
		username string
		password string
		err      bool
	}{
		{name: "username only", value: "testuser:passwd", username: "testuser", password: "passwd"},
		{name: "domain qualified", value: `TEST.GOKRB5\testuser:passwd`, domain: "TEST.GOKRB5", username: "testuser", password: "passwd"},
		{name: "user principal name", value: "testuser@TEST.GOKRB5:passwd", domain: "TEST.GOKRB5", username: "testuser", password: "passwd"},
		{name: "password containing a colon", value: "testuser:pass:wd", username: "testuser", password: "pass:wd"},
		{name: "empty password", value: "testuser:", username: "testuser"},
		{name: "no colon", value: "nocolonhere", err: true},
		{name: "empty", value: "", err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.NotPanics(t, func() {
				domain, username, password, err := parseBasicHeaderValue(base64.StdEncoding.EncodeToString([]byte(tc.value)))

				if tc.err {
					assert.Error(t, err)
					return
				}

				require.NoError(t, err)
				assert.Equal(t, tc.domain, domain)
				assert.Equal(t, tc.username, username)
				assert.Equal(t, tc.password, password)
			})
		})
	}
}
