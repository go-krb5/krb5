package service

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/x/rpc/mstypes"

	"github.com/go-krb5/krb5/pac"
)

// TestADCredentialsNameTheServiceADelegatedTicketCameThrough: a ticket issued by S4U2Proxy carries the
// services it was obtained through, and the acceptor has to say so; a ticket of the principal's own
// carries none and says nothing.
func TestADCredentialsNameTheServiceADelegatedTicketCameThrough(t *testing.T) {
	t.Parallel()

	const (
		user     = "alice"
		frontEnd = "HTTP/app.example.com@EXAMPLE.COM"
	)

	var own pac.PACType

	own.KerbValidationInfo = &pac.KerbValidationInfo{EffectiveName: mstypes.RPCUnicodeString{Value: user}}

	ad := adCredentials(own)
	assert.Equal(t, user, ad.EffectiveName)
	assert.Empty(t, ad.DelegatedThrough)

	delegated := own
	delegated.S4UDelegationInfo = &pac.S4UDelegationInfo{
		S4U2proxyTarget:   mstypes.RPCUnicodeString{Value: "HTTP/registry.example.com@EXAMPLE.COM"},
		TransitedListSize: 1,
		S4UTransitedServices: []mstypes.RPCUnicodeString{
			{Value: frontEnd},
		},
	}

	ad = adCredentials(delegated)
	assert.Equal(t, user, ad.EffectiveName, "the principal is still the one authorized")
	assert.Equal(t, []string{frontEnd}, ad.DelegatedThrough)
}
