package gssapi

import "github.com/go-krb5/x/encoding/asn1"

// GSS-API context flags assigned numbers.
const (
	ContextFlagDeleg    = 1
	ContextFlagMutual   = 2
	ContextFlagReplay   = 4
	ContextFlagSequence = 8
	ContextFlagConf     = 16
	ContextFlagInteg    = 32
	ContextFlagAnon     = 64

	// ContextFlagDelegPolicy requests delegation only where the KDC has said the service may receive it, by
	// setting OK-AS-DELEGATE on the service ticket. It is not an IANA assignment: it originates with Microsoft's
	// SSPI and is implemented by MIT, and its value falls in the 4096 to 524288 range RFC 4121 Section 4.1.1.1
	// reserves for legacy vendor-specific extensions, which is why the authenticator checksum may carry it.
	ContextFlagDelegPolicy = 0x8000
)

// ContextFlags flags for GSSAPI
// DEPRECATED - do not use.
type ContextFlags asn1.BitString

// NewContextFlags creates a new ContextFlags instance
// DEPRECATED - do not use.
func NewContextFlags() ContextFlags {
	var c ContextFlags

	c.BitLength = 32
	c.Bytes = make([]byte, 4)

	return c
}
