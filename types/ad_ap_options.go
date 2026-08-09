package types

import (
	"encoding/binary"
	"fmt"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/iana/adtype"
)

// KILE AP option bit flags, carried in the AD-AUTH-DATA-AP-OPTIONS authorization data of MS-KILE Section 2.2.5.
const (
	// ADAPOptionsCBT indicates that the client expects the applications running on it to include channel binding
	// information in AP requests whenever Kerberos authentication takes place over an outer channel such as TLS.
	// It says nothing about whether this particular request carries a binding.
	ADAPOptionsCBT uint32 = 0x4000

	// ADAPOptionsUnverifiedTargetName indicates the client could not verify the service principal name it is
	// authenticating to. This library never sets it and is declared for completeness of MS-KILE Section 2.2.5.
	ADAPOptionsUnverifiedTargetName uint32 = 0x8000
)

// adAPOptionsLen is the width MS-KILE Section 3.2.5.2 fixes for the value: four octets, little-endian.
const adAPOptionsLen = 4

// ADAPOptions is the value of the AD-AUTH-DATA-AP-OPTIONS authorization data described by MS-KILE Section 2.2.5.
//
// The zero value means the peer sent no such element, which for ADAPOptionsCBT is the state a Kerberos
// implementation predating KILE's channel binding support is in. It is not a claim that the peer rejects channel
// bindings.
type ADAPOptions uint32

// UnmarshalADAPOptions reads the four octet little-endian value.
func UnmarshalADAPOptions(b []byte) (ADAPOptions, error) {
	if len(b) != adAPOptionsLen {
		return 0, fmt.Errorf("AD-AUTH-DATA-AP-OPTIONS is %d octets rather than %d", len(b), adAPOptionsLen)
	}

	return ADAPOptions(binary.LittleEndian.Uint32(b)), nil
}

// Marshal returns the four octet little-endian encoding.
func (o ADAPOptions) Marshal() []byte {
	b := make([]byte, adAPOptionsLen)
	binary.LittleEndian.PutUint32(b, uint32(o))

	return b
}

// Has reports whether the option given is set.
func (o ADAPOptions) Has(opt uint32) bool {
	return uint32(o)&opt != 0
}

// AuthorizationData wraps the options in the AD-IF-RELEVANT element MS-KILE Section 3.2.5.2 requires: "the client
// sends the Authorization Data Type AD-AUTH-DATA-AP-OPTIONS (143) data in the first AD-IF-RELEVANT element".
//
// AD-IF-RELEVANT is the right container because RFC 4120 Section 5.2.6.1 lets a receiver that does not understand
// the enclosed elements ignore them, which is what any non-KILE acceptor will do with these.
func (o ADAPOptions) AuthorizationData() (AuthorizationData, error) {
	inner := AuthorizationData{
		{ADType: adtype.ADAuthDataAPOptions, ADData: o.Marshal()},
	}

	b, err := asn1.Marshal(inner, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, fmt.Errorf("error marshalling AD-AUTH-DATA-AP-OPTIONS: %w", err)
	}

	return AuthorizationData{{ADType: adtype.ADIfRelevant, ADData: b}}, nil
}

// ADAPOptionsFromAuthorizationData returns the KILE AP options an authenticator carries, or zero when it carries
// none.
//
// Both the AD-IF-RELEVANT nesting MS-KILE specifies and a bare top level entry are accepted, because the value is
// read to learn what a peer supports rather than to make an authorization decision, and a peer that placed it one
// level out has still told us the same thing. A malformed entry is treated as absent for the same reason.
func ADAPOptionsFromAuthorizationData(ad AuthorizationData) ADAPOptions {
	for _, e := range ad {
		switch e.ADType {
		case adtype.ADAuthDataAPOptions:
			if o, err := UnmarshalADAPOptions(e.ADData); err == nil {
				return o
			}
		case adtype.ADIfRelevant:
			var inner AuthorizationData

			if _, err := asn1.Unmarshal(e.ADData, &inner); err != nil {
				continue
			}

			if o := ADAPOptionsFromAuthorizationData(inner); o != 0 {
				return o
			}
		}
	}

	return 0
}
