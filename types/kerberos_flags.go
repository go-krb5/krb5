package types

// Reference: https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.8

import (
	"github.com/go-krb5/x/encoding/asn1"
)

// NewKrbFlags returns an ASN1 BitString struct of the right size for KrbFlags.
func NewKrbFlags() asn1.BitString {
	f := asn1.BitString{}
	f.Bytes = make([]byte, 4)
	f.BitLength = len(f.Bytes) * 8

	return f
}

// SetFlags sets the flags of an ASN1 BitString.
func SetFlags(f *asn1.BitString, j []int) {
	for _, i := range j {
		SetFlag(f, i)
	}
}

// SetFlag sets a flag in an ASN1 BitString.
//
// The BitString is grown to hold the flag, so any i within the KrbFlags range of RFC 4120 Section 5.2.8 can be set
// on a zero value. A negative i is ignored: it names no bit, and the index it would compute is out of range.
func SetFlag(f *asn1.BitString, i int) {
	if i < 0 {
		return
	}

	b := i / 8
	p := uint(7 - (i - 8*b))

	for l := len(f.Bytes); l < b+1 || l < 4; l++ {
		f.Bytes = append(f.Bytes, byte(0))
		f.BitLength = len(f.Bytes) * 8
	}

	f.Bytes[b] |= 1 << p
}

// UnsetFlags unsets flags in an ASN1 BitString.
func UnsetFlags(f *asn1.BitString, j []int) {
	for _, i := range j {
		UnsetFlag(f, i)
	}
}

// UnsetFlag unsets a flag in an ASN1 BitString.
//
// A flag beyond the end of the BitString is already unset, so it is left alone rather than growing the string to
// clear a bit that is not there.
func UnsetFlag(f *asn1.BitString, i int) {
	if i < 0 {
		return
	}

	for l := len(f.Bytes); l < 4; l++ {
		f.Bytes = append(f.Bytes, byte(0))
		f.BitLength = len(f.Bytes) * 8
	}

	b := i / 8
	p := uint(7 - (i - 8*b))

	if b >= len(f.Bytes) {
		return
	}

	f.Bytes[b] = f.Bytes[b] &^ (1 << p)
}

// IsFlagSet tests if a flag is set in the ASN1 BitString.
//
// A BitString too short to hold the flag reports it unset rather than indexing past its end. BIT STRING is a
// variable length type and its length is decided by whoever encoded it: a KrbCredInfo delegated by a peer, for
// instance, reaches credentials.Credential.TicketFlags with whatever length the peer sent, including none at all.
// A flag that was never encoded is not set.
func IsFlagSet(f *asn1.BitString, i int) bool {
	if i < 0 {
		return false
	}

	b := i / 8
	p := uint(7 - (i - 8*b))

	if b >= len(f.Bytes) {
		return false
	}

	return f.Bytes[b]&(1<<p) != 0
}
