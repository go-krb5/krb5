package gssapi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Field widths and offsets of the GSS-API authenticator checksum described by RFC 4121 Section 4.1.1.
const (
	// ChecksumBndLgth is the value RFC 4121 Section 4.1.1 fixes in the four octet Lgth field at the start of the
	// checksum: the width of the Bnd field that follows it.
	ChecksumBndLgth = 16

	// ChecksumMinLen is the smallest checksum RFC 4121 Section 4.1.1 describes, holding Lgth, Bnd and Flags.
	ChecksumMinLen = 24

	// ChecksumDelegMinLen is the smallest checksum carrying delegation, adding the two octet DlgOpt and Dlgth
	// fields. RFC 4121 Section 4.1.1 requires "at least 28 octets plus Dlgth octets when GSS_C_DELEG_FLAG is set".
	ChecksumDelegMinLen = 28

	// ChecksumDlgOpt is the delegation option identifier RFC 4121 Section 4.1.1 fixes in DlgOpt.
	ChecksumDlgOpt = 1

	// ChecksumMaxDelegLen is the largest Deleg field this library will emit. The two octet Dlgth could express
	// 65535, but MIT Kerberos rejects credmsg.length+28 > KRB5_INT16_MAX in
	// lib/gssapi/krb5/init_sec_context.c, so a larger KRB_CRED is one no MIT acceptor is prepared to read. This is
	// an interoperability bound rather than a protocol one.
	ChecksumMaxDelegLen = 32767 - ChecksumDelegMinLen
)

// checksumFlagMask selects the flag values RFC 4121 Section 4.1.1.1 permits in the Flags field. Everything else is
// cleared on marshalling, because that section requires it: "Undefined flag values MUST be cleared by the sender,
// and unknown flags MUST be ignored by the receiver."
//
// Two ranges survive. The low bits are the six context establishment flags Section 4.1.1.1 names. Bits 12 to 19 are
// the range it reserves "for use with legacy vendor-specific extensions to this mechanism", which is where the
// Windows flags of RFC 4757 Section 7.1 live; GSS_C_DCE_STYLE (0x1000), GSS_C_IDENTIFY_FLAG (0x2000) and
// GSS_C_EXTENDED_ERROR_FLAG (0x4000), all three of which MS-KILE Section 3.2.5.2 has a client set in this very
// field, along with GSS_C_DELEG_POLICY_FLAG (0x8000) which MIT sets. Masking those away would break interoperation
// with both, so the whole reserved range passes through even though this library defines none of it.
//
// Clearing a flag here removes nothing a peer would have acted on, since the same sentence obliges receivers to
// ignore what they do not recognise. That is what separates this from a silent downgrade: the flag had no effect
// to lose. A caller is therefore not told, and Marshal does not fail.
//
// MIT masks in the same place and for the same reason, at lib/gssapi/krb5/init_sec_context.c, though its mask is
// narrower; it enumerates the three RFC 4757 flags rather than the whole reserved range; and it then ORs in
// GSS_C_TRANS_FLAG (0x100), which this mask clears because Section 4.1.1.1 defines no such value for this field.
const checksumFlagMask = ContextFlagDeleg | ContextFlagMutual | ContextFlagReplay |
	ContextFlagSequence | ContextFlagConf | ContextFlagInteg |
	0x000FF000

// ErrDelegationMissing is returned by Marshal when GSS_C_DELEG_FLAG is set in Flags but Deleg is empty. RFC 4121
// Section 4.1.1 makes DlgOpt, Dlgth and Deleg present if and only if the flag is set, so the two cannot disagree.
// Emitting the flag with those fields zeroed is what MIT rejects with GSS_S_FAILURE on reading DlgOpt as 0.
var ErrDelegationMissing = errors.New("delegation flag set without a delegated credential")

// ErrDelegationTooLarge is returned by Marshal when Deleg exceeds ChecksumMaxDelegLen.
var ErrDelegationTooLarge = errors.New("delegated credential too large")

// ErrDelegationMalformed is returned by Unmarshal when a checksum claims delegation but the fields carrying it
// cannot be read. Callers match against it with errors.Is.
var ErrDelegationMalformed = errors.New("malformed delegation in authenticator checksum")

// ChecksumLgthError reports a checksum whose Lgth field declares a Bnd width other than the 16 RFC 4121 Section
// 4.1.1 fixes. Lgth is the width of Bnd, so any other value moves Flags and every field after it: the layout
// cannot be interpreted at all, not merely its Bnd. Reading the documented offsets anyway would report whatever
// happened to sit there as though it were the real Flags.
type ChecksumLgthError struct {
	Lgth uint32
}

// Error describes the offending length.
func (e ChecksumLgthError) Error() string {
	return fmt.Sprintf("declares a Bnd length of %d rather than %d", e.Lgth, ChecksumBndLgth)
}

// AuthenticatorChecksum is the GSS-API authenticator checksum of RFC 4121 Section 4.1.1, carried in the AP_REQ
// authenticator under checksum type chksumtype.GSSAPI. It conveys the context establishment flags, the channel
// bindings hash, and optionally a delegated credential.
//
//	Octet          Field   Meaning
//	0..3           Lgth    octets in Bnd; always ChecksumBndLgth
//	4..19          Bnd     MD5 of the RFC 1964 Section 1.1.1 channel bindings structure
//	20..23         Flags   context establishment flags, little-endian
//	24..25         DlgOpt  ChecksumDlgOpt; present if and only if GSS_C_DELEG_FLAG is set
//	26..27         Dlgth   length of Deleg; present if and only if GSS_C_DELEG_FLAG is set
//	28..28+Dlgth   Deleg   a KRB_CRED message
//	trailing       Exts    extensions
//
// Every integer is little-endian.
type AuthenticatorChecksum struct {
	// Bnd is the channel bindings hash. Sixteen zero bytes mean no channel bindings.
	Bnd [16]byte

	// Flags are the context establishment flags. GSS_C_DELEG_FLAG is derived from Deleg by Marshal.
	Flags uint32

	// Deleg is a marshalled KRB_CRED, or nil when no credential is delegated.
	Deleg []byte

	// Exts is carried verbatim and never interpreted. RFC 4121 Section 4.1.1 requires that acceptors which do not
	// understand the extensions ignore any octets past Deleg, so they are preserved rather than rejected.
	Exts []byte
}

// Delegated reports whether GSS_C_DELEG_FLAG is set in Flags.
func (c *AuthenticatorChecksum) Delegated() bool {
	return c.Flags&ContextFlagDeleg != 0
}

// Marshal returns the checksum in the RFC 4121 Section 4.1.1 layout.
//
// The delegation flag is derived from Deleg rather than trusted from Flags: a non-empty Deleg sets it, and the flag
// set with an empty Deleg returns ErrDelegationMissing. That is the malformed checksum this type exists to make
// unrepresentable. Clearing the flag instead would be a silent downgrade the caller could not observe.
//
// Flags outside the set RFC 4121 Section 4.1.1.1 permits are cleared, as that section requires of senders. See
// checksumFlagMask for which survive and why clearing them costs a caller nothing.
func (c *AuthenticatorChecksum) Marshal() ([]byte, error) {
	flags := c.Flags & checksumFlagMask

	switch {
	case len(c.Deleg) > ChecksumMaxDelegLen:
		return nil, fmt.Errorf("%w: %d octets exceeds the %d octet interoperable maximum",
			ErrDelegationTooLarge, len(c.Deleg), ChecksumMaxDelegLen)
	case len(c.Deleg) > 0:
		flags |= ContextFlagDeleg
	case flags&ContextFlagDeleg != 0:
		return nil, fmt.Errorf("%w: RFC 4121 Section 4.1.1 makes DlgOpt, Dlgth and Deleg present if and only if GSS_C_DELEG_FLAG is set", ErrDelegationMissing)
	}

	n := ChecksumMinLen
	if len(c.Deleg) > 0 {
		n = ChecksumDelegMinLen + len(c.Deleg)
	}

	b := make([]byte, n, n+len(c.Exts))

	binary.LittleEndian.PutUint32(b[:4], ChecksumBndLgth)
	copy(b[4:20], c.Bnd[:])
	binary.LittleEndian.PutUint32(b[20:24], flags)

	if len(c.Deleg) > 0 {
		binary.LittleEndian.PutUint16(b[24:26], ChecksumDlgOpt)
		//nolint:gosec // G115: len(c.Deleg) is bounded by ChecksumMaxDelegLen in the switch above.
		binary.LittleEndian.PutUint16(b[26:28], uint16(len(c.Deleg)))
		copy(b[ChecksumDelegMinLen:], c.Deleg)
	}

	return append(b, c.Exts...), nil
}

// Unmarshal parses the checksum, resetting the receiver first.
//
// Its strictness is deliberately asymmetric. A checksum too short to hold Lgth, Bnd and Flags leaves the receiver
// zeroed and returns no error, because acceptors parse every checksum in order to discover whether delegation is
// claimed and parsing more often must not reject more often: whether an uninterpretable checksum matters is the
// caller's decision, not this parser's. Once the checksum is long enough and claims delegation, every defect in the
// delegation fields is an error.
func (c *AuthenticatorChecksum) Unmarshal(b []byte) error {
	*c = AuthenticatorChecksum{}

	if len(b) < ChecksumMinLen {
		return nil
	}

	if lgth := binary.LittleEndian.Uint32(b[:4]); lgth != ChecksumBndLgth {
		return ChecksumLgthError{Lgth: lgth}
	}

	copy(c.Bnd[:], b[4:20])
	c.Flags = binary.LittleEndian.Uint32(b[20:24])

	rest := b[ChecksumMinLen:]

	if c.Delegated() {
		if len(b) < ChecksumDelegMinLen {
			return fmt.Errorf("%w: %d octets is too short to carry the delegation fields", ErrDelegationMalformed, len(b))
		}

		if opt := binary.LittleEndian.Uint16(b[24:26]); opt != ChecksumDlgOpt {
			return fmt.Errorf("%w: carries delegation option identifier %d rather than %d",
				ErrDelegationMalformed, opt, ChecksumDlgOpt)
		}

		dlgth := int(binary.LittleEndian.Uint16(b[26:28]))
		if ChecksumDelegMinLen+dlgth > len(b) {
			return fmt.Errorf("%w: declares a Deleg length of %d with only %d octets remaining",
				ErrDelegationMalformed, dlgth, len(b)-ChecksumDelegMinLen)
		}

		c.Deleg = bytes.Clone(b[ChecksumDelegMinLen : ChecksumDelegMinLen+dlgth])
		rest = b[ChecksumDelegMinLen+dlgth:]
	}

	if len(rest) > 0 {
		c.Exts = bytes.Clone(rest)
	}

	return nil
}
