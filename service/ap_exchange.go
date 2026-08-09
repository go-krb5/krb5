package service

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/messages"
)

// VerifyAPREQ verifies an AP_REQ sent to the service. Returns a boolean for if the AP_REQ is valid and the client's principal name and realm.
func VerifyAPREQ(APReq *messages.APReq, s *Settings) (bool, *credentials.Credentials, error) {
	var creds *credentials.Credentials

	ok, err := APReq.Verify(s.Keytab, s.MaxClockSkew(), s.ClientAddress(), s.KeytabPrincipal())
	if err != nil || !ok {
		return false, creds, err
	}

	if s.RequireHostAddr() && len(APReq.Ticket.DecryptedEncPart.CAddr) < 1 {
		return false, creds,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "ticket does not contain HostAddress values required")
	}

	if cb := s.RequireChannelBinding(); cb != nil {
		if err = verifyChannelBinding(APReq, cb); err != nil {
			return false, creds, err
		}
	}

	// Check for replay.
	rc := GetReplayCache(s.MaxClockSkew())
	if rc.IsReplay(APReq.Ticket.SName, APReq.Authenticator) {
		return false, creds,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_REPEAT, "replay detected")
	}

	c := credentials.NewFromPrincipalName(APReq.Ticket.DecryptedEncPart.CName, APReq.Ticket.DecryptedEncPart.CRealm)
	creds = c
	creds.SetAuthTime(time.Now().UTC())
	creds.SetAuthenticated(true)
	creds.SetValidUntil(APReq.Ticket.DecryptedEncPart.EndTime)

	// PAC decoding.
	if !s.disablePACDecoding {
		isPAC, pac, err := APReq.Ticket.GetPACType(s.Keytab, s.KeytabPrincipal(), s.Logger())
		if isPAC && err != nil {
			return false, creds, err
		}

		if isPAC {
			// There is a valid PAC. Adding attributes to creds.
			creds.SetADCredentials(credentials.ADCredentials{
				GroupMembershipSIDs: pac.KerbValidationInfo.GetGroupMembershipSIDs(),
				LogOnTime:           pac.KerbValidationInfo.LogOnTime.Time(),
				LogOffTime:          pac.KerbValidationInfo.LogOffTime.Time(),
				PasswordLastSet:     pac.KerbValidationInfo.PasswordLastSet.Time(),
				EffectiveName:       pac.KerbValidationInfo.EffectiveName.Value,
				FullName:            pac.KerbValidationInfo.FullName.Value,
				UserID:              int(pac.KerbValidationInfo.UserID),
				PrimaryGroupID:      int(pac.KerbValidationInfo.PrimaryGroupID),
				LogonServer:         pac.KerbValidationInfo.LogonServer.Value,
				LogonDomainName:     pac.KerbValidationInfo.LogonDomainName.Value,
				LogonDomainID:       pac.KerbValidationInfo.LogonDomainID.String(),
			})
		}
	}

	return true, creds, nil
}

// ErrBadChannelBinding identifies a channel binding verification failure. RFC 2743 Section 2.2.2 gives this failure
// its own GSS-API major status, GSS_S_BAD_BINDINGS, which is deliberately distinct from a defective token: it tells
// the initiator that its credential was sound but was presented over a channel the acceptor is not bound to, which
// is the difference between "retry" and "you may be talking to a man in the middle". Callers translating an AP_REQ
// failure into a GSS-API status match against this with errors.Is.
var ErrBadChannelBinding = errors.New("bad channel binding")

// badChannelBindingError joins ErrBadChannelBinding to the KRB_ERROR describing the failure. Both are exposed
// through Unwrap so that a caller can classify the failure with errors.Is and still recover the KRB_ERROR to send on
// the wire with errors.As. KRB_AP_ERR_BADMATCH is reused for the wire error because RFC 4120 defines no code for bad
// channel bindings; the distinction that matters to the initiator is carried by the GSS-API status.
type badChannelBindingError struct {
	krberr messages.KRBError
}

// Error returns the description of the underlying KRB_ERROR.
func (e badChannelBindingError) Error() string {
	return e.krberr.Error()
}

// Unwrap exposes the sentinel and the KRB_ERROR so that errors.Is(err, ErrBadChannelBinding) and
// errors.As(err, &messages.KRBError{}) both succeed.
func (e badChannelBindingError) Unwrap() []error {
	return []error{ErrBadChannelBinding, e.krberr}
}

// newBadChannelBindingError builds the error returned when channel binding verification fails.
func newBadChannelBindingError(APReq *messages.APReq, etext string) error {
	return badChannelBindingError{
		krberr: messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADMATCH, etext),
	}
}

// authenticatorChksumBndLgth is the value RFC 4121 Section 4.1.1 fixes in the four octet little-endian Lgth field at
// the start of the GSS-API authenticator checksum: the width of the Bnd field that follows it.
const authenticatorChksumBndLgth = 16

// authenticatorChksumMinLen is the smallest GSS-API authenticator checksum RFC 4121 Section 4.1.1 describes, holding
// Lgth, Bnd and Flags. The delegation and extension fields beyond it are optional.
const authenticatorChksumMinLen = 24

// verifyChannelBinding compares the Bnd field of the AP_REQ authenticator's GSS-API checksum against the channel
// binding the service requires, as described by RFC 4121 Section 4.1.1. The comparison is constant time.
//
// Lgth is checked rather than assumed. RFC 4121 Section 4.1.1 fixes it at 16, so a checksum declaring anything else
// is not a layout whose octets 4 to 19 can be read as Bnd; comparing them anyway would report a binding mismatch for
// what is really a malformed checksum, sending whoever has to diagnose it after the wrong problem.
//
// Every failure is reported as ErrBadChannelBinding, including an authenticator that carries no usable Bnd at all:
// once the acceptor has supplied bindings, an initiator that supplied none has bindings that do not match, which
// RFC 2743 Section 2.2.2 classifies as bad bindings rather than as a defective token.
func verifyChannelBinding(APReq *messages.APReq, cb *gssapi.ChannelBinding) error {
	cksum := APReq.Authenticator.Cksum.Checksum

	if APReq.Authenticator.Cksum.CksumType != chksumtype.GSSAPI || len(cksum) < authenticatorChksumMinLen {
		return newBadChannelBindingError(APReq, "authenticator does not contain a GSSAPI checksum carrying channel bindings")
	}

	if lgth := binary.LittleEndian.Uint32(cksum[:4]); lgth != authenticatorChksumBndLgth {
		return newBadChannelBindingError(APReq, fmt.Sprintf(
			"authenticator GSSAPI checksum declares a Bnd length of %d rather than %d", lgth, authenticatorChksumBndLgth))
	}

	expected := cb.Bnd()

	if !hmac.Equal(cksum[4:20], expected[:]) {
		return newBadChannelBindingError(APReq, "channel binding mismatch")
	}

	return nil
}
