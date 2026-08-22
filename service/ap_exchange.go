package service

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"time"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
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
	} else if s.RequireChannelBindingSupport() {
		if err = verifyChannelBindingSupport(APReq); err != nil {
			return false, creds, err
		}
	}

	// Check for replay.
	sname, srealm := replayCacheService(&APReq.Ticket, s)

	rc := GetReplayCache(s.MaxClockSkew())
	if rc.IsReplay(sname, srealm, APReq.Authenticator) {
		return false, creds,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_REPEAT, "replay detected")
	}

	c := credentials.NewFromPrincipalName(APReq.Ticket.DecryptedEncPart.CName, APReq.Ticket.DecryptedEncPart.CRealm)
	creds = c
	creds.SetAuthTime(time.Now().UTC())
	creds.SetAuthenticated(true)
	creds.SetValidUntil(APReq.Ticket.DecryptedEncPart.EndTime)

	if err = extractDelegatedCredential(APReq, creds); err != nil {
		return false, creds, err
	}

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

// replayCacheService returns the service principal a presentation is recorded against, which RFC 4120 Section 3.2.3
// stores "along with the client name, time, and microsecond fields from the recently-seen authenticators".
//
// It is the principal whose key actually decrypted the ticket, which is not always the one the ticket names.
// Ticket.SName sits outside the KDC-sealed EncTicketPart and is covered by no checksum, and where KeytabPrincipal
// overrides the keytab lookup it is consulted for nothing else at all. Keying the replay cache on it there would let
// a captured AP_REQ be replayed indefinitely by rewriting it, each rewrite both missing the entry that should have
// caught it and displacing that entry for the next attempt.
//
// Without the override the two are the same value: DecryptEncPart resolved the key by that name and realm, so a
// ticket naming anything else would not have decrypted. The realm is taken from the ticket in both cases for the
// same reason, since it selects the key whether or not the name is overridden.
func replayCacheService(tkt *messages.Ticket, s *Settings) (sname types.PrincipalName, srealm string) {
	if kp := s.KeytabPrincipal(); kp != nil {
		return *kp, tkt.Realm
	}

	return tkt.SName, tkt.Realm
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

	if APReq.Authenticator.Cksum.CksumType != chksumtype.GSSAPI || len(cksum) < gssapi.ChecksumMinLen {
		return newBadChannelBindingError(APReq, "authenticator does not contain a GSSAPI checksum carrying channel bindings")
	}

	var c gssapi.AuthenticatorChecksum

	if err := c.Unmarshal(cksum); err != nil {
		var lgth gssapi.ChecksumLgthError
		if errors.As(err, &lgth) {
			return newBadChannelBindingError(APReq, fmt.Sprintf("authenticator GSSAPI checksum %s", lgth.Error()))
		}

		return newBadChannelBindingError(APReq, fmt.Sprintf("authenticator GSSAPI checksum could not be read: %s", err.Error()))
	}

	expected := cb.Bnd()

	if !hmac.Equal(c.Bnd[:], expected[:]) {
		return newBadChannelBindingError(APReq, "channel binding mismatch")
	}

	return nil
}

// ErrBadDelegation identifies a failure to accept a credential a client delegated in its AP_REQ. RFC 4121 Section
// 4.1.1 makes the delegation fields present if and only if GSS_C_DELEG_FLAG is set, so a request that claims a
// delegation this service cannot read is defective rather than merely unhelpful: an acceptor has no way to tell the
// initiator that its forwarded ticket was discarded. Callers translating an AP_REQ failure into a GSS-API status
// match against this with errors.Is.
var ErrBadDelegation = errors.New("bad delegated credential")

// badDelegationError joins ErrBadDelegation to the KRB_ERROR describing the failure. Both are exposed through
// Unwrap so that a caller can classify the failure with errors.Is and still recover the KRB_ERROR to send on the
// wire with errors.As. KRB_AP_ERR_INAPP_CKSUM is the wire error because the defect is in the authenticator's
// checksum.
type badDelegationError struct {
	krberr messages.KRBError
}

// Error returns the description of the underlying KRB_ERROR.
func (e badDelegationError) Error() string {
	return e.krberr.Error()
}

// Unwrap exposes the sentinel and the KRB_ERROR.
func (e badDelegationError) Unwrap() []error {
	return []error{ErrBadDelegation, e.krberr}
}

// newBadDelegationError builds the error returned when a delegated credential cannot be accepted.
func newBadDelegationError(APReq *messages.APReq, etext string) error {
	return badDelegationError{
		krberr: messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_INAPP_CKSUM, etext),
	}
}

// extractDelegatedCredential reads the KRB_CRED a client delegated in the Deleg field of the AP_REQ authenticator's
// GSS-API checksum, as described by RFC 4121 Section 4.1.1, and attaches it to creds.
//
// An AP_REQ that does not claim delegation, or whose checksum cannot be interpreted at all, is left alone: a
// checksum whose Lgth moves every field after Bnd is one in which Flags cannot be located, so whether delegation
// was requested is unknowable and reporting a delegation failure would be a guess. Once delegation is claimed,
// every defect is fatal.
//
// The credential is decrypted with the authenticator's subkey when it carries one, falling back to the ticket
// session key. RFC 4121 Section 4.1.1 requires initiators to use the session key and this library does, but MIT's
// rd_cred.c accepts either and peers exist that send the subkey.
func extractDelegatedCredential(APReq *messages.APReq, creds *credentials.Credentials) error {
	cksum := APReq.Authenticator.Cksum.Checksum

	if APReq.Authenticator.Cksum.CksumType != chksumtype.GSSAPI || len(cksum) < gssapi.ChecksumMinLen {
		return nil
	}

	var c gssapi.AuthenticatorChecksum

	if err := c.Unmarshal(cksum); err != nil {
		var lgth gssapi.ChecksumLgthError
		if errors.As(err, &lgth) {
			return nil
		}

		return newBadDelegationError(APReq, fmt.Sprintf("authenticator GSSAPI checksum %s", err.Error()))
	}

	if !c.Delegated() {
		return nil
	}

	var cred messages.KRBCred

	if err := cred.Unmarshal(c.Deleg); err != nil {
		return newBadDelegationError(APReq, fmt.Sprintf("delegated credential could not be read: %s", err.Error()))
	}

	if err := decryptDelegatedCredential(&cred, APReq); err != nil {
		return newBadDelegationError(APReq, err.Error())
	}

	cc, err := cred.CCache()
	if err != nil {
		return newBadDelegationError(APReq, fmt.Sprintf("delegated credential could not be used: %s", err.Error()))
	}

	creds.SetDelegatedCredentials(cc)

	return nil
}

// decryptDelegatedCredential decrypts the KRB_CRED with the authenticator subkey if one is present, falling back to
// the ticket session key, mirroring MIT's rd_cred.c.
func decryptDelegatedCredential(cred *messages.KRBCred, APReq *messages.APReq) error {
	keys := make([]types.EncryptionKey, 0, 2)

	if len(APReq.Authenticator.SubKey.KeyValue) > 0 {
		keys = append(keys, APReq.Authenticator.SubKey)
	}

	keys = append(keys, APReq.Ticket.DecryptedEncPart.Key)

	var err error

	for _, key := range keys {
		if err = cred.DecryptEncPart(key); err == nil {
			return nil
		}
	}

	return fmt.Errorf("could not decrypt the delegated credential with the authenticator subkey or the ticket session key: %w", err)
}

// verifyChannelBindingSupport applies the rule MS-KILE Section 3.4.5.3 gives an application server whose
// ApplicationRequiresCBT parameter is set: "return GSS_S_BAD_BINDINGS whenever the AP exchange request message
// contains an all-zero channel binding value and does not contain the AD-IF-RELEVANT element
// KERB_AP_OPTIONS_CBT".
//
// Both conditions must hold for a rejection, which makes this strictly weaker than verifyChannelBinding: a peer
// that advertises KERB_AP_OPTIONS_CBT and then supplies no binding passes here and would fail there. That is
// Microsoft's compatibility compromise, not an equivalent check, and the setting that reaches this documents the
// difference.
//
// A binding that is present but wrong is not this function's concern. It cannot be: this mode has no binding to
// compare against, which is the other reason it is weaker.
func verifyChannelBindingSupport(APReq *messages.APReq) error {
	cksum := APReq.Authenticator.Cksum.Checksum

	if APReq.Authenticator.Cksum.CksumType != chksumtype.GSSAPI || len(cksum) < gssapi.ChecksumMinLen {
		return newBadChannelBindingError(APReq, "authenticator does not contain a GSSAPI checksum carrying channel bindings")
	}

	var c gssapi.AuthenticatorChecksum

	if err := c.Unmarshal(cksum); err != nil {
		return newBadChannelBindingError(APReq, fmt.Sprintf("authenticator GSSAPI checksum could not be read: %s", err.Error()))
	}

	if c.Bnd != ([16]byte{}) {
		return nil
	}

	if types.ADAPOptionsFromAuthorizationData(APReq.Authenticator.AuthorizationData).Has(types.ADAPOptionsCBT) {
		return nil
	}

	return newBadChannelBindingError(APReq,
		"authenticator carries no channel binding and does not advertise KERB_AP_OPTIONS_CBT, so the client cannot bind to the outer channel")
}
