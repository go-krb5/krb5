package service

import (
	"crypto/hmac"
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

// verifyChannelBinding compares the Bnd field of the AP_REQ authenticator's GSS-API checksum against the channel
// binding the service requires, as described by RFC 4121 Section 4.1.1. The comparison is constant time.
func verifyChannelBinding(APReq *messages.APReq, cb *gssapi.ChannelBinding) error {
	if APReq.Authenticator.Cksum.CksumType != chksumtype.GSSAPI || len(APReq.Authenticator.Cksum.Checksum) < 24 {
		return messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADMATCH,
			"authenticator does not contain a GSSAPI checksum carrying channel bindings")
	}

	expected := cb.Bnd()

	if !hmac.Equal(APReq.Authenticator.Cksum.Checksum[4:20], expected[:]) {
		return messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADMATCH,
			"channel binding mismatch")
	}

	return nil
}
