package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// ErrEvidenceNotForwardable is returned when the KDC issued the protocol transition ticket without the FORWARDABLE
// flag, so it cannot be the evidence of a constrained delegation request. Callers match against it with errors.Is.
var ErrEvidenceNotForwardable = errors.New("the protocol transition ticket is not forwardable")

// Impersonation is a service ticket this client obtained in another principal's name by S4U2Self and S4U2Proxy.
//
// It is what an initiator needs to authenticate to the service as that principal: the ticket, its session key and
// the name the ticket was issued to, which the authenticator has to repeat. See spnego.OnBehalfOf.
type Impersonation struct {
	Ticket     messages.Ticket
	SessionKey types.EncryptionKey
	CName      types.PrincipalName
	CRealm     string
	EndTime    time.Time
}

// Impersonate obtains a ticket to the service spn in the name of user, a principal of userRealm, without that user
// taking part: protocol transition (S4U2Self) followed by constrained delegation (S4U2Proxy), MS-SFU Sections 3.1.5.1
// and 3.1.5.2.
//
// The KDC decides whether this client may do it, and two separate permissions are involved. The protocol transition
// ticket is forwardable only for a service trusted to authenticate for delegation (MIT's ok_to_auth_as_delegate,
// Active Directory's TRUSTED_TO_AUTH_FOR_DELEGATION); without that, ErrEvidenceNotForwardable is returned before
// anything is asked of the target. The delegation itself is honoured only towards services the KDC lists for this
// client (MIT's krbAllowedToDelegateTo, Active Directory's msDS-AllowedToDelegateTo); a refusal comes back as the
// KDC's KRB_ERROR, recoverable with errors.As.
//
// The tickets are deliberately not added to the client's cache. They are in another principal's name, and handing
// one back from GetServiceTicket for this client's own requests would be a correctness bug. Callers that repeat an
// impersonation cache the result themselves, keyed by user and service, until EndTime.
//
// Only a user and a service of this client's own realm are supported: across realms the requests have to follow
// referrals, which is not implemented.
func (cl *Client) Impersonate(user types.PrincipalName, userRealm, spn string) (Impersonation, error) {
	var imp Impersonation

	evidence, self, err := cl.S4U2Self(user, userRealm)
	if err != nil {
		return imp, err
	}

	if !types.IsFlagSet(&self.Flags, flags.Forwardable) {
		return imp, fmt.Errorf("%w: the KDC trusts %s to act on behalf of %s@%s only towards itself; to reach %s it must also be trusted to authenticate for delegation (ok_to_auth_as_delegate)", ErrEvidenceNotForwardable, cl.Credentials.CName().PrincipalNameString(), user.PrincipalNameString(), userRealm, spn)
	}

	tkt, dep, err := cl.S4U2Proxy(evidence, user, userRealm, spn)
	if err != nil {
		return imp, err
	}

	return Impersonation{
		Ticket:     tkt,
		SessionKey: dep.Key,
		CName:      user,
		CRealm:     userRealm,
		EndTime:    dep.EndTime,
	}, nil
}

// S4U2Self obtains a ticket to this client's own principal in the name of user, a principal of userRealm: the
// protocol transition of MS-SFU Section 3.1.5.1. The ticket is returned with the decrypted part of the reply, whose
// flags say whether it is forwardable and so usable as evidence for S4U2Proxy.
func (cl *Client) S4U2Self(user types.PrincipalName, userRealm string) (messages.Ticket, messages.EncKDCRepPart, error) {
	var (
		tkt messages.Ticket
		dep messages.EncKDCRepPart
	)

	realm := cl.Credentials.Realm()
	if userRealm != realm {
		return tkt, dep, fmt.Errorf("protocol transition for %s@%s: a user of another realm than %s is not supported", user.PrincipalNameString(), userRealm, realm)
	}

	tgt, sessionKey, err := cl.sessionTGT(realm)
	if err != nil {
		return tkt, dep, err
	}

	req, err := messages.NewS4U2SelfTGSReq(cl.Credentials.CName(), realm, realm, cl.Config, tgt, sessionKey, user, userRealm)
	if err != nil {
		return tkt, dep, krberror.Errorf(err, krberror.KRBMsgError, "failed to generate an S4U2Self TGS_REQ")
	}

	b, err := req.Marshal()
	if err != nil {
		return tkt, dep, krberror.Errorf(err, krberror.EncodingError, "failed to marshal the S4U2Self TGS_REQ")
	}

	rep, err := cl.onBehalfOfExchange(req, b, realm, sessionKey, user, userRealm)
	if err != nil {
		return tkt, dep, fmt.Errorf("protocol transition for %s@%s: %w", user.PrincipalNameString(), userRealm, err)
	}

	return rep.Ticket, rep.DecryptedEncPart, nil
}

// S4U2Proxy obtains a ticket to the service spn in the name of user, the client of evidence: the constrained
// delegation of MS-SFU Section 3.1.5.2. evidence is a forwardable ticket to this client in the user's name, from
// S4U2Self or presented by the user.
func (cl *Client) S4U2Proxy(evidence messages.Ticket, user types.PrincipalName, userRealm, spn string) (messages.Ticket, messages.EncKDCRepPart, error) {
	var (
		tkt messages.Ticket
		dep messages.EncKDCRepPart
	)

	realm := cl.Credentials.Realm()

	// A target the configuration places in another realm is refused before the KDC is asked. One it cannot place is
	// asked of this realm's KDC, and if that KDC answers with a referral the reply check refuses it.
	princ := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	if r := cl.spnRealm(princ); r != "" && r != realm {
		return tkt, dep, fmt.Errorf("constrained delegation to %s: a service of another realm (%s) than %s is not supported", spn, r, realm)
	}

	tgt, sessionKey, err := cl.sessionTGT(realm)
	if err != nil {
		return tkt, dep, err
	}

	req, err := messages.NewS4U2ProxyTGSReq(cl.Credentials.CName(), realm, realm, cl.Config, tgt, sessionKey, princ, evidence)
	if err != nil {
		return tkt, dep, krberror.Errorf(err, krberror.KRBMsgError, "failed to generate an S4U2Proxy TGS_REQ")
	}

	b, err := req.Marshal()
	if err != nil {
		return tkt, dep, krberror.Errorf(err, krberror.EncodingError, "failed to marshal the S4U2Proxy TGS_REQ")
	}

	rep, err := cl.onBehalfOfExchange(req, b, realm, sessionKey, user, userRealm)
	if err != nil {
		return tkt, dep, fmt.Errorf("constrained delegation to %s on behalf of %s@%s: %w", spn, user.PrincipalNameString(), userRealm, err)
	}

	return rep.Ticket, rep.DecryptedEncPart, nil
}

// onBehalfOfExchange sends an S4U request, b being req on the wire, and checks that the reply is a ticket in the
// user's name. Unlike TGSExchange it follows no referrals, refusing a reply that is one (see TGSRep.VerifyOnBehalfOf),
// and does not touch the cache.
func (cl *Client) onBehalfOfExchange(req messages.TGSReq, b []byte, realm string, sessionKey types.EncryptionKey, user types.PrincipalName, userRealm string) (messages.TGSRep, error) {
	var rep messages.TGSRep

	r, err := cl.sendToKDC(b, realm)
	if err != nil {
		// Wrapped with %w rather than krberror.Errorf, which does not implement Unwrap: the caller needs errors.As
		// to recover a KRB_ERROR and tell a KDC refusal from a network failure.
		return rep, fmt.Errorf("the KDC did not issue the ticket: %w", err)
	}

	if err = rep.Unmarshal(r); err != nil {
		return rep, krberror.Errorf(err, krberror.EncodingError, "failed to process the TGS_REP")
	}

	if err = rep.DecryptEncPart(sessionKey); err != nil {
		return rep, krberror.Errorf(err, krberror.DecryptingError, "failed to decrypt the TGS_REP")
	}

	if ok, err := rep.VerifyOnBehalfOf(cl.Config, req, user, userRealm); !ok {
		return rep, krberror.Errorf(err, krberror.KRBMsgError, "the TGS_REP is not valid")
	}

	cl.Log("ticket for %s issued in the name of %s@%s (EndTime: %v)", rep.Ticket.SName.PrincipalNameString(), user.PrincipalNameString(), userRealm, rep.DecryptedEncPart.EndTime)

	return rep, nil
}
