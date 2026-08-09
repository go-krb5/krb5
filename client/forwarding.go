package client

import (
	"errors"
	"fmt"
	"net"

	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// ErrNotForwardable is returned when the client's TGT cannot be forwarded because the KDC did not mark it
// FORWARDABLE. RFC 4120 Section 3.3 honours the FORWARDED option "only if the FORWARDABLE flag is set in the TGT".
// Callers match against it with errors.Is.
var ErrNotForwardable = errors.New("the client's ticket granting ticket is not forwardable")

// errNotForwardable wraps ErrNotForwardable with the operator-actionable causes, so callers matching with
// errors.Is still see them in err.Error().
//
// Both causes are named because the local one is not the likelier one in a domain. Against Active Directory the
// KDC withholds FORWARDABLE regardless of what the client asks for when the account carries the
// ADS_UF_NOT_DELEGATED bit of MS-ADTS Section 2.2.16, or is in Protected Users; naming only the krb5.conf setting
// would send an operator to change something that is already correct.
func errNotForwardable() error {
	return fmt.Errorf("%w: the KDC will not honour a FORWARDED request against it. Either forwardable = true is not set in the libdefaults section of krb5.conf, or the account is barred from delegation: in Active Directory by the ADS_UF_NOT_DELEGATED bit (\"Account is sensitive and cannot be delegated\") or by membership of Protected Users, both of which withhold the FORWARDABLE flag however it is requested", ErrNotForwardable)
}

// ForwardedTGT obtains a ticket-granting ticket for this client marked FORWARDED, for delegating the client's
// identity to the service named by spn as described by RFC 4121 Section 4.1.1.
//
// The ticket returned is deliberately not added to the client's ticket cache. It is a credential intended for
// another host, and handing it back from GetCachedTicket, or letting it stand in for the client's own session TGT,
// would be a correctness bug. Callers use it once and discard it.
//
// Addresses are supplied only when the client's own TGT has them, matching MIT's krb5_fwd_tgt_creds. With this
// library's NoAddresses default the forwarded ticket is addressless, which RFC 4120 Section 2.6 blesses.
//
// svcKey is the session key of the service ticket the delegation accompanies. MS-KILE Section 3.3.5.7.4 has the
// client "set the etype field of the TGS-REQ to the contents of the keytype field in the previous TGS-REP", so
// that the KDC issues the forwarded ticket with a session key the application server can use; svcKey's type is
// that keytype. If the KDC refuses that encryption type the request is retried once with the configured defaults,
// mirroring MIT's krb5_fwd_tgt_creds, which does the same rather than failing the delegation outright.
func (cl *Client) ForwardedTGT(spn types.PrincipalName, svcKey types.EncryptionKey) (tkt messages.Ticket, dep messages.EncKDCRepPart, err error) {
	realm := cl.Credentials.Realm()

	// sessionTGT is called before the forwardable check, not after: it is the only path (via ensureValidSession's
	// refreshSession -> realmLogin) by which a stale session picks up a FORWARDABLE flag from a fresh AS-REQ, e.g.
	// after an operator flips LibDefaults.Forwardable at runtime. Checking forwardable first would short-circuit
	// exactly the re-login that could satisfy the request. When the existing session is still valid,
	// ensureValidSession's fast path returns without any network I/O, so this costs nothing in the common case.
	tgt, sessionKey, err := cl.sessionTGT(realm)
	if err != nil {
		return tkt, dep, err
	}

	s, ok := cl.sessions.get(realm)
	if !ok {
		return tkt, dep, fmt.Errorf("could not find TGT session for %s", realm)
	}

	if !s.forwardable() {
		return tkt, dep, errNotForwardable()
	}

	var addrs types.HostAddresses

	if s.addressed() {
		if addrs, err = spnHostAddresses(spn); err != nil {
			return tkt, dep, err
		}
	}

	supported := s.supported()
	if e, ok := cl.cache.getEntry(spn.PrincipalNameString()); ok {
		supported = supported.Intersect(e.SupportedETypes)
	}

	tkt, dep, err = cl.forwardedTGSExchange(realm, tgt, sessionKey, addrs, []int32{svcKey.KeyType}, supported)
	if err == nil || !kdcRefused(err) {
		return tkt, dep, err
	}

	// MIT's krb5_fwd_tgt_creds retries with an unrestricted encryption type when the KDC rejects the pinned one,
	// rather than failing the delegation. The pinned type is a MS-KILE SHOULD chosen to suit the application
	// server; a KDC that cannot honour it has not said the delegation itself is impossible.
	cl.Log("KDC refused a forwarded TGT with encryption type %d, retrying with the configured defaults", svcKey.KeyType)

	return cl.forwardedTGSExchange(realm, tgt, sessionKey, addrs, nil, supported)
}

// kdcRefused reports whether the error carries a KRB_ERROR, meaning the KDC answered and declined, as opposed to a
// local or network failure that a retry would only repeat.
func kdcRefused(err error) bool {
	var krberr messages.KRBError

	return errors.As(err, &krberr)
}

// forwardedTGSExchange performs one forwarding request. It is separate from ForwardedTGT so that the encryption
// type fallback can run it twice without duplicating the exchange, and it deliberately does not touch cl.cache.
func (cl *Client) forwardedTGSExchange(realm string, tgt messages.Ticket, sessionKey types.EncryptionKey, addrs types.HostAddresses, etypes []int32, supported types.SupportedETypes) (tkt messages.Ticket, dep messages.EncKDCRepPart, err error) {
	req, err := messages.NewForwardedTGSReq(cl.Credentials.CName(), realm, realm, cl.Config, tgt, sessionKey, addrs, etypes, supported)
	if err != nil {
		return tkt, dep, krberror.Errorf(err, krberror.KRBMsgError, "failed to generate a forwarded TGS_REQ")
	}

	b, err := req.Marshal()
	if err != nil {
		return tkt, dep, krberror.Errorf(err, krberror.EncodingError, "failed to marshal the forwarded TGS_REQ")
	}

	r, err := cl.sendToKDC(b, realm)
	if err != nil {
		// Wrapped with %w rather than krberror.Errorf, which does not implement Unwrap: the caller needs
		// errors.As to recover a KRB_ERROR so it can tell a KDC refusal from a network failure.
		return tkt, dep, fmt.Errorf("error requesting a forwarded TGT: %w", err)
	}

	var rep messages.TGSRep

	if err = rep.Unmarshal(r); err != nil {
		return tkt, dep, krberror.Errorf(err, krberror.EncodingError, "failed to process the forwarded TGS_REP")
	}

	if err = rep.DecryptEncPart(sessionKey); err != nil {
		return tkt, dep, krberror.Errorf(err, krberror.DecryptingError, "failed to decrypt the forwarded TGS_REP")
	}

	if ok, err := rep.Verify(cl.Config, req); !ok {
		return tkt, dep, krberror.Errorf(err, krberror.KRBMsgError, "the forwarded TGS_REP is not valid")
	}

	return rep.Ticket, rep.DecryptedEncPart, nil
}

// spnHostAddresses resolves the addresses of the host a service principal names, for the addresses field of a
// forwarding request. RFC 4120 Section 3.3 describes these as "the address(es) of the host from which the resulting
// ticket is to be valid".
//
// MIT derives the same host from the service principal's second component, and fails with KRB5_FWD_BAD_PRINCIPAL
// when the principal is not host based, which is what the length check mirrors.
func spnHostAddresses(spn types.PrincipalName) (types.HostAddresses, error) {
	if len(spn.NameString) < 2 {
		return nil, fmt.Errorf("cannot determine the host to forward a ticket to from service principal %s: it is not host based", spn.PrincipalNameString())
	}

	ips, err := net.LookupIP(spn.NameString[1])
	if err != nil {
		return nil, fmt.Errorf("could not resolve %s to forward a ticket to it: %w", spn.NameString[1], err)
	}

	return types.HostAddressesFromNetIPs(ips), nil
}
