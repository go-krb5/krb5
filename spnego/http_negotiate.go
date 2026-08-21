package spnego

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/gssapi"
)

// MaxNegotiationLegs bounds the number of SPNEGO tokens the client will send in answer to one request. RFC 4178
// negotiations with the Kerberos mechanism take one leg, or two when the target asks to continue, so the bound is
// slack; it is there because a target that keeps challenging would otherwise keep the client answering forever.
const MaxNegotiationLegs = 4

// negotiationAction is what a Negotiate challenge asks the client to do next.
type negotiationAction int

const (
	// negotiationStop means the exchange is over, or there is nothing this client can usefully send. The
	// challenging response is returned to the caller as it stands.
	negotiationStop negotiationAction = iota
	// negotiationInitiate means send the first token of an exchange.
	negotiationInitiate
	// negotiationContinue means send a token continuing an exchange the target asked to continue.
	negotiationContinue
	// negotiationAnswerMIC means verify the target's mechListMIC and answer it with one of the client's own.
	negotiationAnswerMIC
)

// negotiateChallenge returns the SPNEGO token in a Negotiate challenge, and reports whether the response is one.
func negotiateChallenge(resp *http.Response) ([]byte, bool, error) {
	if resp.StatusCode != http.StatusUnauthorized {
		return nil, false, nil
	}

	for _, h := range resp.Header.Values(HTTPHeaderAuthResponse) {
		scheme, token, _ := strings.Cut(h, " ")
		if !strings.EqualFold(scheme, HTTPHeaderAuthResponseValueKey) {
			continue
		}

		token = strings.TrimSpace(token)
		if token == "" {
			return nil, true, nil
		}

		b, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			return nil, true, fmt.Errorf("error in base64 decoding the negotiation challenge: %w", err)
		}

		return b, true, nil
	}

	return nil, false, nil
}

// negotiationNext decides what the client does with the token a target challenged it with.
func negotiationNext(token []byte) (negotiationAction, NegTokenResp, error) {
	var nr NegTokenResp

	if len(token) == 0 {
		return negotiationInitiate, nr, nil
	}

	init, nt, err := UnmarshalNegToken(token)
	if err != nil {
		return negotiationStop, nr, fmt.Errorf("could not read the SPNEGO challenge: %w", err)
	}

	if init {
		return negotiationStop, nr, errors.New("the SPNEGO challenge is a NegTokenInit, not a negotiation response from a target")
	}

	nr = nt.(NegTokenResp)

	// RFC 4178 Section 4.2.2 has the target name the mechanism it selected in its first reply. One that is named
	// and is not Kerberos is a mechanism this client cannot continue with.
	if len(nr.SupportedMech) > 0 && !isKerberosMech(nr.SupportedMech) {
		return negotiationStop, nr, nil
	}

	switch nr.State() {
	case NegStateAcceptIncomplete:
		return negotiationContinue, nr, nil
	case NegStateRequestMIC:
		// Section 5(c)(IV): where the optimistic token is also the last mechanism token, which is always so for
		// this client because it offers one mechanism, a target asking for the MIC exchange "MUST include a
		// mechlistMIC token in that first reply". Without it there is nothing to verify and no way to proceed
		// that would not amount to answering an unauthenticated request for a MIC.
		if len(nr.MechListMIC) == 0 {
			return negotiationStop, nr, errors.New("the target asked for the mechListMIC exchange but sent no mechListMIC of its own")
		}

		return negotiationAnswerMIC, nr, nil
	default:
		// accept-completed ends the negotiation and reject terminates it. Either way there is nothing to send.
		return negotiationStop, nr, nil
	}
}

// negotiate sets the Authorization header for the next leg of an exchange, reporting whether there is a leg to send.
func (c *Client) negotiate(req *http.Request, resp *http.Response, token []byte) (bool, error) {
	action, nr, err := negotiationNext(token)
	if err != nil {
		return false, err
	}

	switch action {
	case negotiationInitiate:
		return true, SetSPNEGOHeader(c.krb5Client, req, c.spn, c.requestTokenOptions(resp)...)
	case negotiationContinue:
		return true, setSPNEGOContinuationHeader(c.krb5Client, req, c.spn, c.requestTokenOptions(resp)...)
	case negotiationAnswerMIC:
		return true, setSPNEGOMechListMICHeader(c.krb5Client, req, c.spn, nr.MechListMIC)
	default:
		return false, nil
	}
}

// setSPNEGOContinuationHeader sets the Authorization header for a leg continuing an exchange the target asked to
// continue.
//
// RFC 4178 Section 4.2.2 carries this in a NegTokenResp and not another NegTokenInit, and the initiator names no
// supportedMech there because that field appears "only in the first reply from the target"; the mech token itself
// names the mechanism. The AP_REQ is built afresh rather than reused, since the one already sent has been seen by
// the target and a service that keeps a replay cache would refuse it.
func setSPNEGOContinuationHeader(cl *client.Client, r *http.Request, spn string, opts ...KRB5TokenOption) error {
	spn, err := requestSPN(cl, r, spn)
	if err != nil {
		return err
	}

	mt, err := negotiationMechToken(cl, spn, opts...)
	if err != nil {
		return err
	}

	b, err := mt.Marshal()
	if err != nil {
		return fmt.Errorf("could not marshal the KRB5 token continuing the negotiation: %w", err)
	}

	return setNegotiationHeader(r, NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptIncomplete),
		ResponseToken: b,
	})
}

// setSPNEGOMechListMICHeader answers a target's request-mic, as RFC 4178 Section 5(c)(IV) describes: "The initiator
// MUST verify the received mechlistMIC token and generate a mechlistMIC token to send back to the target."
func setSPNEGOMechListMICHeader(cl *client.Client, r *http.Request, spn string, targetMIC []byte) error {
	spn, err := requestSPN(cl, r, spn)
	if err != nil {
		return err
	}

	_, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		return fmt.Errorf("could not get the service ticket to verify the mechListMIC: %w", err)
	}

	payload, err := mechListMICPayload(nil, initiatorMechTypes())
	if err != nil {
		return err
	}

	if err = verifyMechListMIC(targetMIC, payload, key, true); err != nil {
		return err
	}

	mic, err := newMechListMIC(payload, key, false)
	if err != nil {
		return err
	}

	return setNegotiationHeader(r, NegTokenResp{
		NegState:    asn1.Enumerated(NegStateAcceptCompleted),
		MechListMIC: mic,
	})
}

// negotiationMechToken builds the Kerberos mech token for a leg of a negotiation.
func negotiationMechToken(cl *client.Client, spn string, opts ...KRB5TokenOption) (KRB5Token, error) {
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		return KRB5Token{}, fmt.Errorf("could not get the service ticket for %s: %w", spn, err)
	}

	mt, err := NewKRB5TokenAPREQ(cl, tkt, key, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, []int{}, opts...)
	if err != nil {
		return mt, fmt.Errorf("could not build the KRB5 token: %w", err)
	}

	return mt, nil
}

// setNegotiationHeader base64 encodes a negotiation token into the request's Authorization header.
func setNegotiationHeader(r *http.Request, nr NegTokenResp) error {
	b, err := nr.Marshal()
	if err != nil {
		return fmt.Errorf("could not marshal the SPNEGO negotiation token: %w", err)
	}

	r.Header.Set(HTTPHeaderAuthRequest, HTTPHeaderAuthResponseValueKey+" "+base64.StdEncoding.EncodeToString(b))

	return nil
}

// requestSPN resolves the service principal name for a request, deriving it from the request when none is
// configured, exactly as SetSPNEGOHeader does.
func requestSPN(cl *client.Client, r *http.Request, spn string) (string, error) {
	if spn != "" {
		return spn, nil
	}

	pn, err := setRequestSPN(r, canonicalizeHostname(cl))
	if err != nil {
		return "", err
	}

	return pn.PrincipalNameString(), nil
}

// initiatorMechTypes returns the mechanism list this library offers as a SPNEGO initiator. It holds Kerberos alone,
// which is the only mechanism implemented here, and it is what a mechListMIC computed by this initiator protects.
func initiatorMechTypes() []asn1.ObjectIdentifier {
	return []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}
}
