package spnego

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/types"
)

// https://msdn.microsoft.com/en-us/library/ms995330.aspx

// Negotiation state values.
const (
	NegStateAcceptCompleted  NegState = 0
	NegStateAcceptIncomplete NegState = 1
	NegStateReject           NegState = 2
	NegStateRequestMIC       NegState = 3
)

// NegState is a type to indicate the SPNEGO negotiation state.
type NegState int

// NegTokenInit implements Negotiation Token of type Init.
type NegTokenInit struct {
	MechTypes       []asn1.ObjectIdentifier
	ReqFlags        asn1.BitString
	MechTokenBytes  []byte
	MechListMIC     []byte
	mechToken       gssapi.ContextToken
	settings        *service.Settings
	mechTypesRaw    []byte
	respMechListMIC []byte
}

type marshalNegTokenInit struct {
	MechTypes []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`

	ReqFlags asn1.BitString `asn1:"explicit,optional,tag:1"`

	MechTokenBytes []byte `asn1:"explicit,optional,omitempty,tag:2"`

	MechListMIC []byte `asn1:"explicit,optional,omitempty,tag:3"`
}

// NegTokenResp implements Negotiation Token of type Resp/Targ.
type NegTokenResp struct {
	NegState        asn1.Enumerated
	SupportedMech   asn1.ObjectIdentifier
	ResponseToken   []byte
	MechListMIC     []byte
	mechToken       gssapi.ContextToken
	settings        *service.Settings
	mechTypes       []asn1.ObjectIdentifier
	mechTypesRaw    []byte
	respMechListMIC []byte
}

type marshalNegTokenResp struct {
	NegState asn1.Enumerated `asn1:"explicit,tag:0"`

	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`

	ResponseToken []byte `asn1:"explicit,optional,omitempty,tag:2"`

	// MechListMIC protects the initiator's MechTypes; see RFC 4178 Section 5 and mechlist_mic.go.
	MechListMIC []byte `asn1:"explicit,optional,omitempty,tag:3"`
}

// NegTokenTarg implements Negotiation Token of type Resp/Targ.
type NegTokenTarg NegTokenResp

// Marshal an Init negotiation token.
func (n *NegTokenInit) Marshal() ([]byte, error) {
	m := marshalNegTokenInit{
		MechTypes:      n.MechTypes,
		ReqFlags:       n.ReqFlags,
		MechTokenBytes: n.MechTokenBytes,
		MechListMIC:    n.MechListMIC,
	}

	b, err := asn1.Marshal(m, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, err
	}

	nt := asn1.RawValue{
		Tag:        0,
		Class:      2,
		IsCompound: true,
		Bytes:      b,
	}

	nb, err := asn1.Marshal(nt, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, err
	}

	return nb, nil
}

// Unmarshal an Init negotiation token.
func (n *NegTokenInit) Unmarshal(b []byte) error {
	init, nt, err := UnmarshalNegToken(b)
	if err != nil {
		return err
	}

	if !init {
		return errors.New("bytes were not that of a NegTokenInit")
	}

	nInit := nt.(NegTokenInit)

	n.MechTokenBytes = nInit.MechTokenBytes
	n.MechListMIC = nInit.MechListMIC
	n.MechTypes = nInit.MechTypes
	n.ReqFlags = nInit.ReqFlags
	n.mechTypesRaw = nInit.mechTypesRaw

	return nil
}

// Verify an Init negotiation token.
//
// Kerberos is selected wherever it appears in mechTypes rather than only at the head of the list. RFC 4178 Section
// 4.2.2 has the acceptor name the mechanism it selected and ask for another leg, which is what an initiator offering
// NegoEx or NTLM ahead of Kerberos, the ordinary Windows case, expects to happen.
func (n *NegTokenInit) Verify() (bool, gssapi.Status) {
	i := kerberosMechIndex(n.MechTypes)
	if i < 0 {
		return false, gssapi.Status{Code: gssapi.StatusBadMech, Message: "no supported mechanism specified in negotiation"}
	}

	// The optimistic mechToken belongs to the first mechanism in the list. When that is not Kerberos the token is
	// not ours to read, so the reply names Kerberos and the initiator sends a Kerberos token of its own in the
	// leg that follows.
	if i > 0 || (n.mechToken == nil && n.MechTokenBytes == nil) {
		return false, gssapi.Status{Code: gssapi.StatusContinueNeeded}
	}

	mt := new(KRB5Token)

	mt.settings = n.settings
	if n.mechToken == nil {
		err := mt.Unmarshal(n.MechTokenBytes)
		if err != nil {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}

		n.mechToken = mt
	} else {
		var ok bool

		mt, ok = n.mechToken.(*KRB5Token)
		if !ok {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "MechToken is not a KRB5 token as expected"}
		}
	}

	ok, status := mt.Verify()
	if !ok || status.Code != gssapi.StatusComplete {
		return ok, status
	}

	if err := n.exchangeMechListMIC(mt); err != nil {
		return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
	}

	return ok, status
}

// exchangeMechListMIC performs the acceptor's half of the mechListMIC exchange of RFC 4178 Section 5 for the leg
// that carried the mechanism list itself.
func (n *NegTokenInit) exchangeMechListMIC(mt *KRB5Token) error {
	var err error

	n.respMechListMIC, err = exchangeMechListMIC(n.MechListMIC, n.mechTypesRaw, n.MechTypes, mt)

	return err
}

// exchangeMechListMIC verifies an initiator's mechListMIC against the mechanism list it protects and returns the MIC
// the acceptor owes in reply, or nil when the initiator sent none and there is no exchange to perform.
func exchangeMechListMIC(mic, raw []byte, mechTypes []asn1.ObjectIdentifier, mt *KRB5Token) ([]byte, error) {
	if len(mic) == 0 {
		return nil, nil
	}

	key, err := mt.contextKey()
	if err != nil {
		return nil, err
	}

	payload, err := mechListMICPayload(raw, mechTypes)
	if err != nil {
		return nil, err
	}

	if err = verifyMechListMIC(mic, payload, key, false); err != nil {
		return nil, err
	}

	return newMechListMIC(payload, key, true)
}

// Context returns the SPNEGO context which will contain any verify user identity information.
func (n *NegTokenInit) Context() context.Context {
	if n.mechToken != nil {
		mt, ok := n.mechToken.(*KRB5Token)
		if !ok {
			return nil
		}

		return mt.Context()
	}

	return nil
}

// Marshal a Resp/Targ negotiation token.
func (n *NegTokenResp) Marshal() ([]byte, error) {
	m := marshalNegTokenResp{
		NegState:      n.NegState,
		SupportedMech: n.SupportedMech,
		ResponseToken: n.ResponseToken,
		MechListMIC:   n.MechListMIC,
	}

	b, err := asn1.Marshal(m, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, err
	}

	nt := asn1.RawValue{
		Tag:        1,
		Class:      2,
		IsCompound: true,
		Bytes:      b,
	}

	nb, err := asn1.Marshal(nt, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, err
	}

	return nb, nil
}

// Unmarshal a Resp/Targ negotiation token.
func (n *NegTokenResp) Unmarshal(b []byte) error {
	init, nt, err := UnmarshalNegToken(b)
	if err != nil {
		return err
	}

	if init {
		return errors.New("bytes were not that of a NegTokenResp")
	}

	nResp := nt.(NegTokenResp)
	n.MechListMIC = nResp.MechListMIC
	n.NegState = nResp.NegState
	n.ResponseToken = nResp.ResponseToken
	n.SupportedMech = nResp.SupportedMech

	return nil
}

// Verify a Resp/Targ negotiation token.
//
// RFC 4178 Section 4.2.2 puts supportedMech "only in the first reply from the target", so a token continuing an
// exchange carries none and the mechanism is the one already agreed. Its absence is therefore accepted; a
// mechanism that is named and is not Kerberos is not.
func (n *NegTokenResp) Verify() (bool, gssapi.Status) {
	if len(n.SupportedMech) > 0 && !isKerberosMech(n.SupportedMech) {
		return false, gssapi.Status{Code: gssapi.StatusBadMech, Message: "no supported mechanism specified in negotiation"}
	}

	if n.mechToken == nil && n.ResponseToken == nil {
		return false, gssapi.Status{Code: gssapi.StatusContinueNeeded}
	}

	mt := new(KRB5Token)

	mt.settings = n.settings
	if n.mechToken == nil {
		if err := mt.Unmarshal(n.ResponseToken); err != nil {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}

		n.mechToken = mt
	} else {
		var ok bool

		mt, ok = n.mechToken.(*KRB5Token)
		if !ok {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "MechToken is not a KRB5 token as expected"}
		}
	}

	ok, status := mt.Verify()
	if !ok || status.Code != gssapi.StatusComplete {
		return ok, status
	}

	if err := n.exchangeMechListMIC(mt); err != nil {
		return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
	}

	return ok, status
}

// exchangeMechListMIC performs the acceptor's half of the mechListMIC exchange of RFC 4178 Section 5 for a leg
// continuing an exchange, where the mechanism list the MIC protects arrived earlier and is not in this token.
//
// An acceptor with no list retained refuses rather than passes a MIC it cannot check. Accepting one unverified would
// be indistinguishable, to anyone reading the result, from having verified it.
func (n *NegTokenResp) exchangeMechListMIC(mt *KRB5Token) error {
	if len(n.MechListMIC) > 0 && len(n.mechTypesRaw) == 0 && len(n.mechTypes) == 0 {
		return errors.New("the negotiation carries a mechListMIC but this acceptor did not retain the mechanism list it protects, so it cannot be verified: drive the whole exchange through one SPNEGO value")
	}

	var err error

	n.respMechListMIC, err = exchangeMechListMIC(n.MechListMIC, n.mechTypesRaw, n.mechTypes, mt)

	return err
}

// State returns the negotiation state of the negotiation response.
func (n *NegTokenResp) State() NegState {
	return NegState(n.NegState)
}

// Context returns the SPNEGO context which will contain any verify user identity information.
func (n *NegTokenResp) Context() context.Context {
	if n.mechToken != nil {
		mt, ok := n.mechToken.(*KRB5Token)
		if !ok {
			return nil
		}

		return mt.Context()
	}

	return nil
}

// UnmarshalNegToken umarshals and returns either a NegTokenInit or a NegTokenResp.
//
// The boolean indicates if the response is a NegTokenInit.
// If error is nil and the boolean is false the response is a NegTokenResp.
func UnmarshalNegToken(b []byte) (bool, any, error) {
	var a asn1.RawValue

	_, err := asn1.Unmarshal(b, &a, asn1.WithUnmarshalAllowTypeGeneralString(true))
	if err != nil {
		return false, nil, fmt.Errorf("error unmarshalling NegotiationToken: %w", err)
	}

	switch a.Tag {
	case 0:
		var n marshalNegTokenInit

		_, err = asn1.Unmarshal(a.Bytes, &n, asn1.WithUnmarshalAllowTypeGeneralString(true))
		if err != nil {
			return false, nil, fmt.Errorf("error unmarshalling NegotiationToken type %d (Init): %w", a.Tag, err)
		}

		// MechTypeList is a SEQUENCE OF, so a token carrying a zero length one decodes without error. RFC 4178
		// Section 4.2.1 defines the field as "one or more security mechanisms available for the initiator", so a
		// token offering none is malformed: there is no mechanism to negotiate.
		if len(n.MechTypes) == 0 {
			return false, nil, errors.New("NegTokenInit does not contain any mechanism types")
		}

		nt := NegTokenInit{
			MechTypes:      n.MechTypes,
			ReqFlags:       n.ReqFlags,
			MechTokenBytes: n.MechTokenBytes,
			MechListMIC:    n.MechListMIC,
			mechTypesRaw:   mechTypeListBytes(a.Bytes),
		}

		return true, nt, nil
	case 1:
		var n marshalNegTokenResp

		_, err = asn1.Unmarshal(a.Bytes, &n, asn1.WithUnmarshalAllowTypeGeneralString(true))
		if err != nil {
			return false, nil, fmt.Errorf("error unmarshalling NegotiationToken type %d (Resp/Targ): %w", a.Tag, err)
		}

		nt := NegTokenResp{
			NegState:      n.NegState,
			SupportedMech: n.SupportedMech,
			ResponseToken: n.ResponseToken,
			MechListMIC:   n.MechListMIC,
		}

		return false, nt, nil
	default:
		return false, nil, errors.New("unknown choice type for NegotiationToken")
	}
}

// mechTypeListBytes recovers the MechTypeList from the body of a NegTokenInit exactly as it arrived, which is the
// message a mechListMIC is computed over. It returns nil when the field cannot be read that way, leaving the caller
// to fall back on re-encoding the decoded list.
func mechTypeListBytes(b []byte) []byte {
	var raw struct {
		MechTypes asn1.RawValue `asn1:"explicit,tag:0"`
	}

	if _, err := asn1.Unmarshal(b, &raw, asn1.WithUnmarshalAllowTypeGeneralString(true)); err != nil {
		return nil
	}

	return raw.MechTypes.Bytes
}

// NewNegTokenInitKRB5 creates new Init negotiation token for Kerberos 5.
func NewNegTokenInitKRB5(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, opts ...KRB5TokenOption) (NegTokenInit, error) {
	// The Delegation option is not folded into these flags here: NewKRB5TokenAPREQ does that for every caller, so
	// that the option means the same thing whichever entry point receives it.
	flagsGSSAPI := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}

	mt, err := NewKRB5TokenAPREQ(cl, tkt, sessionKey, flagsGSSAPI, []int{}, opts...)
	if err != nil {
		return NegTokenInit{}, fmt.Errorf("error getting KRB5 token; %w", err)
	}

	mtb, err := mt.Marshal()
	if err != nil {
		return NegTokenInit{}, fmt.Errorf("error marshalling KRB5 token; %w", err)
	}

	// The token is kept as well as its bytes: an initiator that asked for mutual authentication has
	// to remember the ctime and cusec it sent in order to check the reply against them, and they are
	// inside the AP-REQ's encrypted authenticator — readable here, where it was just built, and
	// nowhere afterwards without decrypting it again.
	return NegTokenInit{
		MechTypes:      initiatorMechTypes(),
		MechTokenBytes: mtb,
		mechToken:      &mt,
	}, nil
}
