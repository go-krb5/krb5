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
	MechTypes      []asn1.ObjectIdentifier
	ReqFlags       asn1.BitString
	MechTokenBytes []byte
	MechListMIC    []byte
	mechToken      gssapi.ContextToken
	settings       *service.Settings
	// rawMechTypesDER stores the exact DER encoding of the MechTypes SEQUENCE.
	// This is critical for mechListMIC computation per RFC 4178 - the MIC
	// must be computed over the exact bytes, not a re-encoded version.
	rawMechTypesDER []byte
	// initialSeqNum stores the Authenticator's sequence number from the AP-REQ.
	// This should be used to initialize the client's send sequence number
	// per RFC 4121.
	initialSeqNum int64
}

type marshalNegTokenInit struct {
	MechTypes []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`

	ReqFlags asn1.BitString `asn1:"explicit,optional,tag:1"`

	MechTokenBytes []byte `asn1:"explicit,optional,omitempty,tag:2"`

	// This field is not used when negotiating Kerberos tokens.
	MechListMIC []byte `asn1:"explicit,optional,omitempty,tag:3"`
}

// NegTokenResp implements Negotiation Token of type Resp/Targ.
type NegTokenResp struct {
	NegState      asn1.Enumerated
	SupportedMech asn1.ObjectIdentifier
	ResponseToken []byte
	MechListMIC   []byte
	mechToken     gssapi.ContextToken
	settings      *service.Settings
}

type marshalNegTokenResp struct {
	NegState asn1.Enumerated `asn1:"explicit,tag:0"`

	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`

	ResponseToken []byte `asn1:"explicit,optional,omitempty,tag:2"`

	// This field is not used when negotiating Kerberos tokens.
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
	n.rawMechTypesDER = nInit.rawMechTypesDER

	return nil
}

// RawMechTypesDER returns the raw DER encoding of the MechTypes SEQUENCE.
// This is needed for mechListMIC computation per RFC 4178.
func (n *NegTokenInit) RawMechTypesDER() []byte {
	return n.rawMechTypesDER
}

// SetRawMechTypesDER sets the raw DER encoding of the MechTypes SEQUENCE.
// This should be called when creating a NegTokenInit to ensure proper
// mechListMIC computation.
func (n *NegTokenInit) SetRawMechTypesDER(der []byte) {
	n.rawMechTypesDER = make([]byte, len(der))
	copy(n.rawMechTypesDER, der)
}

// InitialSeqNum returns the Authenticator's sequence number from the AP-REQ.
// This should be used to initialize the client's send sequence number.
func (n *NegTokenInit) InitialSeqNum() int64 {
	return n.initialSeqNum
}

// Verify an Init negotiation token.
func (n *NegTokenInit) Verify() (bool, gssapi.Status) {
	var mtSupported bool

	for _, m := range n.MechTypes {
		if m.Equal(gssapi.OIDKRB5.OID()) || m.Equal(gssapi.OIDMSLegacyKRB5.OID()) {
			if n.mechToken == nil && n.MechTokenBytes == nil {
				return false, gssapi.Status{Code: gssapi.StatusContinueNeeded}
			}

			mtSupported = true

			break
		}
	}

	if !mtSupported {
		return false, gssapi.Status{Code: gssapi.StatusBadMech, Message: "no supported mechanism specified in negotiation"}
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

	return n.mechToken.Verify()
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
func (n *NegTokenResp) Verify() (bool, gssapi.Status) {
	if n.SupportedMech.Equal(gssapi.OIDKRB5.OID()) || n.SupportedMech.Equal(gssapi.OIDMSLegacyKRB5.OID()) {
		if n.mechToken == nil && n.ResponseToken == nil {
			return false, gssapi.Status{Code: gssapi.StatusContinueNeeded}
		}

		mt := new(KRB5Token)

		mt.settings = n.settings
		if n.mechToken == nil {
			err := mt.Unmarshal(n.ResponseToken)
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

		if mt == nil {
			return false, gssapi.Status{Code: gssapi.StatusContinueNeeded}
		}
		// Verify the mechtoken.
		return mt.Verify()
	}

	return false, gssapi.Status{Code: gssapi.StatusBadMech, Message: "no supported mechanism specified in negotiation"}
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

// GetKRB5Token returns the KRB5Token from the ResponseToken field.
// This is useful for client-side processing of AP-REP tokens.
func (n *NegTokenResp) GetKRB5Token() (*KRB5Token, error) {
	if n.ResponseToken == nil {
		return nil, errors.New("no response token present")
	}

	if n.mechToken != nil {
		mt, ok := n.mechToken.(*KRB5Token)
		if ok {
			return mt, nil
		}
	}

	mt := new(KRB5Token)
	if err := mt.Unmarshal(n.ResponseToken); err != nil {
		return nil, fmt.Errorf("error unmarshalling response token: %w", err)
	}

	n.mechToken = mt

	return mt, nil
}

// HasMechListMIC returns true if the NegTokenResp contains a mechListMIC.
func (n *NegTokenResp) HasMechListMIC() bool {
	return len(n.MechListMIC) > 0
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

		// Extract raw MechTypes DER bytes for mechListMIC computation.
		// Per RFC 4178, the MIC must be computed over the exact DER bytes.
		rawMechTypesDER, err := extractRawMechTypesDER(a.Bytes)
		if err != nil {
			return false, nil, fmt.Errorf("error extracting raw MechTypes DER: %w", err)
		}

		nt := NegTokenInit{
			MechTypes:       n.MechTypes,
			ReqFlags:        n.ReqFlags,
			MechTokenBytes:  n.MechTokenBytes,
			MechListMIC:     n.MechListMIC,
			rawMechTypesDER: rawMechTypesDER,
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

// extractRawMechTypesDER extracts the raw DER bytes of the MechTypes field from a NegTokenInit.
// The input is the inner bytes of the NegTokenInit (after the context tag).
// The MechTypes field is at context tag [0] and contains a SEQUENCE OF OID.
func extractRawMechTypesDER(b []byte) ([]byte, error) {
	// Parse the SEQUENCE containing the NegTokenInit fields.
	var seq asn1.RawValue

	rest, err := asn1.Unmarshal(b, &seq)
	if err != nil {
		return nil, fmt.Errorf("error parsing NegTokenInit SEQUENCE: %w", err)
	}

	if len(rest) > 0 {
		return nil, errors.New("trailing data after NegTokenInit SEQUENCE")
	}

	// Parse the first field which should be the context-tagged [0] MechTypes.
	var mechTypesField asn1.RawValue

	_, err = asn1.Unmarshal(seq.Bytes, &mechTypesField)
	if err != nil {
		return nil, fmt.Errorf("error parsing MechTypes field: %w", err)
	}

	// The mechTypesField.Bytes contains the SEQUENCE OF OID.
	// We need to return just the SEQUENCE OF OID, not the context tag wrapper.
	// The mechTypesField.FullBytes would include the context tag, but we need
	// the inner SEQUENCE for MIC computation per RFC 4178.
	return mechTypesField.Bytes, nil
}

// NewNegTokenInitKRB5 creates new Init negotiation token for Kerberos 5.
func NewNegTokenInitKRB5(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey) (NegTokenInit, error) {
	return NewNegTokenInitKRB5WithFlags(cl, tkt, sessionKey, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, []int{})
}

// NewNegTokenInitKRB5WithFlags creates new Init negotiation token for Kerberos 5 with custom flags.
func NewNegTokenInitKRB5WithFlags(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, flagsGSSAPI []int, optionsAP []int) (NegTokenInit, error) {
	result, err := NewKRB5TokenAPREQ(cl, tkt, sessionKey, flagsGSSAPI, optionsAP)
	if err != nil {
		return NegTokenInit{}, fmt.Errorf("error getting KRB5 token; %w", err)
	}

	mtb, err := result.Token.Marshal()
	if err != nil {
		return NegTokenInit{}, fmt.Errorf("error marshalling KRB5 token; %w", err)
	}

	mechTypes := []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}

	// Marshal the MechTypes to get the raw DER bytes for MIC computation.
	rawMechTypesDER, err := asn1.Marshal(mechTypes, asn1.WithMarshalSlicePreserveTypes(true))
	if err != nil {
		return NegTokenInit{}, fmt.Errorf("error marshalling MechTypes for MIC; %w", err)
	}

	return NegTokenInit{
		MechTypes:       mechTypes,
		MechTokenBytes:  mtb,
		rawMechTypesDER: rawMechTypesDER,
		initialSeqNum:   result.SeqNum,
	}, nil
}
