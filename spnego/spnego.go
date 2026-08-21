// Package spnego implements the Simple and Protected GSSAPI Negotiation Mechanism for Kerberos authentication.
package spnego

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/types"
)

// SPNEGO implements the GSS-API mechanism for RFC 4178.
type SPNEGO struct {
	serviceSettings *service.Settings
	client          *client.Client
	spn             string
	tokenOptions    []KRB5TokenOption
	mechListMIC     []byte
	mechTypes       []asn1.ObjectIdentifier
	mechTypesRaw    []byte

	// What an initiator needs to check the acceptor's reply: the session key the AP-REP is
	// encrypted under, and the ctime/cusec it must echo. Set by InitSecContext and read by
	// VerifyMutual; both zero on an acceptor, which never initiates.
	sessionKey types.EncryptionKey
	sentCTime  time.Time
	sentCusec  int
}

// SPNEGOClient configures the SPNEGO mechanism suitable for client side use.
//
// Pass ChannelBinding to bind the context to the transport channel underneath it:
//
//	cb, err := gssapi.NewChannelBindingTLSServerEndPointFromState(&state)
//	s := SPNEGOClient(cl, spn, ChannelBinding(cb)).
func SPNEGOClient(cl *client.Client, spn string, opts ...KRB5TokenOption) *SPNEGO {
	s := new(SPNEGO)
	s.client = cl
	s.spn = spn
	s.tokenOptions = opts
	s.serviceSettings = service.NewSettings(nil, service.SName(spn))

	return s
}

// SPNEGOService configures the SPNEGO mechanism suitable for service side use.
func SPNEGOService(kt *keytab.Keytab, options ...func(*service.Settings)) *SPNEGO {
	s := new(SPNEGO)
	s.serviceSettings = service.NewSettings(kt, options...)

	return s
}

// OID returns the GSS-API assigned OID for SPNEGO.
func (s *SPNEGO) OID() asn1.ObjectIdentifier {
	return gssapi.OIDSPNEGO.OID()
}

// AcquireCred is the GSS-API method to acquire a client credential via Kerberos for SPNEGO.
func (s *SPNEGO) AcquireCred() error {
	return s.client.AffirmLogin()
}

// InitSecContext is the GSS-API method for the client to a generate a context token to the service via Kerberos.
func (s *SPNEGO) InitSecContext() (gssapi.ContextToken, error) {
	tkt, key, err := s.client.GetServiceTicket(s.spn)
	if err != nil {
		return &SPNEGOToken{}, err
	}

	negTokenInit, err := NewNegTokenInitKRB5(s.client, tkt, key, s.tokenOptions...)
	if err != nil {
		return &SPNEGOToken{}, fmt.Errorf("could not create NegTokenInit: %w", err)
	}

	s.sessionKey = key
	if mt, ok := negTokenInit.mechToken.(*KRB5Token); ok {
		s.sentCTime, s.sentCusec = mt.APReq.Authenticator.CTime, mt.APReq.Authenticator.Cusec
	}

	return &SPNEGOToken{
		Init:         true,
		NegTokenInit: negTokenInit,
		settings:     s.serviceSettings,
	}, nil
}

// AcceptSecContext is the GSS-API method for the service to verify the context token provided by the client and
// establish a context.
func (s *SPNEGO) AcceptSecContext(ct gssapi.ContextToken) (bool, context.Context, gssapi.Status) {
	var ctx context.Context

	t, ok := ct.(*SPNEGOToken)
	if !ok {
		return false, ctx, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "context token provided was not an SPNEGO token"}
	}

	t.settings = s.serviceSettings

	if t.Init && len(t.NegTokenInit.MechTypes) == 0 {
		return false, ctx, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "SPNEGO NegTokenInit does not contain any mechanism types"}
	}

	// Which mechanism a NegTokenInit selects is left to NegTokenInit.Verify, which searches the whole of mechTypes
	// rather than only its first entry. RFC 4178 Section 4.2.2 puts supportedMech "only in the first reply from
	// the target", so an initiator continuing an exchange names no mechanism here and the mech token decides; a
	// mechanism that is named and is not Kerberos is refused.
	if t.Resp && len(t.NegTokenResp.SupportedMech) > 0 && !isKerberosMech(t.NegTokenResp.SupportedMech) {
		return false, ctx, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "SPNEGO OID of MechToken is not of type KRB5"}
	}

	if t.Resp {
		t.NegTokenResp.mechTypes, t.NegTokenResp.mechTypesRaw = s.mechTypes, s.mechTypesRaw
	}

	// RFC 4178 Section 4.2.1 says of reqFlags that "the acceptor MUST ignore this reqFlags field", which is why
	// t.NegTokenInit.ReqFlags is read nowhere: it is not integrity protected and carries no authority.
	ok, status := t.Verify()
	ctx = t.Context()

	if t.Init {
		s.mechListMIC = t.NegTokenInit.respMechListMIC
		// The list is kept whatever the outcome, because the leg that offers it is the only one that carries it
		// and a mechListMIC on a later leg protects it.
		s.mechTypes, s.mechTypesRaw = t.NegTokenInit.MechTypes, t.NegTokenInit.mechTypesRaw
	} else {
		s.mechListMIC = t.NegTokenResp.respMechListMIC
	}

	return ok, ctx, status
}

// MechListMIC returns the mechListMIC this acceptor owes the initiator in its reply to the negotiation token it
// last accepted, or nil when no MIC was exchanged. RFC 4178 Section 5(c)(I) requires one whenever the initiator
// supplied one, and has the initiator verify it.
func (s *SPNEGO) MechListMIC() []byte {
	return s.mechListMIC
}

// Log will write to the service's logger if it is configured.
func (s *SPNEGO) Log(format string, v ...any) {
	if s.serviceSettings.Logger() != nil {
		s.serviceSettings.Logger().Output(2, fmt.Sprintf(format, v...))
	}
}

// SPNEGOToken is a GSS-API context token.
type SPNEGOToken struct {
	Init         bool
	Resp         bool
	NegTokenInit NegTokenInit
	NegTokenResp NegTokenResp
	settings     *service.Settings
	context      context.Context
}

// Marshal SPNEGO context token.
func (s *SPNEGOToken) Marshal() ([]byte, error) {
	var b []byte

	if s.Init {
		hb, _ := asn1.Marshal(gssapi.OIDSPNEGO.OID(), asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))

		tb, err := s.NegTokenInit.Marshal()
		if err != nil {
			return b, fmt.Errorf("could not marshal NegTokenInit: %w", err)
		}

		b = append(hb, tb...)

		return asn1tools.AddASNAppTag(b, 0), nil
	}

	if s.Resp {
		b, err := s.NegTokenResp.Marshal()
		if err != nil {
			return b, fmt.Errorf("could not marshal NegTokenResp: %w", err)
		}

		return b, nil
	}

	return b, errors.New("SPNEGO cannot be marshalled. It contains neither a NegTokenInit or NegTokenResp")
}

// Unmarshal SPNEGO context token.
func (s *SPNEGOToken) Unmarshal(b []byte) error {
	var (
		r   []byte
		err error
	)
	// We need some data in the array.

	if len(b) < 1 {
		return fmt.Errorf("provided byte array is empty")
	}

	if b[0] != byte(161) {
		// Not a NegTokenResp/Targ could be a NegTokenInit.
		var oid asn1.ObjectIdentifier

		r, err = asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
		if err != nil {
			return fmt.Errorf("not a valid SPNEGO token: %w", err)
		}
		// Check the OID is the SPNEGO OID value.
		SPNEGOOID := gssapi.OIDSPNEGO.OID()
		if !oid.Equal(SPNEGOOID) {
			return fmt.Errorf("OID %s does not match SPNEGO OID %s", oid.String(), SPNEGOOID.String())
		}
	} else {
		// Could be a NegTokenResp/Targ.
		r = b
	}

	_, nt, err := UnmarshalNegToken(r)
	if err != nil {
		return err
	}

	switch v := nt.(type) {
	case NegTokenInit:
		s.Init = true
		s.NegTokenInit = v
		s.NegTokenInit.settings = s.settings
	case NegTokenResp:
		s.Resp = true
		s.NegTokenResp = v
		s.NegTokenResp.settings = s.settings
	default:
		return errors.New("unknown choice type for NegotiationToken")
	}

	return nil
}

// Verify the SPNEGOToken.
func (s *SPNEGOToken) Verify() (bool, gssapi.Status) {
	if (!s.Init && !s.Resp) || (s.Init && s.Resp) {
		return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "invalid SPNEGO token, unclear if NegTokenInit or NegTokenResp"}
	}

	if s.Init {
		s.NegTokenInit.settings = s.settings

		ok, status := s.NegTokenInit.Verify()
		if ok {
			s.context = s.NegTokenInit.Context()
		}

		return ok, status
	}

	if s.Resp {
		s.NegTokenResp.settings = s.settings

		ok, status := s.NegTokenResp.Verify()
		if ok {
			s.context = s.NegTokenResp.Context()
		}

		return ok, status
	}
	// should not be possible to get here.
	return false, gssapi.Status{Code: gssapi.StatusFailure, Message: "unable to verify SPNEGO token"}
}

// Context returns the SPNEGO context which will contain any verify user identity information.
func (s *SPNEGOToken) Context() context.Context {
	return s.context
}
