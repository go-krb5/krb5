package spnego

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/types"
)

// GSSAPI KRB5 MechToken IDs.
const (
	TOK_ID_KRB_AP_REQ = "0100"
	TOK_ID_KRB_AP_REP = "0200"
	TOK_ID_KRB_ERROR  = "0300"
)

// KRB5Token context token implementation for GSSAPI.
type KRB5Token struct {
	OID      asn1.ObjectIdentifier
	tokID    []byte
	APReq    messages.APReq
	APRep    messages.APRep
	KRBError messages.KRBError
	settings *service.Settings
	context  context.Context
}

// Marshal a KRB5Token into a slice of bytes.
func (m *KRB5Token) Marshal() ([]byte, error) {
	// Create the header.
	b, _ := asn1.Marshal(m.OID, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	b = append(b, m.tokID...)

	var (
		tb  []byte
		err error
	)

	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		tb, err = m.APReq.Marshal()
		if err != nil {
			return []byte{}, fmt.Errorf("error marshalling AP_REQ for MechToken: %w", err)
		}
	case TOK_ID_KRB_AP_REP:
		return []byte{}, errors.New("marshal of AP_REP GSSAPI MechToken not supported by krb5")
	case TOK_ID_KRB_ERROR:
		return []byte{}, errors.New("marshal of KRB_ERROR GSSAPI MechToken not supported by krb5")
	}

	if err != nil {
		return []byte{}, fmt.Errorf("error mashalling kerberos message within mech token: %w", err)
	}

	b = append(b, tb...)

	return asn1tools.AddASNAppTag(b, 0), nil
}

// Unmarshal a KRB5Token.
func (m *KRB5Token) Unmarshal(b []byte) error {
	var oid asn1.ObjectIdentifier

	r, err := asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
	if err != nil {
		return fmt.Errorf("error unmarshalling KRB5Token OID: %w", err)
	}

	if !oid.Equal(gssapi.OIDKRB5.OID()) {
		return fmt.Errorf("error unmarshalling KRB5Token, OID is %s not %s", oid.String(), gssapi.OIDKRB5.OID().String())
	}

	m.OID = oid

	if len(r) < 2 {
		return fmt.Errorf("krb5token too short")
	}

	m.tokID = r[0:2]
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		var a messages.APReq

		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REQ: %w", err)
		}

		m.APReq = a
	case TOK_ID_KRB_AP_REP:
		var a messages.APRep

		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REP: %w", err)
		}

		m.APRep = a
	case TOK_ID_KRB_ERROR:
		var a messages.KRBError

		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token KRBError: %w", err)
		}

		m.KRBError = a
	}

	return nil
}

// Verify a KRB5Token.
func (m *KRB5Token) Verify() (bool, gssapi.Status) {
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		ok, creds, err := service.VerifyAPREQ(&m.APReq, m.settings)
		if err != nil {
			// RFC 2743 Section 2.2.2 separates a credential presented over the wrong channel from a malformed
			// token. Reporting a channel binding failure as a defective token would leave the initiator unable to
			// tell the two apart, and unable to tell that it is the channel rather than its credential at fault.
			if errors.Is(err, service.ErrBadChannelBinding) {
				return false, gssapi.Status{Code: gssapi.StatusBadBindings, Message: err.Error()}
			}

			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}

		if !ok {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveCredential, Message: "KRB5_AP_REQ token not valid"}
		}

		m.context = context.Background()
		m.context = context.WithValue(m.context, CTXKey, creds)

		return true, gssapi.Status{Code: gssapi.StatusComplete}
	case TOK_ID_KRB_AP_REP:
		// Client side
		// TODO how to verify the AP_REP - not yet implemented.
		return false, gssapi.Status{Code: gssapi.StatusFailure, Message: "verifying an AP_REP is not currently supported by krb5"}
	case TOK_ID_KRB_ERROR:
		if m.KRBError.MsgType != msgtype.KRB_ERROR {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "KRB5_Error token not valid"}
		}

		return true, gssapi.Status{Code: gssapi.StatusUnavailable}
	}

	return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "unknown TOK_ID in KRB5 token"}
}

// IsAPReq tests if the MechToken contains an AP_REQ.
func (m *KRB5Token) IsAPReq() bool {
	return hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REQ
}

// IsAPRep tests if the MechToken contains an AP_REP.
func (m *KRB5Token) IsAPRep() bool {
	return hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REP
}

// IsKRBError tests if the MechToken contains an KRB_ERROR.
func (m *KRB5Token) IsKRBError() bool {
	return hex.EncodeToString(m.tokID) == TOK_ID_KRB_ERROR
}

// Context returns the KRB5 token's context which will contain any verify user identity information.
func (m *KRB5Token) Context() context.Context {
	return m.context
}

// KRB5TokenOption configures optional content of a KRB5Token.
type KRB5TokenOption func(*krb5TokenOptions)

// krb5TokenOptions holds the resolved options for creating a KRB5Token.
type krb5TokenOptions struct {
	channelBinding *gssapi.ChannelBinding
}

// ChannelBinding configures the GSS-API channel binding to bind the AP_REQ to. The hash of the binding is carried in
// the Bnd field of the authenticator checksum described by RFC 4121 Section 4.1.1.
//
// A nil binding means no channel bindings, which is the default.
//
//	cb, err := gssapi.NewChannelBindingTLSServerEndPointFromState(&state)
//	s := SPNEGOClient(cl, spn, ChannelBinding(cb)).
func ChannelBinding(cb *gssapi.ChannelBinding) KRB5TokenOption {
	return func(o *krb5TokenOptions) {
		o.channelBinding = cb
	}
}

// newKRB5TokenOptions resolves the options provided, applying them in order so that the last value wins.
func newKRB5TokenOptions(opts ...KRB5TokenOption) *krb5TokenOptions {
	o := new(krb5TokenOptions)

	for _, opt := range opts {
		opt(o)
	}

	return o
}

// NewKRB5TokenAPREQ creates a new KRB5 token with AP_REQ.
func NewKRB5TokenAPREQ(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, flagsGSSAPI []int, optionsAP []int, opts ...KRB5TokenOption) (KRB5Token, error) {
	// TODO consider providing the SPN rather than the specific tkt and key and get these from the krb client.
	var m KRB5Token

	m.OID = gssapi.OIDKRB5.OID()
	tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REQ)
	m.tokID = tb

	auth, err := krb5TokenAuthenticator(cl.Credentials, flagsGSSAPI, newKRB5TokenOptions(opts...).channelBinding)
	if err != nil {
		return m, err
	}

	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		auth,
	)
	if err != nil {
		return m, err
	}

	for _, o := range optionsAP {
		types.SetFlag(&APReq.APOptions, o)
	}

	m.APReq = APReq

	return m, nil
}

// krb5TokenAuthenticator creates a new kerberos authenticator for kerberos MechToken.
func krb5TokenAuthenticator(creds *credentials.Credentials, flags []int, cb *gssapi.ChannelBinding) (types.Authenticator, error) {
	// RFC 4121 Section 4.1.1.
	auth, err := types.NewAuthenticator(creds.Domain(), creds.CName())
	if err != nil {
		return auth, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}

	chksum, err := newAuthenticatorChksum(flags, cb)
	if err != nil {
		return auth, err
	}

	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  chksum,
	}

	return auth, nil
}

// ErrDelegationUnimplemented is returned when gssapi.ContextFlagDeleg is requested. RFC 4121 Section 4.1.1 requires
// the delegation option identifier in DlgOpt and a KRB_CRED in Deleg whenever the flag is set; this library
// implements neither, so it refuses the request rather than emitting a checksum that claims a delegation it cannot
// perform. Callers match against it with errors.Is.
var ErrDelegationUnimplemented = errors.New("credential delegation is not implemented")

// newAuthenticatorChksum creates the authenticator checksum for a kerberos MechToken as described by RFC 4121
// Section 4.1.1: a four byte Lgth of 16, the sixteen byte Bnd channel bindings hash and the four byte context flags.
// The result is always 24 bytes.
//
// A nil channel binding leaves Bnd as the sixteen zero bytes that mean no channel bindings.
//
// Requesting gssapi.ContextFlagDeleg returns ErrDelegationUnimplemented. Setting the flag obliges the initiator to
// populate the DlgOpt, Dlgth and Deleg fields that follow Flags, and this library has no KRB_CRED to put there:
// messages.KRBCred can be received but not emitted, and nothing acquires a forwarded TGT. Emitting the flag with
// those fields zeroed is what this used to do, and MIT rejects it with GSS_S_FAILURE on reading DlgOpt as 0, so the
// refusal costs no working deployment anything. Nothing in this library requests the flag: both SPNEGO paths ask for
// ContextFlagInteg and ContextFlagConf only.
func newAuthenticatorChksum(flags []int, cb *gssapi.ChannelBinding) ([]byte, error) {
	for _, i := range flags {
		if i&gssapi.ContextFlagDeleg != 0 {
			return nil, fmt.Errorf("%w: RFC 4121 Section 4.1.1 requires DlgOpt to carry the delegation option identifier 1 and Deleg to carry a KRB_CRED", ErrDelegationUnimplemented)
		}
	}

	a := make([]byte, 24)
	binary.LittleEndian.PutUint32(a[:4], 16)

	bnd := cb.Bnd()
	copy(a[4:20], bnd[:])

	for _, i := range flags {
		f := binary.LittleEndian.Uint32(a[20:24])

		f |= uint32(i)

		binary.LittleEndian.PutUint32(a[20:24], f)
	}

	return a, nil
}
