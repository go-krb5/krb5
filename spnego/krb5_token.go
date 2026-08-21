package spnego

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/client"
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

	if !isKerberosMech(oid) {
		return fmt.Errorf("error unmarshalling KRB5Token, OID is %s not %s or %s",
			oid.String(), gssapi.OIDKRB5.OID().String(), gssapi.OIDMSLegacyKRB5.OID().String())
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

			// RFC 2743 defines no GSS-API status more specific than a defective token for a delegated credential
			// this acceptor could not read, so this maps to the same StatusDefectiveToken as the fallback below.
			// The branch is kept explicit, matching ErrBadChannelBinding above, so that a future status more
			// specific than "defective token" has one place to be added without re-deriving which sentinel means
			// what.
			if errors.Is(err, service.ErrBadDelegation) {
				return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
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
	delegation     bool
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

// Delegation requests credential delegation: the AP_REQ will carry a forwarded ticket-granting ticket in the Deleg
// field of the authenticator checksum described by RFC 4121 Section 4.1.1, letting the service act as the client.
//
// This requires a forwardable TGT. Set forwardable = true in the libdefaults section of krb5.conf before
// authenticating, or the KDC will refuse to issue the forwarded ticket; this library defaults it to false.
//
// Delegation grants the service complete use of the client's identity, as RFC 4120 Section 2.6 describes. Request
// it only against services trusted with that.
//
//	s := SPNEGOClient(cl, spn, Delegation()).
func Delegation() KRB5TokenOption {
	return func(o *krb5TokenOptions) {
		o.delegation = true
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
//
// Delegation is requested either by the Delegation option or by gssapi.ContextFlagDeleg in flagsGSSAPI; the two are
// reconciled here, which is the single place every caller passes through. Folding the option into the flags in a
// caller instead would leave this entry point silently ignoring it and returning a non-delegating token to a caller
// that believed it had delegated.
func NewKRB5TokenAPREQ(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, flagsGSSAPI []int, optionsAP []int, opts ...KRB5TokenOption) (KRB5Token, error) {
	// TODO consider providing the SPN rather than the specific tkt and key and get these from the krb client.
	var m KRB5Token

	m.OID = gssapi.OIDKRB5.OID()
	tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REQ)
	m.tokID = tb

	opt := newKRB5TokenOptions(opts...)

	if opt.delegation && !delegationFlagged(flagsGSSAPI) {
		// Copied rather than appended in place: flagsGSSAPI belongs to the caller and may have spare capacity.
		flagsGSSAPI = append(append([]int(nil), flagsGSSAPI...), gssapi.ContextFlagDeleg)
	}

	auth, err := krb5TokenAuthenticator(cl, tkt, sessionKey, flagsGSSAPI, opt.channelBinding)
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

// newAuthenticatorChksum creates the authenticator checksum for a kerberos MechToken as described by RFC 4121
// Section 4.1.1.
//
// A nil channel binding leaves Bnd as the sixteen zero bytes that mean no channel bindings. A nil deleg produces
// the 24 octet checksum that carries no delegated credential.
//
// Requesting gssapi.ContextFlagDeleg without supplying deleg returns gssapi.ErrDelegationMissing: RFC 4121 Section
// 4.1.1 makes the delegation fields present if and only if the flag is set, and a checksum claiming a delegation
// it does not carry is rejected by MIT with GSS_S_FAILURE on reading DlgOpt as 0.
func newAuthenticatorChksum(flags []int, cb *gssapi.ChannelBinding, deleg []byte) ([]byte, error) {
	c := gssapi.AuthenticatorChecksum{
		Bnd:   cb.Bnd(),
		Deleg: deleg,
	}

	for _, i := range flags {
		c.Flags |= uint32(i) //nolint:gosec // G115: the GSS-API context flags are small positive constants.
	}

	return c.Marshal()
}

// krb5TokenAuthenticator creates a new kerberos authenticator for kerberos MechToken.
//
// When gssapi.ContextFlagDeleg is requested a forwarded TGT is obtained from the KDC and carried in the checksum as
// a KRB_CRED, encrypted under the session key of the ticket authenticating the context. RFC 4121 Section 4.1.1
// requires that key specifically: "The EncryptedData field of the KRB_CRED message MUST be encrypted in the session
// key of the ticket used to authenticate the context."
func krb5TokenAuthenticator(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, flags []int, cb *gssapi.ChannelBinding) (types.Authenticator, error) {
	// RFC 4121 Section 4.1.1.
	auth, err := types.NewAuthenticator(cl.Credentials.Domain(), cl.Credentials.CName())
	if err != nil {
		return auth, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}

	var deleg []byte

	if delegationRequested(cl, tkt, flags) {
		if deleg, err = delegatedCredential(cl, tkt, sessionKey); err != nil {
			return auth, err
		}
	}

	chksum, err := newAuthenticatorChksum(flags, cb, deleg)
	if err != nil {
		return auth, err
	}

	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  chksum,
	}

	// MS-KILE Section 3.2.5.2 has a client that supplies channel bindings also advertise KERB_AP_OPTIONS_CBT in
	// the authenticator's authorization data, which is how a Windows acceptor with ApplicationRequiresCBT tells a
	// binding-capable client from one predating the feature. The Bnd field alone does not carry that: an unbound
	// request and a request from a client that cannot bind at all look identical there.
	if cb != nil {
		if auth.AuthorizationData, err = types.ADAPOptions(types.ADAPOptionsCBT).AuthorizationData(); err != nil {
			return auth, krberror.Errorf(err, krberror.EncodingError, "error generating authenticator authorization data")
		}
	}

	return auth, nil
}

// delegationRequested reports whether any of the flags carries GSS_C_DELEG_FLAG. The bit is tested rather than the
// value because callers may combine flags into a single slice element.
func delegationRequested(cl *client.Client, tkt messages.Ticket, flags []int) bool {
	deleg, policy := delegationFlags(flags)

	// ContextFlagDelegPolicy asks that the KDC's opinion be honoured, so wherever it appears the ticket decides.
	// MIT differs here: because its flag mask sets GSS_C_DELEG_FLAG unconditionally, a caller passing both flags
	// delegates whether or not the ticket permits it, and only its enforce_ok_as_delegate configuration, which
	// replaces one flag with the other, produces the gate. A caller that names the policy flag at all has asked
	// for the gate, so honouring it is the reading that cannot surprise anyone into over-delegating.
	if policy {
		return cl.OKAsDelegate(tkt.SName)
	}

	return deleg
}

// delegationFlagged reports whether any delegation is being asked for, ignoring whether policy would permit it.
// It exists to keep the option plumbing from adding a flag the caller already supplied.
func delegationFlagged(flags []int) bool {
	deleg, policy := delegationFlags(flags)

	return deleg || policy
}

// delegationFlags reports which delegation flags appear. The bits are tested rather than the values, because
// callers may combine flags into a single slice element.
func delegationFlags(flags []int) (deleg, policy bool) {
	for _, i := range flags {
		if i&gssapi.ContextFlagDeleg != 0 {
			deleg = true
		}

		if i&gssapi.ContextFlagDelegPolicy != 0 {
			policy = true
		}
	}

	return deleg, policy
}

// delegatedCredential obtains a forwarded TGT and marshals it as the KRB_CRED that RFC 4121 Section 4.1.1 carries
// in the Deleg field of the authenticator checksum.
//
// Unlike MIT, which silently clears GSS_C_DELEG_FLAG when forwarding fails, a failure here is returned. This
// library has no ret_flags plumbing, so a caller could not observe the downgrade and would believe a delegation had
// happened that had not.
//
// Failures are wrapped with fmt.Errorf and %w rather than with krberror.Errorf. krberror.Krberror flattens what it
// wraps into strings and exposes no Unwrap, which would break the chain and leave a caller unable to tell
// client.ErrNotForwardable; the one failure with an operator-actionable remedy, from any other KDC error except by
// matching on substrings.
func delegatedCredential(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey) ([]byte, error) {
	ftgt, dep, err := cl.ForwardedTGT(tkt.SName, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("error obtaining a forwarded TGT to delegate: %w", err)
	}

	info := messages.NewKrbCredInfo(dep, cl.Credentials.CName(), cl.Credentials.Domain())

	cred, err := messages.NewKRBCred([]messages.Ticket{ftgt}, []messages.KrbCredInfo{info}, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("error building the KRB_CRED to delegate: %w", err)
	}

	b, err := cred.Marshal()
	if err != nil {
		return nil, fmt.Errorf("error marshalling the KRB_CRED to delegate: %w", err)
	}

	return b, nil
}

// isKerberosMech reports whether the object identifier names a Kerberos 5 GSS-API mechanism this library speaks.
func isKerberosMech(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(gssapi.OIDKRB5.OID()) || oid.Equal(gssapi.OIDMSLegacyKRB5.OID())
}
