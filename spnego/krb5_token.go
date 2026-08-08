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

// VerifyAPRep verifies an AP_REP token using the provided client context.
// This is used for client-side mutual authentication. The session key from
// the context is used to decrypt the EncAPRepPart.
func (m *KRB5Token) VerifyAPRep(ctx *ClientContext) (bool, gssapi.Status) {
	if !m.IsAPRep() {
		return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "token is not an AP_REP"}
	}

	if err := ctx.ProcessAPRep(&m.APRep); err != nil {
		return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
	}

	return true, gssapi.Status{Code: gssapi.StatusComplete}
}

// GetKRBError returns the KRB_ERROR if this token contains one, or an error otherwise.
func (m *KRB5Token) GetKRBError() (*messages.KRBError, error) {
	if !m.IsKRBError() {
		return nil, errors.New("token is not a KRB_ERROR")
	}

	return &m.KRBError, nil
}

// Context returns the KRB5 token's context which will contain any verify user identity information.
func (m *KRB5Token) Context() context.Context {
	return m.context
}

// KRB5TokenResult contains the result of creating a KRB5 token, including
// the token and the authenticator sequence number for context initialization.
type KRB5TokenResult struct {
	Token  KRB5Token
	SeqNum int64
}

// NewKRB5TokenAPREQ creates a new KRB5 token with AP_REQ.
// Returns a KRB5TokenResult containing the token and the authenticator's
// sequence number, which should be used to initialize the security context.
func NewKRB5TokenAPREQ(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, flagsGSSAPI []int, optionsAP []int) (KRB5TokenResult, error) {
	// TODO consider providing the SPN rather than the specific tkt and key and get these from the krb client.
	var m KRB5Token

	m.OID = gssapi.OIDKRB5.OID()
	tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REQ)
	m.tokID = tb

	auth, err := krb5TokenAuthenticator(cl.Credentials, flagsGSSAPI)
	if err != nil {
		return KRB5TokenResult{}, err
	}

	// Capture the sequence number before the authenticator is encrypted.
	seqNum := auth.SeqNumber

	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		auth,
	)
	if err != nil {
		return KRB5TokenResult{}, err
	}

	for _, o := range optionsAP {
		types.SetFlag(&APReq.APOptions, o)
	}

	m.APReq = APReq

	return KRB5TokenResult{Token: m, SeqNum: seqNum}, nil
}

// krb5TokenAuthenticator creates a new kerberos authenticator for kerberos MechToken.
func krb5TokenAuthenticator(creds *credentials.Credentials, flags []int) (types.Authenticator, error) {
	// RFC 4121 Section 4.1.1.
	auth, err := types.NewAuthenticator(creds.Domain(), creds.CName())
	if err != nil {
		return auth, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}

	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  newAuthenticatorChksum(flags),
	}

	return auth, nil
}

// Create new authenticator checksum for kerberos MechToken.
func newAuthenticatorChksum(flags []int) []byte {
	a := make([]byte, 24)
	binary.LittleEndian.PutUint32(a[:4], 16)

	for _, i := range flags {
		if i == gssapi.ContextFlagDeleg {
			x := make([]byte, 28-len(a))
			a = append(a, x...)
		}

		f := binary.LittleEndian.Uint32(a[20:24])

		f |= uint32(i)

		binary.LittleEndian.PutUint32(a[20:24], f)
	}

	return a
}
