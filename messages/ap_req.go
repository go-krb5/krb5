package messages

import (
	"fmt"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/asn1apptag"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/types"
)

type marshalAPReq struct {
	PVNO      int            `asn1:"explicit,tag:0"`
	MsgType   int            `asn1:"explicit,tag:1"`
	APOptions asn1.BitString `asn1:"explicit,tag:2"`
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag.
	Ticket                 asn1.RawValue       `asn1:"explicit,tag:3"`
	EncryptedAuthenticator types.EncryptedData `asn1:"explicit,tag:4"`
}

// APReq implements RFC 4120 KRB_AP_REQ: https://tools.ietf.org/html/rfc4120#section-5.5.1.
type APReq struct {
	PVNO                   int                 `asn1:"explicit,tag:0"`
	MsgType                int                 `asn1:"explicit,tag:1"`
	APOptions              asn1.BitString      `asn1:"explicit,tag:2"`
	Ticket                 Ticket              `asn1:"explicit,tag:3"`
	EncryptedAuthenticator types.EncryptedData `asn1:"explicit,tag:4"`
	Authenticator          types.Authenticator `asn1:"optional"`
}

// NewAPReq generates a new KRB_AP_REQ struct.
//
// The authenticator is encrypted with the AP-REQ key usage of RFC 4120 Section 7.5.1. An AP_REQ carried as a
// TGS-REQ's PA-TGS-REQ takes a different usage and is built by newAPReqPATGSReq.
func NewAPReq(tkt Ticket, sessionKey types.EncryptionKey, auth types.Authenticator) (APReq, error) {
	return newAPReq(tkt, sessionKey, auth, keyusage.AP_REQ_AUTHENTICATOR)
}

// newAPReqPATGSReq generates the KRB_AP_REQ a TGS-REQ carries as its PA-TGS-REQ pre-authentication data.
//
// RFC 4120 Section 7.5.1 assigns key usage 7 to the "TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator", which is a
// property of where the AP_REQ sits and not of what its ticket names. The ticket is a TGT whenever a new service
// ticket is being obtained, but it is the service ticket itself when one is being renewed, and both take usage 7.
func newAPReqPATGSReq(tkt Ticket, sessionKey types.EncryptionKey, auth types.Authenticator) (APReq, error) {
	return newAPReq(tkt, sessionKey, auth, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR)
}

func newAPReq(tkt Ticket, sessionKey types.EncryptionKey, auth types.Authenticator, usage int) (APReq, error) {
	var a APReq

	ed, err := encryptAuthenticator(auth, sessionKey, tkt, usage)
	if err != nil {
		return a, krberror.Errorf(err, krberror.KRBMsgError, "error creating Authenticator for AP_REQ")
	}

	a = APReq{
		PVNO:                   iana.PVNO,
		MsgType:                msgtype.KRB_AP_REQ,
		APOptions:              types.NewKrbFlags(),
		Ticket:                 tkt,
		EncryptedAuthenticator: ed,
		Authenticator:          auth,
	}

	return a, nil
}

// encryptAuthenticator encrypts the authenticator with the key usage its AP_REQ's position calls for.
func encryptAuthenticator(a types.Authenticator, sessionKey types.EncryptionKey, tkt Ticket, usage int) (types.EncryptedData, error) {
	var ed types.EncryptedData

	m, err := a.Marshal()
	if err != nil {
		return ed, krberror.Errorf(err, krberror.EncodingError, "marshaling error of EncryptedData form of Authenticator")
	}

	ed, err = crypto.GetEncryptedData(m, sessionKey, uint32(usage), tkt.EncPart.KVNO)
	if err != nil {
		return ed, krberror.Errorf(err, krberror.EncryptingError, "error encrypting Authenticator")
	}

	return ed, nil
}

// DecryptAuthenticator decrypts the Authenticator within the AP_REQ.
// sessionKey may simply be the key within the decrypted EncPart of the ticket within the AP_REQ.
func (a *APReq) DecryptAuthenticator(sessionKey types.EncryptionKey) (err error) {
	ab, err := crypto.DecryptEncPart(a.EncryptedAuthenticator, sessionKey, keyusage.AP_REQ_AUTHENTICATOR)
	if err != nil {
		return fmt.Errorf("error decrypting authenticator: %w", err)
	}

	if err = a.Authenticator.Unmarshal(ab); err != nil {
		return fmt.Errorf("error unmarshalling authenticator: %w", err)
	}

	return nil
}

// Unmarshal bytes b into the APReq struct.
func (a *APReq) Unmarshal(b []byte) error {
	var m marshalAPReq

	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asn1apptag.APREQ))
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "unmarshal error of AP_REQ")
	}

	if m.MsgType != msgtype.KRB_AP_REQ {
		return NewKRBError(types.PrincipalName{}, "", errorcode.KRB_AP_ERR_MSG_TYPE, errorcode.Lookup(errorcode.KRB_AP_ERR_MSG_TYPE))
	}

	a.PVNO = m.PVNO
	a.MsgType = m.MsgType
	a.APOptions = m.APOptions
	a.EncryptedAuthenticator = m.EncryptedAuthenticator

	a.Ticket, err = unmarshalTicket(m.Ticket.Bytes)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "unmarshalling error of Ticket within AP_REQ")
	}

	return nil
}

// Marshal APReq struct.
func (a *APReq) Marshal() ([]byte, error) {
	m := marshalAPReq{
		PVNO:                   a.PVNO,
		MsgType:                a.MsgType,
		APOptions:              a.APOptions,
		EncryptedAuthenticator: a.EncryptedAuthenticator,
	}

	var b []byte

	b, err := a.Ticket.Marshal()
	if err != nil {
		return b, err
	}

	m.Ticket = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        3,
		Bytes:      b,
	}

	mk, err := asn1.Marshal(m, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return mk, krberror.Errorf(err, krberror.EncodingError, "marshaling error of AP_REQ")
	}

	mk = asn1tools.AddASNAppTag(mk, asn1apptag.APREQ)

	return mk, nil
}

// Verify an AP_REQ using service's keytab, spn and max acceptable clock skew duration.
// The service ticket encrypted part and authenticator will be decrypted as part of this operation.
func (a *APReq) Verify(kt *keytab.Keytab, d time.Duration, cAddr types.HostAddress, snameOverride *types.PrincipalName) (bool, error) {
	// Decrypt ticket's encrypted part with service key
	// TODO decrypt with service's session key from its TGT is use-to-user. Need to figure out how to get TGT.
	// if types.IsFlagSet(&a.APOptions, flags.APOptionUseSessionKey) {
	//	err := a.Ticket.Decrypt(tgt.DecryptedEncPart.Key)
	//	if err != nil {
	//		return false, krberror.Errorf(err, krberror.DecryptingError, "error decrypting encpart of ticket provided using session key")
	//	}
	// } else {
	//	err := a.Ticket.DecryptEncPart(*kt, &a.Ticket.SName)
	//	if err != nil {
	//		return false, krberror.Errorf(err, krberror.DecryptingError, "error decrypting encpart of service ticket provided")
	//	}
	// }.
	sname := &a.Ticket.SName
	if snameOverride != nil {
		sname = snameOverride
	}

	err := a.Ticket.DecryptEncPart(kt, sname)
	if err != nil {
		return false, krberror.Errorf(err, krberror.DecryptingError, "error decrypting encpart of service ticket provided")
	}

	// Check time validity of ticket.
	ok, err := a.Ticket.Valid(d)
	if err != nil || !ok {
		return ok, err
	}

	// Check client's address is listed in the client addresses in the ticket.
	if len(a.Ticket.DecryptedEncPart.CAddr) > 0 {
		// If client addresses are present check if any of them match the source IP that sent the APReq
		// If there is no match return KRB_AP_ERR_BADADDR error.
		if !types.HostAddressesContains(a.Ticket.DecryptedEncPart.CAddr, cAddr) {
			return false, NewKRBError(a.Ticket.SName, a.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "client address not within the list contained in the service ticket")
		}
	}

	// Decrypt authenticator with session key from ticket's encrypted part.
	err = a.DecryptAuthenticator(a.Ticket.DecryptedEncPart.Key)
	if err != nil {
		return false, NewKRBError(a.Ticket.SName, a.Ticket.Realm, errorcode.KRB_AP_ERR_BAD_INTEGRITY, "could not decrypt authenticator")
	}

	// Check the client name and realm in the authenticator are the same as those in the ticket. RFC 4120 section 3.2.3
	// requires both to be compared. The authenticator is generated by the client and sealed only under the session key
	// the client holds, so its client identity is not trustworthy on its own; only the ticket's encrypted part is
	// sealed by the KDC. Omitting the realm comparison would let a client present a ticket for its own principal while
	// naming any realm it chooses in the authenticator.
	if !a.Authenticator.CName.Equal(a.Ticket.DecryptedEncPart.CName) {
		return false, NewKRBError(a.Ticket.SName, a.Ticket.Realm, errorcode.KRB_AP_ERR_BADMATCH, "CName in Authenticator does not match that in service ticket")
	}

	if a.Authenticator.CRealm != a.Ticket.DecryptedEncPart.CRealm {
		return false, NewKRBError(a.Ticket.SName, a.Ticket.Realm, errorcode.KRB_AP_ERR_BADMATCH, "CRealm in Authenticator does not match that in service ticket")
	}

	// Check the clock skew between the client and the service server.
	ct := a.Authenticator.CTime.Add(time.Duration(a.Authenticator.Cusec) * time.Microsecond)

	t := time.Now().UTC()
	if t.Sub(ct) > d || ct.Sub(t) > d {
		return false, NewKRBError(a.Ticket.SName, a.Ticket.Realm, errorcode.KRB_AP_ERR_SKEW, fmt.Sprintf("clock skew with client too large. greater than %v seconds", d))
	}

	return true, nil
}
