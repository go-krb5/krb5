package messages

import (
	"fmt"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/asn1apptag"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/types"
)

type marshalKRBCred struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	Tickets asn1.RawValue       `asn1:"explicit,tag:2"`
	EncPart types.EncryptedData `asn1:"explicit,tag:3"`
}

// KRBCred implements RFC 4120 KRB_CRED: https://tools.ietf.org/html/rfc4120#section-5.8.1.
type KRBCred struct {
	PVNO             int
	MsgType          int
	Tickets          []Ticket
	EncPart          types.EncryptedData
	DecryptedEncPart EncKrbCredPart
}

// EncKrbCredPart is the encrypted part of KRB_CRED.
type EncKrbCredPart struct {
	TicketInfo []KrbCredInfo     `asn1:"explicit,tag:0"`
	Nouce      int               `asn1:"optional,explicit,tag:1"`
	Timestamp  time.Time         `asn1:"generalized,optional,explicit,tag:2"`
	Usec       int               `asn1:"optional,explicit,tag:3"`
	SAddress   types.HostAddress `asn1:"optional,explicit,tag:4"`
	RAddress   types.HostAddress `asn1:"optional,explicit,tag:5"`
}

// KrbCredInfo is the KRB_CRED_INFO part of KRB_CRED.
type KrbCredInfo struct {
	Key       types.EncryptionKey `asn1:"explicit,tag:0"`
	PRealm    string              `asn1:"general,optional,explicit,tag:1"`
	PName     types.PrincipalName `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString      `asn1:"optional,explicit,tag:3"`
	AuthTime  time.Time           `asn1:"generalized,optional,explicit,tag:4"`
	StartTime time.Time           `asn1:"generalized,optional,explicit,tag:5"`
	EndTime   time.Time           `asn1:"generalized,optional,explicit,tag:6"`
	RenewTill time.Time           `asn1:"generalized,optional,explicit,tag:7"`
	SRealm    string              `asn1:"optional,explicit,ia5,tag:8"`
	SName     types.PrincipalName `asn1:"optional,explicit,tag:9"`
	CAddr     types.HostAddresses `asn1:"optional,explicit,tag:10"`
}

// NewKRBCred builds a KRB_CRED conveying the tickets given, with info[i] describing tkts[i] as RFC 4120 Section
// 5.8.1 requires: "Successive tickets are paired with the corresponding KrbCredInfo sequence from the enc-part".
//
// The EncKrbCredPart is encrypted under key with key usage 14, per RFC 4120 Section 5.8.1. For the GSS-API
// delegation of RFC 4121 Section 4.1.1 that key is the session key of the ticket authenticating the context.
func NewKRBCred(tkts []Ticket, info []KrbCredInfo, key types.EncryptionKey) (KRBCred, error) {
	var k KRBCred

	if len(tkts) != len(info) {
		return k, krberror.NewErrorf(krberror.KRBMsgError,
			"KRB_CRED carries %d tickets and %d KrbCredInfo entries; they must correspond", len(tkts), len(info))
	}

	denc := EncKrbCredPart{TicketInfo: info}

	b, err := denc.Marshal()
	if err != nil {
		return k, krberror.Errorf(err, krberror.EncodingError, "error marshalling EncKrbCredPart")
	}

	ed, err := crypto.GetEncryptedData(b, key, keyusage.KRB_CRED_ENCPART, 0)
	if err != nil {
		return k, krberror.Errorf(err, krberror.EncryptingError, "error encrypting KRB_CRED EncPart")
	}

	return KRBCred{
		PVNO:             iana.PVNO,
		MsgType:          msgtype.KRB_CRED,
		Tickets:          tkts,
		EncPart:          ed,
		DecryptedEncPart: denc,
	}, nil
}

// NewKrbCredInfo builds the KrbCredInfo describing a ticket obtained from a KDC exchange. RFC 4120 Section 5.8.1
// defines these fields as "the values of the corresponding fields from the ticket found in the ticket field", with
// prealm and pname naming "the delegated principal identity".
func NewKrbCredInfo(dep EncKDCRepPart, cname types.PrincipalName, crealm string) KrbCredInfo {
	return KrbCredInfo{
		Key:       dep.Key,
		PRealm:    crealm,
		PName:     cname,
		Flags:     dep.Flags,
		AuthTime:  dep.AuthTime,
		StartTime: dep.StartTime,
		EndTime:   dep.EndTime,
		RenewTill: dep.RenewTill,
		SRealm:    dep.SRealm,
		SName:     dep.SName,
		CAddr:     types.HostAddresses(dep.CAddr),
	}
}

// Marshal the KRB_CRED.
func (k *KRBCred) Marshal() ([]byte, error) {
	m := marshalKRBCred{
		PVNO:    k.PVNO,
		MsgType: k.MsgType,
		EncPart: k.EncPart,
	}

	var err error

	if m.Tickets, err = MarshalTicketSequence(k.Tickets); err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "error marshalling tickets within KRB_CRED")
	}
	// MarshalTicketSequence does not set Tag: it must match this field's explicit tag number, as
	// KDCReqBody.Marshal does for AdditionalTickets.
	m.Tickets.Tag = 2

	b, err := asn1.Marshal(m, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "error marshalling KRB_CRED")
	}

	return asn1tools.AddASNAppTag(b, asn1apptag.KRBCred), nil
}

// Unmarshal bytes b into the KRBCred struct.
func (k *KRBCred) Unmarshal(b []byte) error {
	var m marshalKRBCred

	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asn1apptag.KRBCred))
	if err != nil {
		return processUnmarshalReplyError(b, err)
	}

	expectedMsgType := msgtype.KRB_CRED
	if m.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a KRB_CRED. Expected: %v; Actual: %v", expectedMsgType, m.MsgType)
	}

	k.PVNO = m.PVNO
	k.MsgType = m.MsgType

	k.EncPart = m.EncPart
	if len(m.Tickets.Bytes) > 0 {
		k.Tickets, err = unmarshalTicketsSequence(m.Tickets)
		if err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "error unmarshalling tickets within KRB_CRED")
		}
	}

	return nil
}

// DecryptEncPart decrypts the encrypted part of a KRB_CRED.
//
// An EncPart whose EType is zero is not encrypted and its Cipher field is the EncKrbCredPart itself. RFC 4120
// Section 5.8.1 records that some GSS-API mechanism implementations send it that way, and that this is not a
// vulnerability because the whole KRB_CRED is already inside an encrypted message. This library accepts that form
// and never emits it.
func (k *KRBCred) DecryptEncPart(key types.EncryptionKey) error {
	b := k.EncPart.Cipher

	if k.EncPart.EType != 0 {
		var err error

		if b, err = crypto.DecryptEncPart(k.EncPart, key, keyusage.KRB_CRED_ENCPART); err != nil {
			return krberror.Errorf(err, krberror.DecryptingError, "error decrypting KRB_CRED EncPart")
		}
	}

	var denc EncKrbCredPart

	if err := denc.Unmarshal(b); err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error unmarshalling encrypted part of KRB_CRED")
	}

	k.DecryptedEncPart = denc

	return nil
}

// CCache converts a decrypted KRB_CRED into a version 4 credential cache, which client.NewFromCCache accepts. Call
// DecryptEncPart first.
//
// The default principal is taken from the first KrbCredInfo's pname and prealm, which RFC 4120 Section 5.8.1 names
// as "the delegated principal identity".
func (k *KRBCred) CCache() (*credentials.CCache, error) {
	info := k.DecryptedEncPart.TicketInfo

	if len(info) == 0 {
		return nil, krberror.NewErrorf(krberror.KRBMsgError, "KRB_CRED conveys no credentials")
	}

	if len(k.Tickets) != len(info) {
		return nil, krberror.NewErrorf(krberror.KRBMsgError,
			"KRB_CRED carries %d tickets and %d KrbCredInfo entries; they must correspond", len(k.Tickets), len(info))
	}

	cc := credentials.NewV4CCache()
	cc.SetDefaultPrincipal(credentials.NewPrincipal(info[0].PName, info[0].PRealm))

	for i, in := range info {
		b, err := k.Tickets[i].Marshal()
		if err != nil {
			return nil, krberror.Errorf(err, krberror.EncodingError, "error marshalling ticket %d of KRB_CRED", i+1)
		}

		cc.AddCredential(&credentials.Credential{
			Client:      credentials.NewPrincipal(in.PName, in.PRealm),
			Server:      credentials.NewPrincipal(in.SName, in.SRealm),
			Key:         in.Key,
			AuthTime:    in.AuthTime,
			StartTime:   in.StartTime,
			EndTime:     in.EndTime,
			RenewTill:   in.RenewTill,
			TicketFlags: in.Flags,
			Addresses:   []types.HostAddress(in.CAddr),
			Ticket:      b,
		})
	}

	return cc, nil
}

// Marshal the encrypted part of a KRB_CRED.
//
// The optional nonce, timestamp, usec, s-address and r-address fields of RFC 4120 Section 5.8.1 are omitted when
// unset: the asn1 encoder drops an optional field at its zero value.
func (k *EncKrbCredPart) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*k, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "error marshalling EncKrbCredPart")
	}

	return asn1tools.AddASNAppTag(b, asn1apptag.EncKrbCredPart), nil
}

// Unmarshal bytes b into the encrypted part of KRB_CRED.
func (k *EncKrbCredPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%v", asn1apptag.EncKrbCredPart))
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error unmarshalling EncKrbCredPart")
	}

	return nil
}
