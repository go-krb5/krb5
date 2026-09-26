package messages

import (
	"errors"
	"fmt"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/types"
)

// ErrProtocolTransitionUnconfirmed is returned by TGSRep.VerifyProtocolTransition when the KDC's reply carries no
// PA-S4U-X509-USER, as it will from a KDC that does not implement MS-SFU Section 2.2.2. Callers match against it with
// errors.Is to fall back to another proof that the ticket is in the name requested.
var ErrProtocolTransitionUnconfirmed = errors.New("the KDC did not return a PA-S4U-X509-USER, so the ticket cannot be shown to be in the name requested")

// S4UUserID is the user-id of the PA-S4U-X509-USER pre-authentication data of MS-SFU Section 2.2.2.
//
//	S4UUserID ::= SEQUENCE {
//	    nonce               [0] UInt32,
//	    cname               [1] PrincipalName OPTIONAL,
//	    crealm              [2] Realm,
//	    subject-certificate [3] OCTET STRING OPTIONAL,
//	    options             [4] BIT STRING OPTIONAL,
//	    ...
//	}
type S4UUserID struct {
	Nonce              int                 `asn1:"explicit,tag:0"`
	CName              types.PrincipalName `asn1:"explicit,optional,tag:1"`
	CRealm             string              `asn1:"general,explicit,tag:2"`
	SubjectCertificate []byte              `asn1:"explicit,optional,tag:3"`
	Options            asn1.BitString      `asn1:"explicit,optional,tag:4"`
}

// Marshal the S4UUserID. This encoding is what the PA-S4U-X509-USER checksum covers.
func (u *S4UUserID) Marshal() ([]byte, error) {
	return asn1tools.Marshal(*u)
}

// PAS4UX509User implements the PA-S4U-X509-USER pre-authentication data of MS-SFU Section 2.2.2.
//
// A service sends it alongside PA-FOR-USER in a protocol transition (S4U2Self) request. Unlike PA-FOR-USER it is bound
// to the request by the nonce, and a KDC that honours it echoes it in the reply under a checksum keyed with the reply
// key, which is how the service learns that the ticket really is in the name it asked for.
//
//	PA-S4U-X509-USER ::= SEQUENCE {
//	    user-id  [0] S4UUserID,
//	    checksum [1] Checksum
//	}
type PAS4UX509User struct {
	UserID S4UUserID      `asn1:"explicit,tag:0"`
	Cksum  types.Checksum `asn1:"explicit,tag:1"`
}

// NewPAS4UX509User returns the PA-S4U-X509-USER naming user for the request with the given nonce, signed with the
// session key of the ticket-granting ticket the request is made with.
//
// The USE_REPLY_KEY_USAGE option is set, as MIT sets it, so that the KDC signs its echo under a different key usage
// than the request and the one cannot be reflected as the other.
func NewPAS4UX509User(nonce int, user types.PrincipalName, userRealm string, sessionKey types.EncryptionKey) (PAS4UX509User, error) {
	options := types.NewKrbFlags()
	types.SetFlag(&options, s4uOptionUseReplyKeyUsage)

	p := PAS4UX509User{UserID: S4UUserID{
		Nonce:   nonce,
		CName:   user,
		CRealm:  userRealm,
		Options: options,
	}}

	cksum, err := s4uUserIDChecksum(p.UserID, sessionKey, keyusage.PA_S4U_X509_USER_REQUEST)
	if err != nil {
		return p, err
	}

	p.Cksum = cksum

	return p, nil
}

// Marshal the PA-S4U-X509-USER.
func (p *PAS4UX509User) Marshal() ([]byte, error) {
	return asn1tools.Marshal(*p)
}

// Unmarshal bytes into the PA-S4U-X509-USER.
func (p *PAS4UX509User) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, p, asn1.WithUnmarshalAllowTypeGeneralString(true))

	return err
}

// PAData returns the PA-S4U-X509-USER as pre-authentication data of type PA_FOR_X509_USER.
func (p *PAS4UX509User) PAData() (types.PAData, error) {
	b, err := p.Marshal()
	if err != nil {
		return types.PAData{}, err
	}

	return types.PAData{PADataType: patype.PA_FOR_X509_USER, PADataValue: b}, nil
}

// VerifyProtocolTransition checks that the KDC honoured the PA-S4U-X509-USER of the protocol transition request
// tgsReq, which is what shows the ticket is in the name that was asked for.
//
// PA-FOR-USER is signed on its own and is not tied to the request, so one captured from an earlier request made with
// the same TGT can be put in place of the one sent. The reply's cname is plaintext and can be rewritten to match.
// The KDC's echo of the PA-S4U-X509-USER is signed with sessionKey, the key the reply is encrypted under, and carries
// the request's nonce and the user it was issued for, so it cannot be moved from another reply or made to name
// another user. It is looked for in the reply's pre-authentication data and then in its encrypted part, where MIT
// also places it for older encryption types. A reply without it returns ErrProtocolTransitionUnconfirmed; an echo
// that is present and does not verify returns another error, and must not be treated as missing.
func (k *TGSRep) VerifyProtocolTransition(tgsReq TGSReq, sessionKey types.EncryptionKey) error {
	req, ok, err := findPAS4UX509User(tgsReq.PAData)
	if err != nil {
		return fmt.Errorf("the request's PA-S4U-X509-USER is malformed: %w", err)
	}

	if !ok {
		return errors.New("the request carries no PA-S4U-X509-USER to verify the reply against")
	}

	rep, err := k.pas4uX509User()
	if err != nil {
		return err
	}

	if err = rep.verifyEcho(sessionKey); err != nil {
		return err
	}

	if rep.UserID.Nonce != req.UserID.Nonce {
		return errors.New("the KDC's PA-S4U-X509-USER answers another request")
	}

	if !rep.UserID.CName.Equal(req.UserID.CName) || rep.UserID.CRealm != req.UserID.CRealm {
		return fmt.Errorf("the KDC issued the ticket for %s@%s, not %s@%s", rep.UserID.CName.PrincipalNameString(), rep.UserID.CRealm, req.UserID.CName.PrincipalNameString(), req.UserID.CRealm)
	}

	return nil
}

func (k *TGSRep) pas4uX509User() (PAS4UX509User, error) {
	p, ok, err := findPAS4UX509User(k.PAData)
	if err == nil && !ok {
		p, ok, err = findPAS4UX509User(k.DecryptedEncPart.EncPAData)
	}

	if err != nil {
		return p, fmt.Errorf("the KDC's PA-S4U-X509-USER is malformed: %w", err)
	}

	if !ok {
		return p, ErrProtocolTransitionUnconfirmed
	}

	return p, nil
}

func (p *PAS4UX509User) verifyEcho(sessionKey types.EncryptionKey) error {
	usage := uint32(keyusage.PA_S4U_X509_USER_REQUEST)
	if types.IsFlagSet(&p.UserID.Options, s4uOptionUseReplyKeyUsage) {
		usage = keyusage.PA_S4U_X509_USER_REPLY
	}

	want, err := s4uUserIDChecksum(p.UserID, sessionKey, usage)
	if err != nil {
		return err
	}

	if p.Cksum.CksumType != want.CksumType {
		return fmt.Errorf("the KDC's PA-S4U-X509-USER checksum type %d is not that of the session key (%d)", p.Cksum.CksumType, want.CksumType)
	}

	et, err := crypto.GetEType(sessionKey.KeyType)
	if err != nil {
		return err
	}

	b, err := p.UserID.Marshal()
	if err != nil {
		return err
	}

	if !et.VerifyChecksum(sessionKey.KeyValue, b, p.Cksum.Checksum, usage) {
		return errors.New("the KDC's PA-S4U-X509-USER checksum does not verify under the session key")
	}

	return nil
}

const s4uOptionUseReplyKeyUsage = 2

func s4uUserIDChecksum(id S4UUserID, key types.EncryptionKey, usage uint32) (types.Checksum, error) {
	et, err := crypto.GetEType(key.KeyType)
	if err != nil {
		return types.Checksum{}, fmt.Errorf("error getting etype to sign PA-S4U-X509-USER: %w", err)
	}

	b, err := id.Marshal()
	if err != nil {
		return types.Checksum{}, fmt.Errorf("error marshaling the PA-S4U-X509-USER user-id: %w", err)
	}

	cs, err := et.GetChecksumHash(key.KeyValue, b, usage)
	if err != nil {
		return types.Checksum{}, fmt.Errorf("error signing PA-S4U-X509-USER: %w", err)
	}

	return types.Checksum{CksumType: et.GetHashID(), Checksum: cs}, nil
}

func findPAS4UX509User(pas types.PADataSequence) (PAS4UX509User, bool, error) {
	var p PAS4UX509User

	for _, pa := range pas {
		if pa.PADataType == patype.PA_FOR_X509_USER {
			return p, true, p.Unmarshal(pa.PADataValue)
		}
	}

	return p, false, nil
}
