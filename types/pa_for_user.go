package types

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // G501: KERB_CHECKSUM_HMAC_MD5 is what MS-SFU pins PA-FOR-USER to.
	"encoding/binary"
	"errors"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/crypto/rfc4757"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/patype"
)

// PAForUserAuthPackage is the only authentication package MS-SFU Section 2.2.1 defines for PA-FOR-USER.
const PAForUserAuthPackage = "Kerberos"

// PAForUser implements the PA-FOR-USER pre-authentication data of MS-SFU Section 2.2.1.
//
// A service sends it in a TGS-REQ for a ticket to itself to ask for that ticket in the name of a user it has
// authenticated by other means, which MS-SFU calls protocol transition (S4U2Self).
//
//	PA-FOR-USER ::= SEQUENCE {
//	    userName     [0] PrincipalName,
//	    userRealm    [1] Realm,
//	    cksum        [2] Checksum,
//	    auth-package [3] KerberosString
//	}
type PAForUser struct {
	UserName    PrincipalName `asn1:"explicit,tag:0"`
	UserRealm   string        `asn1:"general,explicit,tag:1"`
	Cksum       Checksum      `asn1:"explicit,tag:2"`
	AuthPackage string        `asn1:"general,explicit,tag:3"`
}

// NewPAForUser returns the PA-FOR-USER naming user, signed with the session key of the ticket-granting ticket the
// request is made with.
//
// MS-SFU Section 2.2.1 pins the checksum to KERB_CHECKSUM_HMAC_MD5 whatever the session key's own encryption type,
// so an AES session key signs it too. That checksum is the only thing tying the request to the holder of the TGT;
// the KDC refuses a PA-FOR-USER whose checksum does not verify under the session key it issued.
func NewPAForUser(user PrincipalName, userRealm string, sessionKey EncryptionKey) PAForUser {
	p := PAForUser{
		UserName:    user,
		UserRealm:   userRealm,
		AuthPackage: PAForUserAuthPackage,
	}

	p.Cksum = Checksum{
		CksumType: chksumtype.KERB_CHECKSUM_HMAC_MD5,
		Checksum:  p.checksum(sessionKey),
	}

	return p
}

func (p *PAForUser) checksum(sessionKey EncryptionKey) []byte {
	ksign := rfc4757.HMAC(sessionKey.KeyValue, []byte("signaturekey\x00"))
	inner := md5.Sum(append(rfc4757.UsageToMSMsgType(keyusage.KERB_NON_KERB_CKSUM_SALT), p.checksumData()...)) //nolint:gosec // G401: see the import.

	return rfc4757.HMAC(ksign, inner[:])
}

func (p *PAForUser) checksumData() []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(p.UserName.NameType)) //nolint:gosec // G115: name types are small constants.

	for _, c := range p.UserName.NameString {
		b = append(b, c...)
	}

	b = append(b, p.UserRealm...)

	return append(b, p.AuthPackage...)
}

// Verify checks the checksum against the session key of the ticket-granting ticket the request was made with.
func (p *PAForUser) Verify(sessionKey EncryptionKey) error {
	if p.Cksum.CksumType != chksumtype.KERB_CHECKSUM_HMAC_MD5 {
		return errors.New("PA-FOR-USER checksum is not KERB_CHECKSUM_HMAC_MD5")
	}

	if !hmac.Equal(p.checksum(sessionKey), p.Cksum.Checksum) {
		return errors.New("PA-FOR-USER checksum does not verify")
	}

	return nil
}

// Marshal the PA-FOR-USER.
func (p *PAForUser) Marshal() ([]byte, error) {
	return asn1.Marshal(*p, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
}

// Unmarshal bytes into the PA-FOR-USER.
func (p *PAForUser) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, p, asn1.WithUnmarshalAllowTypeGeneralString(true))

	return err
}

// PAData returns the PA-FOR-USER as pre-authentication data of type PA_FOR_USER.
func (p *PAForUser) PAData() (PAData, error) {
	b, err := p.Marshal()
	if err != nil {
		return PAData{}, err
	}

	return PAData{PADataType: patype.PA_FOR_USER, PADataValue: b}, nil
}
