// Package kadmin provides Kerberos administration capabilities.
package kadmin

import (
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// ChangePasswdMsg generates a change password request for the principal the ticket was issued to and also returns the
// key needed to decrypt the reply.
//
// This is the original Kerberos change password protocol, in which the KDC changes the password of the principal named
// in the ticket. It requires nothing of the requestor beyond an initial ticket, so it is the operation to use for a
// principal changing its own password. To set another principal's password use SetPasswdMsg.
func ChangePasswdMsg(cname types.PrincipalName, realm, password string, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	return newRequest(VersionChangePassword, cname, realm, []byte(password), tkt, sessionKey)
}

// SetPasswdMsg generates a set password request for the principal named by targname and targrealm and also returns the
// key needed to decrypt the reply.
//
// This is the set password protocol defined by RFC 3244, in which the KDC sets the password of the target principal
// administratively. The requestor must be authorized to administer the target principal; on Active Directory that is
// the Reset Password extended right. A principal changing its own password should use ChangePasswdMsg instead.
func SetPasswdMsg(cname types.PrincipalName, realm string, targname types.PrincipalName, targrealm, password string, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	chgpasswd := ChangePasswdData{
		NewPasswd: []byte(password),
		TargName:  targname,
		TargRealm: targrealm,
	}

	userData, err := chgpasswd.Marshal()
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error marshaling change passwd data")

		return
	}

	return newRequest(VersionSetPassword, cname, realm, userData, tkt, sessionKey)
}

// newRequest builds a kpasswd request of the given protocol version carrying userData in its KRB_PRIV and returns the
// subkey the reply will be encrypted with.
func newRequest(version uint16, cname types.PrincipalName, realm string, userData []byte, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	// Generate authenticator.
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")

		return
	}

	etype, err := crypto.GetEType(sessionKey.KeyType)
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey etype")

		return
	}

	err = auth.GenerateSeqNumberAndSubKey(etype.GetETypeID(), etype.GetKeyByteSize())
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey")

		return
	}

	k = auth.SubKey

	// Generate AP_REQ.
	APreq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		return r, k, err
	}

	// Form the KRBPriv encpart data.
	kp := messages.EncKrbPrivPart{
		UserData:       userData,
		Timestamp:      auth.CTime,
		Usec:           auth.Cusec,
		SequenceNumber: auth.SeqNumber,
	}
	kpriv := messages.NewKRBPriv(kp)

	err = kpriv.EncryptEncPart(k)
	if err != nil {
		err = krberror.Errorf(err, krberror.EncryptingError, "error encrypting kpasswd request data")

		return
	}

	r = Request{
		Version: version,
		APREQ:   APreq,
		KRBPriv: kpriv,
	}

	return
}
