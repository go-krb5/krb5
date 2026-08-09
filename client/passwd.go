package client

import (
	"fmt"

	"github.com/go-krb5/krb5/kadmin"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// Kpasswd server response codes.
const (
	KRB5_KPASSWD_SUCCESS             = 0
	KRB5_KPASSWD_MALFORMED           = 1
	KRB5_KPASSWD_HARDERROR           = 2
	KRB5_KPASSWD_AUTHERROR           = 3
	KRB5_KPASSWD_SOFTERROR           = 4
	KRB5_KPASSWD_ACCESSDENIED        = 5
	KRB5_KPASSWD_BAD_VERSION         = 6
	KRB5_KPASSWD_INITIAL_FLAG_NEEDED = 7
)

// ChangePasswd changes the password of the client to the value provided.
//
// This uses the original Kerberos change password protocol, which asks the KDC to change the password of the principal
// the client authenticated as. It requires no administrative privilege. To set the password of another principal use
// SetPasswd.
func (cl *Client) ChangePasswd(newPasswd string) (bool, error) {
	ASRep, err := cl.kpasswdASExchange()
	if err != nil {
		return false, err
	}

	msg, key, err := kadmin.ChangePasswdMsg(cl.Credentials.CName(), cl.Credentials.Domain(), newPasswd, ASRep.Ticket, ASRep.DecryptedEncPart.Key)
	if err != nil {
		return false, err
	}

	if err = cl.exchangeWithKPasswd(msg, key); err != nil {
		return false, err
	}

	cl.Credentials.WithPassword(newPasswd)

	return true, nil
}

// SetPasswd sets the password of the principal named by targName in targRealm to the value provided. If targRealm is
// empty the client's own realm is used.
//
// This uses the set password protocol defined by RFC 3244, which asks the KDC to set the target principal's password
// administratively. The client must be authorized to administer the target principal; on Active Directory that is the
// Reset Password extended right. A client changing its own password should use ChangePasswd instead, which needs no
// such privilege. The client's stored credentials are not updated by this call.
func (cl *Client) SetPasswd(targName types.PrincipalName, targRealm, newPasswd string) (bool, error) {
	if targRealm == "" {
		targRealm = cl.Credentials.Domain()
	}

	ASRep, err := cl.kpasswdASExchange()
	if err != nil {
		return false, err
	}

	msg, key, err := kadmin.SetPasswdMsg(cl.Credentials.CName(), cl.Credentials.Domain(), targName, targRealm, newPasswd, ASRep.Ticket, ASRep.DecryptedEncPart.Key)
	if err != nil {
		return false, err
	}

	if err = cl.exchangeWithKPasswd(msg, key); err != nil {
		return false, err
	}

	return true, nil
}

// kpasswdASExchange obtains an initial ticket for the kadmin/changepw service.
func (cl *Client) kpasswdASExchange() (messages.ASRep, error) {
	ASReq, err := messages.NewASReqForChgPasswd(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return messages.ASRep{}, err
	}

	return cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
}

// exchangeWithKPasswd sends the request to the kpasswd server and checks the result code of the reply, which is
// decrypted with key.
func (cl *Client) exchangeWithKPasswd(msg kadmin.Request, key types.EncryptionKey) error {
	r, err := cl.sendToKPasswd(msg)
	if err != nil {
		return err
	}

	err = r.Decrypt(key)
	if err != nil {
		return err
	}

	if r.ResultCode != KRB5_KPASSWD_SUCCESS {
		return fmt.Errorf("error response from kadmin: code: %d; result: %s; krberror: %w", r.ResultCode, r.Result, r.KRBError)
	}

	return nil
}

func (cl *Client) sendToKPasswd(msg kadmin.Request) (r kadmin.Reply, err error) {
	_, kps, err := cl.Config.GetKpasswdServers(cl.Credentials.Domain(), true)
	if err != nil {
		return r, err
	}

	b, err := msg.Marshal()
	if err != nil {
		return r, err
	}

	var rb []byte
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		rb, err = dialSendUDP(cl.settings.dialer, kps, b)
		if err != nil {
			return r, err
		}
	} else {
		rb, err = dialSendTCP(cl.settings.dialer, kps, b)
		if err != nil {
			return r, err
		}
	}

	err = r.Unmarshal(rb)

	return r, err
}
