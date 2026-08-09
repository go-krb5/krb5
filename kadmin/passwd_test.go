package kadmin

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// testTicket returns a ticket and session key usable for building a kpasswd request. The ticket's encrypted part is
// never decrypted when building a request so it does not need to be populated.
func testTicket(t *testing.T) (messages.Ticket, types.EncryptionKey) {
	t.Helper()

	kb := make([]byte, 32)

	_, err := rand.Read(kb)
	require.NoError(t, err)

	return messages.Ticket{
			TktVNO: 5,
			Realm:  "TEST.GOKRB5",
			SName:  types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "kadmin/changepw"),
		}, types.EncryptionKey{
			KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
			KeyValue: kb,
		}
}

func TestChangePasswdMsg(t *testing.T) {
	t.Parallel()

	tkt, sk := testTicket(t)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser1")

	r, k, err := ChangePasswdMsg(cname, "TEST.GOKRB5", "newpassword", tkt, sk)
	require.NoError(t, err)

	b, err := r.Marshal()
	require.NoError(t, err)

	// The original change password protocol is version 0x0001. Version 0xff80 is RFC 3244 set password, which asks
	// the KDC to set a principal's password administratively rather than change the requestor's own.
	assert.Equal(t, []byte{0x00, 0x01}, b[2:4], "change password must use protocol version 0x0001")

	// For version 0x0001 the KRB_PRIV user data is the cleartext password with no ASN.1 wrapping.
	require.NoError(t, r.KRBPriv.DecryptEncPart(k))
	assert.Equal(t, []byte("newpassword"), r.KRBPriv.DecryptedEncPart.UserData)
}

func TestSetPasswdMsg(t *testing.T) {
	t.Parallel()

	tkt, sk := testTicket(t)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "adminuser")
	targ := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser1")

	r, k, err := SetPasswdMsg(cname, "TEST.GOKRB5", targ, "TEST.GOKRB5", "newpassword", tkt, sk)
	require.NoError(t, err)

	b, err := r.Marshal()
	require.NoError(t, err)

	assert.Equal(t, []byte{0xff, 0x80}, b[2:4], "set password must use protocol version 0xff80")

	// For version 0xff80 the KRB_PRIV user data is a marshaled ChangePasswdData naming the target principal.
	require.NoError(t, r.KRBPriv.DecryptEncPart(k))

	var d ChangePasswdData

	require.NoError(t, d.Unmarshal(r.KRBPriv.DecryptedEncPart.UserData))
	assert.Equal(t, []byte("newpassword"), d.NewPasswd)
	assert.Equal(t, targ, d.TargName)
	assert.Equal(t, "TEST.GOKRB5", d.TargRealm)
}
