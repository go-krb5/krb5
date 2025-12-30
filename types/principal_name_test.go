package types

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/krb5/iana/nametype"
)

func TestPrincipalName_GetSalt(t *testing.T) {
	t.Parallel()

	pn := PrincipalName{
		NameType:   1,
		NameString: []string{"firststring", "secondstring"},
	}
	assert.Equal(t, "TEST.GOKRB5firststringsecondstring", pn.GetSalt("TEST.GOKRB5"), "Principal name default salt not as expected")
}

func TestParseSPNString(t *testing.T) {
	pn, realm := ParseSPNString("HTTP/www.example.com@REALM.COM")
	assert.Equal(t, "REALM.COM", realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, pn.NameType)
	assert.Equal(t, "HTTP", pn.NameString[0])
	assert.Equal(t, "www.example.com", pn.NameString[1])

	pn, realm = ParseSPNString("HTTP/www.example.com")
	assert.Equal(t, "", realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, pn.NameType)
	assert.Equal(t, "HTTP", pn.NameString[0])
	assert.Equal(t, "www.example.com", pn.NameString[1])

	pn, realm = ParseSPNString("www.example.com@REALM.COM")
	assert.Equal(t, "REALM.COM", realm)
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, pn.NameType)
	assert.Equal(t, "www.example.com", pn.NameString[0])
}
