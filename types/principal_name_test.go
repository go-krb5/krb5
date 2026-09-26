package types

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/iana/nametype"
)

func TestPrincipalName_GetSalt(t *testing.T) {
	t.Parallel()

	pn := PrincipalName{
		NameType:   1,
		NameString: []string{"firststring", "secondstring"},
	}
	assert.Equal(t, "TEST.GOKRB5firststringsecondstring", pn.GetSalt("TEST.GOKRB5"))
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

func TestPrincipalNameMarshalsUTF8ComponentsAsTheirOctets(t *testing.T) {
	t.Parallel()

	pn := NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "jurišić/admin")

	b, err := asn1tools.Marshal(pn)
	require.NoError(t, err)

	for _, c := range pn.NameString {
		want := append([]byte{0x1b, byte(len(c))}, c...) //nolint:gosec

		assert.True(t, bytes.Contains(b, want), "component %q is not a GeneralString of its UTF-8 octets", c)
	}

	var back PrincipalName

	_, err = asn1.Unmarshal(b, &back, asn1.WithUnmarshalAllowTypeGeneralString(true))
	require.NoError(t, err)
	assert.Equal(t, pn, back)
}

func TestPrincipalNameGetSaltKeepsUTF8Octets(t *testing.T) {
	t.Parallel()

	pn := NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "jurišić")

	assert.Equal(t, []byte("ATHENA.MIT.EDUjurišić"), []byte(pn.GetSalt("ATHENA.MIT.EDU")))
}
