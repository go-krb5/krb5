package kadmin

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestChangePasswdData_Marshal(t *testing.T) {
	t.Parallel()

	chgpasswd := ChangePasswdData{
		NewPasswd: []byte("newpassword"),
		TargName:  types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser1"),
		TargRealm: "TEST.GOKRB5",
	}

	chpwdb, err := chgpasswd.Marshal()
	require.NoError(t, err)

	b, err := hex.DecodeString(testdata.MarshaledChangePasswdData)
	require.NoError(t, err)

	assert.Equal(t, b, chpwdb)
}
