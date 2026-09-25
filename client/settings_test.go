package client

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/types"
)

func TestKeptPADataIsNotChangedByTheCallersName(t *testing.T) {
	t.Parallel()

	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: []byte("kept")}}
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser")

	var k keptPAData

	k.store(cname, "TEST.GOKRB5", pas)

	cname.NameString[0] = "otheruser"

	assert.Equal(t, pas, k.load(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser"), "TEST.GOKRB5"))
	assert.Nil(t, k.load(cname, "TEST.GOKRB5"))
}

func TestKeptPADataIsNotChangedByTheCallersPAData(t *testing.T) {
	t.Parallel()

	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: []byte("kept")}}
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser")

	var k keptPAData

	k.store(cname, "TEST.GOKRB5", pas)

	pas[0].PADataValue[0] = 'X'
	pas[0].PADataType = patype.PA_PW_SALT

	assert.Equal(t, types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: []byte("kept")}}, k.load(cname, "TEST.GOKRB5"))
}
