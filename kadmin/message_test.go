package kadmin

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestUnmarshalReply(t *testing.T) {
	t.Parallel()

	var a Reply

	b, err := hex.DecodeString(testdata.MarshaledKpasswd_Rep)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, 236, a.MessageLength)
	assert.Equal(t, 1, a.Version)
	assert.Equal(t, 140, a.APREPLength)
	assert.Equal(t, iana.PVNO, a.APREP.PVNO)
	assert.Equal(t, msgtype.KRB_AP_REP, a.APREP.MsgType)
	assert.Equal(t, int32(18), a.APREP.EncPart.EType)
	assert.Equal(t, iana.PVNO, a.KRBPriv.PVNO)
	assert.Equal(t, msgtype.KRB_PRIV, a.KRBPriv.MsgType)
	assert.Equal(t, int32(18), a.KRBPriv.EncPart.EType)
}

// Request marshal is tested via integration test in the client package due to the dynamic keys and encryption.
