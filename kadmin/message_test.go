package kadmin

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
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

func TestReplyUnmarshalRejectsMalformedReply(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		b    []byte
	}{
		{
			"shorter than the fixed header",
			[]byte{0x00, 0x06, 0x00, 0x01},
		},
		{
			"AP-REP length runs past the end",
			[]byte{0xFF, 0xFF, 0x00, 0x01, 0xFF, 0xFF, 0x00, 0x00},
		},
		{
			"message length runs past the end",
			[]byte{0xFF, 0xFF, 0x00, 0x01, 0x00, 0x00},
		},
		{
			"message length is shorter than the header it follows",
			[]byte{0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		},
		{
			"empty",
			[]byte{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var r Reply

			require.NotPanics(t, func() {
				assert.Error(t, r.Unmarshal(tc.b))
			})
		})
	}
}

func TestReplyUnmarshalRejectsErrorReplyWithShortEData(t *testing.T) {
	t.Parallel()

	krbErr := messages.NewKRBError(types.PrincipalName{}, "TEST.GOKRB5", 0, "")

	eb, err := krbErr.Marshal()
	require.NoError(t, err)

	b := make([]byte, 6, 6+len(eb))
	binary.BigEndian.PutUint16(b[0:2], uint16(6+len(eb)))
	binary.BigEndian.PutUint16(b[2:4], 1)
	binary.BigEndian.PutUint16(b[4:6], 0)
	b = append(b, eb...)

	var r Reply

	require.NotPanics(t, func() {
		_ = r.Unmarshal(b)
		assert.True(t, r.IsKRBError)
	})
}
