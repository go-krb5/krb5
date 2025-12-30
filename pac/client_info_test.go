package pac

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/test/testdata"
)

func TestPAC_ClientInfo_Unmarshal(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_Client_Info)
	require.NoError(t, err)

	var k ClientInfo

	require.NoError(t, k.Unmarshal(b))

	assert.Equal(t, time.Date(2017, 5, 6, 15, 53, 11, 000000000, time.UTC), k.ClientID.Time())
	assert.Equal(t, uint16(18), k.NameLength)
	assert.Equal(t, "testuser1", k.Name)
}
