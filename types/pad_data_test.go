package types

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestUnmarshalPADataSequence(t *testing.T) {
	t.Parallel()

	var a PADataSequence

	b, err := hex.DecodeString(testdata.MarshaledKRB5padata_sequence)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, 2, len(a))

	for _, pa := range a {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType)
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue)
	}
}

func TestUnmarshalPADataSequence_empty(t *testing.T) {
	t.Parallel()

	var a PADataSequence

	b, err := hex.DecodeString(testdata.MarshaledKRB5padataSequenceEmpty)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, 0, len(a))
}

func TestUnmarshalPAEncTSEnc(t *testing.T) {
	t.Parallel()
	// Parse the test time value into a time.Time type.
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	var a PAEncTSEnc

	b, err := hex.DecodeString(testdata.MarshaledKRB5pa_enc_ts)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, tt, a.PATimestamp)
	assert.Equal(t, 123456, a.PAUSec)
}

func TestUnmarshalPAEncTSEnc_nousec(t *testing.T) {
	t.Parallel()
	// Parse the test time value into a time.Time type.
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	var a PAEncTSEnc

	b, err := hex.DecodeString(testdata.MarshaledKRB5pa_enc_tsNoUsec)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, tt, a.PATimestamp)
	assert.Equal(t, 0, a.PAUSec)
}

func TestUnmarshalETypeInfo(t *testing.T) {
	t.Parallel()

	var a ETypeInfo

	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_info)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, 3, len(a))
	assert.Equal(t, int32(0), a[0].EType)
	assert.Equal(t, []byte("Morton's #0"), a[0].Salt)
	assert.Equal(t, int32(1), a[1].EType)
	assert.Equal(t, 0, len(a[1].Salt))
	assert.Equal(t, int32(2), a[2].EType)
	assert.Equal(t, []byte("Morton's #2"), a[2].Salt)
}

func TestUnmarshalETypeInfo_only1(t *testing.T) {
	t.Parallel()

	var a ETypeInfo

	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_infoOnly1)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, 1, len(a))
	assert.Equal(t, int32(0), a[0].EType)
	assert.Equal(t, []byte("Morton's #0"), a[0].Salt)
}

func TestUnmarshalETypeInfo_noinfo(t *testing.T) {
	t.Parallel()

	var a ETypeInfo

	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_infoNoInfo)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, 0, len(a))
}

func TestUnmarshalETypeInfo2(t *testing.T) {
	t.Parallel()

	var a ETypeInfo2

	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_info2)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, 3, len(a))
	assert.Equal(t, int32(0), a[0].EType)
	assert.Equal(t, "Morton's #0", a[0].Salt)
	assert.Equal(t, []byte("s2k: 0"), a[0].S2KParams)
	assert.Equal(t, int32(1), a[1].EType)
	assert.Equal(t, 0, len(a[1].Salt))
	assert.Equal(t, []byte("s2k: 1"), a[1].S2KParams)
	assert.Equal(t, int32(2), a[2].EType)
	assert.Equal(t, "Morton's #2", a[2].Salt)
	assert.Equal(t, []byte("s2k: 2"), a[2].S2KParams)
}

func TestUnmarshalETypeInfo2_only1(t *testing.T) {
	t.Parallel()

	var a ETypeInfo2

	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_info2Only1)
	require.NoError(t, err)

	require.NoError(t, a.Unmarshal(b))

	assert.Equal(t, 1, len(a))
	assert.Equal(t, int32(0), a[0].EType)
	assert.Equal(t, "Morton's #0", a[0].Salt)
	assert.Equal(t, []byte("s2k: 0"), a[0].S2KParams)
}
