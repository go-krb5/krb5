package pac

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"log"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestPACTypeVerify(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_AD_WIN2K_PAC)
	require.NoError(t, err)

	var pac PACType

	require.NoError(t, pac.Unmarshal(b))

	b, _ = hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	pn, _ := types.ParseSPNString("sysHTTP")

	key, _, err := kt.GetEncryptionKey(pn, "TEST.GOKRB5", 2, 18)
	require.NoError(t, err)

	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)

	require.NoError(t, pac.ProcessPACInfoBuffers(key, l))

	pacInvalidServerSig := pac
	pacInvalidServerSig.ServerChecksum.Signature[0] ^= 0xFF
	pacInvalidNilKerbValidationInfo := pac
	pacInvalidNilKerbValidationInfo.KerbValidationInfo = nil
	pacInvalidNilServerSig := pac
	pacInvalidNilServerSig.ServerChecksum = nil
	pacInvalidNilKdcSig := pac
	pacInvalidNilKdcSig.KDCChecksum = nil
	pacInvalidClientInfo := pac
	pacInvalidClientInfo.ClientInfo = nil

	var pacs = []struct {
		pac PACType
	}{
		{pacInvalidServerSig},
		{pacInvalidNilKerbValidationInfo},
		{pacInvalidNilServerSig},
		{pacInvalidNilKdcSig},
		{pacInvalidClientInfo},
	}

	for _, s := range pacs {
		v, err := s.pac.verify(key)
		assert.False(t, v)
		assert.Error(t, err)
	}
}

func TestPACTypeUnmarshalRejectsBufferOutsideData(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		total  int
		size   uint32
		offset uint64
	}{
		{"offset beyond the data", 64, 0xFFFF, 0xFFFFFF},
		{"offset within the data but size runs past the end", 64, 0xFFFF, 24},
		{"offset at the very end of the address space", 64, 8, ^uint64(0)},
		{"offset and size sum wraps", 64, 0xFFFFFFFF, ^uint64(0) - 16},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var pac PACType

			err := pac.Unmarshal(pacWithBuffer(tc.total, infoTypeKerbValidationInfo, tc.size, tc.offset))
			assert.ErrorContains(t, err, "lies outside the PAC")
		})
	}
}

func TestProcessPACInfoBuffersRejectsBufferOutsideData(t *testing.T) {
	t.Parallel()

	pac := PACType{
		CBuffers:    1,
		Data:        make([]byte, 64),
		ZeroSigData: make([]byte, 64),
		Buffers: []InfoBuffer{
			{ULType: infoTypeKerbValidationInfo, CBBufferSize: 0xFFFF, Offset: 0xFFFFFF},
		},
	}

	w := bytes.NewBufferString("")

	require.NotPanics(t, func() {
		err := pac.ProcessPACInfoBuffers(types.EncryptionKey{}, log.New(w, "", 0))
		assert.ErrorContains(t, err, "lies outside the PAC")
	})
}

func TestProcessPACInfoBuffersRejectsShortZeroSigData(t *testing.T) {
	t.Parallel()

	pac := PACType{
		CBuffers:    1,
		Data:        make([]byte, 64),
		ZeroSigData: nil,
		Buffers: []InfoBuffer{
			{ULType: infoTypePACServerSignatureData, CBBufferSize: 20, Offset: 24},
		},
	}

	w := bytes.NewBufferString("")

	require.NotPanics(t, func() {
		err := pac.ProcessPACInfoBuffers(types.EncryptionKey{}, log.New(w, "", 0))
		assert.ErrorContains(t, err, "must be the same length")
	})
}

func pacWithBuffer(total int, ulType, size uint32, offset uint64) []byte {
	b := make([]byte, total)

	binary.LittleEndian.PutUint32(b[0:4], 1) // cBuffers
	binary.LittleEndian.PutUint32(b[4:8], 0) // Version
	binary.LittleEndian.PutUint32(b[8:12], ulType)
	binary.LittleEndian.PutUint32(b[12:16], size)
	binary.LittleEndian.PutUint64(b[16:24], offset)

	return b
}

func TestProcessPACInfoBuffersWithNilLogger(t *testing.T) {
	t.Parallel()

	b := make([]byte, 32)

	binary.LittleEndian.PutUint32(b[0:4], 1) // cBuffers
	binary.LittleEndian.PutUint32(b[4:8], 0) // Version
	binary.LittleEndian.PutUint32(b[8:12], infoTypeUPNDNSInfo)
	binary.LittleEndian.PutUint32(b[12:16], 8)
	binary.LittleEndian.PutUint64(b[16:24], 24)

	var pac PACType

	require.NoError(t, pac.Unmarshal(b))

	require.NotPanics(t, func() {
		assert.Error(t, pac.ProcessPACInfoBuffers(types.EncryptionKey{}, nil))
	})
}

func TestPACTypeUnmarshalRejectsImplausibleBufferCount(t *testing.T) {
	t.Parallel()

	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b[0:4], 0xFFFFFFFF)

	var pac PACType

	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	err := pac.Unmarshal(b)

	runtime.ReadMemStats(&after)

	assert.ErrorContains(t, err, "declares 4294967295 info buffers")

	// 4294967295 InfoBuffer values are about 68GB. The guard has to fire before the allocation, not after it.
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20),
		"the buffer count was allocated before it was validated")
}
