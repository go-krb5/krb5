package pac

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/go-krb5/x/rpc/mstypes"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

const (
	infoTypeKerbValidationInfo     uint32 = 1
	infoTypeCredentials            uint32 = 2
	infoTypePACServerSignatureData uint32 = 6
	infoTypePACKDCSignatureData    uint32 = 7
	infoTypePACClientInfo          uint32 = 10
	infoTypeS4UDelegationInfo      uint32 = 11
	infoTypeUPNDNSInfo             uint32 = 12
	infoTypePACClientClaimsInfo    uint32 = 13
	infoTypePACDeviceInfo          uint32 = 14
	infoTypePACDeviceClaimsInfo    uint32 = 15
)

// PACType implements: https://msdn.microsoft.com/en-us/library/cc237950.aspx
type PACType struct {
	CBuffers           uint32
	Version            uint32
	Buffers            []InfoBuffer
	Data               []byte
	KerbValidationInfo *KerbValidationInfo
	CredentialsInfo    *CredentialsInfo
	ServerChecksum     *SignatureData
	KDCChecksum        *SignatureData
	ClientInfo         *ClientInfo
	S4UDelegationInfo  *S4UDelegationInfo
	UPNDNSInfo         *UPNDNSInfo
	ClientClaimsInfo   *ClientClaimsInfo
	DeviceInfo         *DeviceInfo
	DeviceClaimsInfo   *DeviceClaimsInfo
	ZeroSigData        []byte
}

// InfoBuffer implements the PAC Info Buffer: https://msdn.microsoft.com/en-us/library/cc237954.aspx
type InfoBuffer struct {
	ULType       uint32 // A 32-bit unsigned integer in little-endian format that describes the type of data present in the buffer contained at Offset.
	CBBufferSize uint32 // A 32-bit unsigned integer in little-endian format that contains the size, in bytes, of the buffer in the PAC located at Offset.
	Offset       uint64 // A 64-bit unsigned integer in little-endian format that contains the offset to the beginning of the buffer, in bytes, from the beginning of the PACTYPE structure. The data offset MUST be a multiple of eight. The following sections specify the format of each type of element.
}

// bounds returns the start and end offsets of the buffer within a PACTYPE structure of n bytes, and reports
// whether the buffer lies within it.
func (i InfoBuffer) bounds(n int) (start, end int, ok bool) {
	if n < 0 || i.Offset > uint64(n) || uint64(i.CBBufferSize) > uint64(n)-i.Offset {
		return 0, 0, false
	}

	return int(i.Offset), int(i.Offset) + int(i.CBBufferSize), true
}

// outsideErr describes a buffer whose offset and size do not lie within the PAC.
func (i InfoBuffer) outsideErr(n, index int) error {
	return fmt.Errorf("PAC info buffer %d of type %d lies outside the PAC: offset %d, size %d, PAC is %d bytes",
		index, i.ULType, i.Offset, i.CBBufferSize, n)
}

// Unmarshal bytes into the PACType struct.
func (pac *PACType) Unmarshal(b []byte) (err error) {
	pac.Data = b
	zb := make([]byte, len(b))
	copy(zb, b)
	pac.ZeroSigData = zb
	r := mstypes.NewReader(bytes.NewReader(b))

	pac.CBuffers, err = r.Uint32()
	if err != nil {
		return err
	}

	pac.Version, err = r.Uint32()
	if err != nil {
		return err
	}

	buf := make([]InfoBuffer, pac.CBuffers)
	for i := range buf {
		buf[i].ULType, err = r.Uint32()
		if err != nil {
			return
		}

		buf[i].CBBufferSize, err = r.Uint32()
		if err != nil {
			return
		}

		buf[i].Offset, err = r.Uint64()
		if err != nil {
			return
		}

		if _, _, ok := buf[i].bounds(len(b)); !ok {
			return buf[i].outsideErr(len(b), i)
		}
	}

	pac.Buffers = buf

	return nil
}

// discardLogger stands in for a nil *log.Logger. Writing to a nil one dereferences its mutex and panics rather
// than discarding, and callers reach here holding whatever service.Settings.Logger returned, which is nil unless
// a logger was configured.
var discardLogger = log.New(io.Discard, "", 0)

// ProcessPACInfoBuffers processes the PAC Info Buffers.
//
// Reference: https://msdn.microsoft.com/en-us/library/cc237954.aspx
func (pac *PACType) ProcessPACInfoBuffers(key types.EncryptionKey, l *log.Logger) error {
	if l == nil {
		l = discardLogger
	}

	if len(pac.ZeroSigData) != len(pac.Data) {
		return fmt.Errorf("PAC signature scratch buffer is %d bytes and the PAC is %d bytes; they must be the same length",
			len(pac.ZeroSigData), len(pac.Data))
	}

	for i, buf := range pac.Buffers {
		start, end, ok := buf.bounds(len(pac.Data))
		if !ok {
			return buf.outsideErr(len(pac.Data), i)
		}

		p := make([]byte, buf.CBBufferSize)
		copy(p, pac.Data[start:end])

		switch buf.ULType {
		case infoTypeKerbValidationInfo:
			if pac.KerbValidationInfo != nil {
				continue
			}

			var k KerbValidationInfo

			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("error processing KerbValidationInfo: %w", err)
			}

			pac.KerbValidationInfo = &k
		case infoTypeCredentials:
			// Currently PAC parsing is only useful on the service side in krb5
			// The CredentialsInfo are only useful when krb5 has implemented RFC4556 and only applied on the client side.
			// Skipping CredentialsInfo - will be revisited under RFC4556 implementation.
			continue
			// if pac.CredentialsInfo != nil {
			//	//Must ignore subsequent buffers of this type
			//	continue
			//}
			// var k CredentialsInfo
			// err := k.Unmarshal(p, key) // The encryption key used is the AS reply key only available to the client.
			// if err != nil {
			//	return fmt.Errorf("error processing CredentialsInfo: %w", err)
			//}
			// pac.CredentialsInfo = &k.
		case infoTypePACServerSignatureData:
			if pac.ServerChecksum != nil {
				continue
			}

			var k SignatureData

			zb, err := k.Unmarshal(p)
			copy(pac.ZeroSigData[start:end], zb)

			if err != nil {
				return fmt.Errorf("error processing ServerChecksum: %w", err)
			}

			pac.ServerChecksum = &k
		case infoTypePACKDCSignatureData:
			if pac.KDCChecksum != nil {
				continue
			}

			var k SignatureData

			zb, err := k.Unmarshal(p)
			copy(pac.ZeroSigData[start:end], zb)

			if err != nil {
				return fmt.Errorf("error processing KDCChecksum: %w", err)
			}

			pac.KDCChecksum = &k
		case infoTypePACClientInfo:
			if pac.ClientInfo != nil {
				continue
			}

			var k ClientInfo

			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("error processing ClientInfo: %w", err)
			}

			pac.ClientInfo = &k
		case infoTypeS4UDelegationInfo:
			if pac.S4UDelegationInfo != nil {
				continue
			}

			var k S4UDelegationInfo

			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process S4U_DelegationInfo: %v", err)
				continue
			}

			pac.S4UDelegationInfo = &k
		case infoTypeUPNDNSInfo:
			if pac.UPNDNSInfo != nil {
				// Must ignore subsequent buffers of this type.
				continue
			}

			var k UPNDNSInfo

			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process UPN_DNSInfo: %v", err)
				continue
			}

			pac.UPNDNSInfo = &k
		case infoTypePACClientClaimsInfo:
			if pac.ClientClaimsInfo != nil || len(p) < 1 {
				// Must ignore subsequent buffers of this type.
				continue
			}

			var k ClientClaimsInfo

			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process ClientClaimsInfo: %v", err)
				continue
			}

			pac.ClientClaimsInfo = &k
		case infoTypePACDeviceInfo:
			if pac.DeviceInfo != nil {
				// Must ignore subsequent buffers of this type.
				continue
			}

			var k DeviceInfo

			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process DeviceInfo: %v", err)
				continue
			}

			pac.DeviceInfo = &k
		case infoTypePACDeviceClaimsInfo:
			if pac.DeviceClaimsInfo != nil {
				// Must ignore subsequent buffers of this type.
				continue
			}

			var k DeviceClaimsInfo

			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process DeviceClaimsInfo: %v", err)
				continue
			}

			pac.DeviceClaimsInfo = &k
		}
	}

	if ok, err := pac.verify(key); !ok {
		return err
	}

	return nil
}

func (pac *PACType) verify(key types.EncryptionKey) (bool, error) {
	if pac.KerbValidationInfo == nil {
		return false, errors.New("PAC Info Buffers does not contain a KerbValidationInfo")
	}

	if pac.ServerChecksum == nil {
		return false, errors.New("PAC Info Buffers does not contain a ServerChecksum")
	}

	if pac.KDCChecksum == nil {
		return false, errors.New("PAC Info Buffers does not contain a KDCChecksum")
	}

	if pac.ClientInfo == nil {
		return false, errors.New("PAC Info Buffers does not contain a ClientInfo")
	}

	etype, err := crypto.GetChecksumEType(int32(pac.ServerChecksum.SignatureType))
	if err != nil {
		return false, err
	}

	if ok := etype.VerifyChecksum(key.KeyValue,
		pac.ZeroSigData,
		pac.ServerChecksum.Signature,
		keyusage.KERB_NON_KERB_CKSUM_SALT); !ok {
		return false, errors.New("PAC service checksum verification failed")
	}

	return true, nil
}
