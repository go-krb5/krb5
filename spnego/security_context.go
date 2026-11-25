package spnego

import (
	"errors"

	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/types"
)

// NewSecurityLayerSession returns a session that protects messages exchanged with the acceptor of the Kerberos
// context this initiator established, as RFC 4121 per-message Wrap tokens. It is how a protocol that encrypts its
// messages after an HTTP Negotiate exchange, such as the MS-WSMV message encryption WinRM uses, obtains what it
// protects them with.
//
// It must be called after InitSecContext, and after VerifyMutual where the context asked for mutual
// authentication. The session is set up as RFC 4121 describes:
//
//   - The key is the subkey the acceptor asserted in its AP-REP if it asserted one, which also sets the
//     AcceptorSubkey flag of Section 4.2.2; otherwise the subkey of the initiator's authenticator if it carried
//     one; otherwise the session key of the ticket. This is the order of Section 2.
//   - The tokens it sends start from the sequence number of the initiator's authenticator. The tokens it receives
//     start from the sequence number of the acceptor's AP-REP, or from the initiator's own where the acceptor sent
//     no AP-REP, as MIT krb5 and Windows do for a context established without mutual authentication.
//
// The options given are applied after these, so a caller may add gssapi.RotateTrailer or gssapi.DCEStyle where the
// protocol needs that token layout, and may override the sequence numbers. maxBufferSize is as for
// gssapi.NewSecurityLayerSession; zero means unlimited.
func (s *SPNEGO) NewSecurityLayerSession(layer gssapi.SecurityLayer, maxBufferSize int, opts ...gssapi.SecurityLayerOption) (*gssapi.SecurityLayerSession, error) {
	key, acceptorSubkey, err := s.protocolKey()
	if err != nil {
		return nil, err
	}

	recv := s.sentSeqNum
	if s.acceptorReplied {
		recv = s.acceptorSeqNum
	}

	base := []gssapi.SecurityLayerOption{
		gssapi.InitialSendSequenceNumber(seqNum(s.sentSeqNum)),
		gssapi.InitialReceiveSequenceNumber(seqNum(recv)),
	}

	if acceptorSubkey {
		base = append(base, gssapi.AcceptorSubkey())
	}

	return gssapi.NewSecurityLayerSession(key, layer, true, maxBufferSize, append(base, opts...)...)
}

func (s *SPNEGO) protocolKey() (key types.EncryptionKey, acceptorSubkey bool, err error) {
	switch {
	case len(s.sessionKey.KeyValue) == 0:
		return key, false, errors.New("spnego: this context never initiated, so there is no established context to protect messages with")
	case len(s.acceptorSubkey.KeyValue) > 0:
		return s.acceptorSubkey, true, nil
	case len(s.initiatorSubkey.KeyValue) > 0:
		return s.initiatorSubkey, false, nil
	default:
		return s.sessionKey, false, nil
	}
}

func seqNum(n int64) uint64 {
	return uint64(uint32(n)) //nolint:gosec // G115: RFC 4120 sequence numbers are 32 bits, and some implementations encode them as signed.
}
