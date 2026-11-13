package spnego

import (
	"errors"
	"fmt"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

// mechListMICPayload returns the message a mechListMIC is computed over. RFC 4178 Section 5(a) defines it as "the
// DER encoding of the value of type MechTypeList, which is contained in the mechTypes field of the NegTokenInit",
// and is explicit that "the input message is NOT the DER encoding of the type [0] MechTypeList": the context tag
// the field carries inside the token is not part of what is signed.
func mechListMICPayload(raw []byte, mechTypes []asn1.ObjectIdentifier) ([]byte, error) {
	if len(raw) > 0 {
		return raw, nil
	}

	if len(mechTypes) == 0 {
		return nil, errors.New("cannot compute a mechListMIC over an empty mechanism list")
	}

	b, err := asn1tools.Marshal(mechTypes)
	if err != nil {
		return nil, fmt.Errorf("error marshalling the MechTypeList for the mechListMIC: %w", err)
	}

	return b, nil
}

// newMechListMIC returns the MIC token RFC 4178 Section 5(a) obtains by "invoking GSS_GetMIC()" over the mechanism
// list, which for the Kerberos mechanism is the token described by RFC 4121 Section 4.2.6.1. acceptorSubkey reports
// that key is the subkey the acceptor asserted, which Section 4.2.2 has the token flag.
func newMechListMIC(payload []byte, key types.EncryptionKey, fromAcceptor, acceptorSubkey bool) ([]byte, error) {
	mt := gssapi.MICToken{Payload: payload}

	if fromAcceptor {
		mt.Flags |= gssapi.MICTokenFlagSentByAcceptor
	}

	if acceptorSubkey {
		mt.Flags |= gssapi.MICTokenFlagAcceptorSubkey
	}

	if err := mt.SetChecksum(key, micKeyUsage(fromAcceptor)); err != nil {
		return nil, fmt.Errorf("error computing the mechListMIC checksum: %w", err)
	}

	return mt.Marshal()
}

// verifyMechListMIC checks a MIC token against the mechanism list it should protect. Every failure is an error: RFC
// 4178 Section 5 terminates the negotiation for a MIC that does not verify, so there is no partial success to
// report and nothing for a caller to weigh up. acceptorSubkey reports that key is the subkey the acceptor asserted,
// and a MIC whose AcceptorSubkey flag disagrees names a key other than the one it is checked with.
func verifyMechListMIC(mic, payload []byte, key types.EncryptionKey, fromAcceptor, acceptorSubkey bool) error {
	var mt gssapi.MICToken

	if err := mt.Unmarshal(mic, fromAcceptor); err != nil {
		return fmt.Errorf("error reading the mechListMIC: %w", err)
	}

	if flagged := mt.Flags&gssapi.MICTokenFlagAcceptorSubkey != 0; flagged != acceptorSubkey {
		if acceptorSubkey {
			return errors.New("the mechListMIC is not flagged as protected with the subkey the acceptor asserted")
		}

		return errors.New("the mechListMIC is flagged as protected with an acceptor subkey the acceptor never asserted")
	}

	if len(mt.Checksum) == 0 {
		return errors.New("the mechListMIC carries no checksum")
	}

	mt.Payload = payload

	ok, err := mt.Verify(key, micKeyUsage(fromAcceptor))
	if err != nil {
		return fmt.Errorf("the mechListMIC does not verify: %w", err)
	}

	if !ok {
		return errors.New("the mechListMIC does not verify")
	}

	return nil
}

// micKeyUsage returns the key usage RFC 4121 Section 2 assigns to a MIC token from each side of the exchange. It is
// derived from the same argument that sets the acceptor flag in the token header so that the two, which are one
// fact spelled twice, cannot be set inconsistently.
func micKeyUsage(fromAcceptor bool) uint32 {
	if fromAcceptor {
		return keyusage.GSSAPI_ACCEPTOR_SIGN
	}

	return keyusage.GSSAPI_INITIATOR_SIGN
}
