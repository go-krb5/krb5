package spnego

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// APRepToken builds the AP-REP GSSAPI mech token that answers a verified AP-REQ.
//
// It must be called on a token whose Verify has succeeded: the session key it encrypts under comes
// out of the ticket, which is only decrypted as part of verifying, and the ctime/cusec come from
// the initiator's authenticator, which is only readable with that same key.
func (m *KRB5Token) APRepToken() ([]byte, error) {
	if hex.EncodeToString(m.tokID) != TOK_ID_KRB_AP_REQ {
		return nil, errors.New("spnego: an AP-REP answers an AP-REQ, and this token is not one")
	}

	key := m.APReq.Ticket.DecryptedEncPart.Key
	if len(key.KeyValue) == 0 {
		return nil, errors.New("spnego: the ticket carries no session key; verify the AP-REQ before answering it")
	}

	// SequenceNumber is echoed only when the initiator sent one. A zero there is not "sequence zero"; the field is
	// OPTIONAL and the authenticator simply had none; and sending one back that the initiator never chose is a value
	// it cannot check.
	enc := messages.EncAPRepPart{
		CTime: m.APReq.Authenticator.CTime,
		Cusec: m.APReq.Authenticator.Cusec,
	}
	if m.APReq.Authenticator.SeqNumber != 0 {
		enc.SequenceNumber = m.APReq.Authenticator.SeqNumber
	}

	plain, err := enc.Marshal()
	if err != nil {
		return nil, fmt.Errorf("spnego: marshal EncAPRepPart: %w", err)
	}
	// No subkey is offered, so the AP-REP is encrypted under the ticket's session key. KVNO 0
	// because a session key has no version: it exists for this one exchange.
	ed, err := crypto.GetEncryptedData(plain, key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, fmt.Errorf("spnego: encrypt EncAPRepPart: %w", err)
	}

	rep := KRB5Token{
		OID:   m.OID,
		APRep: messages.APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: ed},
	}
	rep.tokID, _ = hex.DecodeString(TOK_ID_KRB_AP_REP)

	return rep.Marshal()
}

// ResponseToken returns the SPNEGO token an acceptor sends back once AcceptSecContext has succeeded:
// a NegTokenResp with the negotiation marked complete, carrying the AP-REP when the AP-REQ asked for
// mutual authentication.
//
// It is a separate call rather than a fourth return value from AcceptSecContext so that an acceptor
// which does not do mutual authentication is unaffected, and so that a caller that does can decide
// per request; an HTTP acceptor puts this in WWW-Authenticate, a gRPC one in a response header.
func (s *SPNEGOToken) ResponseToken() ([]byte, error) {
	if !s.Init {
		return nil, errors.New("spnego: only an initiator's token is answered")
	}
	mt, ok := s.NegTokenInit.mechToken.(*KRB5Token)
	if !ok || mt == nil {
		return nil, errors.New("spnego: no verified KRB5 mech token to answer")
	}

	rep, err := acceptorAPRep(mt)
	if err != nil {
		return nil, err
	}

	resp := NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptCompleted),
		SupportedMech: mt.OID,
		ResponseToken: rep,
	}

	return resp.Marshal()
}

func (s *SPNEGOToken) verifiedMechToken() *KRB5Token {
	var mt *KRB5Token
	if s.Init {
		mt, _ = s.NegTokenInit.mechToken.(*KRB5Token)
	} else if s.Resp {
		mt, _ = s.NegTokenResp.mechToken.(*KRB5Token)
	}

	return mt
}

func acceptorAPRep(mt *KRB5Token) ([]byte, error) {
	if mt == nil || !mutualRequested(mt) {
		return nil, nil
	}

	return mt.APRepToken()
}

// mutualRequested reports whether the initiator asked to be told who it is talking to.
//
// The request is read from the AP_REQ, where Kerberos puts it, and not from the NegTokenInit's ReqFlags, where
// SPNEGO once did. RFC 4178 Section 4.2.1 is explicit that the latter is not an acceptor's to read: "This field is
// inherited from RFC 2478 and is not integrity protected. For implementations of this specification, the initiator
// SHOULD omit this reqFlags field and the acceptor MUST ignore this reqFlags field."
//
// Two places in the AP_REQ carry the request and either one is taken as asking, because initiators differ in which
// they set:
//
//   - GSS_C_MUTUAL_FLAG in the authenticator checksum, RFC 4121 Section 4.1.1.1. This is the one an acceptor can
//     trust: the checksum is inside the authenticator, encrypted under the ticket's session key.
//   - The MUTUAL-REQUIRED AP option, RFC 4120 Section 5.5.1, which Section 3.2.5 makes the trigger for the AP_REP.
//     It travels in the clear, so it can be added or stripped in flight; an initiator that asked and had the bit
//     stripped gets no AP_REP and fails closed in SPNEGO.VerifyMutual, which is the safe direction.
//
// An AP_REQ carrying neither is not asking, and gets no AP_REP: RFC 4120 Section 3.2.5 conditions the reply on the
// request, and an initiator that did not ask has nothing to check and ignores what it cannot use.
func mutualRequested(mt *KRB5Token) bool {
	if types.IsFlagSet(&mt.APReq.APOptions, flags.APOptionMutualRequired) {
		return true
	}

	cksum := mt.APReq.Authenticator.Cksum.Checksum
	if mt.APReq.Authenticator.Cksum.CksumType != chksumtype.GSSAPI || len(cksum) < gssapi.ChecksumMinLen {
		return false
	}

	var c gssapi.AuthenticatorChecksum

	// A checksum too malformed to read is not a request. Verifying the AP_REQ is what rejects it; this only
	// decides whether to answer one that was already accepted.
	if err := c.Unmarshal(cksum); err != nil {
		return false
	}

	return c.Mutual()
}

// VerifyMutual checks the acceptor's reply and reports whether it proves the peer holds the service
// key. It is the initiator's half of what APRepToken produces, and it closes this package's own
// standing gap; KRB5Token.Verify still answers "verifying an AP_REP is not currently supported"
// for the generic case, which is the path a caller reaches without the session key this one kept.
//
// The proof is decryption: the AP-REP is encrypted under the ticket's session key, and only a peer
// that could decrypt the ticket ever saw it. The echoed ctime and cusec are then compared to what
// this initiator actually sent, which is what stops an AP-REP captured from an earlier exchange
// with the same service from being replayed at this one.
func (s *SPNEGO) VerifyMutual(b []byte) error {
	if len(s.sessionKey.KeyValue) == 0 {
		return errors.New("spnego: this context never initiated, so there is no reply to check")
	}

	var resp NegTokenResp
	if err := resp.Unmarshal(b); err != nil {
		return fmt.Errorf("spnego: the acceptor's reply is not a NegTokenResp: %w", err)
	}
	if NegState(resp.NegState) == NegStateReject {
		return errors.New("spnego: the acceptor rejected the negotiation")
	}
	if len(resp.ResponseToken) == 0 {
		return errors.New("spnego: the acceptor sent no AP-REP, so it has not proved who it is")
	}

	var mt KRB5Token
	if err := mt.Unmarshal(resp.ResponseToken); err != nil {
		return fmt.Errorf("spnego: the acceptor's response token is not a KRB5 token: %w", err)
	}
	if hex.EncodeToString(mt.tokID) != TOK_ID_KRB_AP_REP {
		return errors.New("spnego: the acceptor's response token is not an AP-REP")
	}

	plain, err := crypto.DecryptEncPart(mt.APRep.EncPart, s.sessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		// This is the load-bearing failure: anything that did not hold the service key could not
		// have produced something that decrypts under the session key inside the ticket.
		return fmt.Errorf("spnego: the AP-REP does not decrypt under this exchange's session key: %w", err)
	}
	var enc messages.EncAPRepPart
	if err := enc.Unmarshal(plain); err != nil {
		return fmt.Errorf("spnego: the AP-REP's encrypted part is malformed: %w", err)
	}

	// Compared at second precision plus cusec, which is the precision the protocol actually carries:
	// ctime travels as a GeneralizedTime and is truncated to the second on the wire, while the
	// sub-second part is what cusec is for. Comparing the initiator's in-memory time directly would
	// fail on the nanoseconds that never left the process.
	if enc.CTime.Unix() != s.sentCTime.Unix() || enc.Cusec != s.sentCusec {
		return errors.New("spnego: the AP-REP echoes a different time than this exchange sent, so it answers another one")
	}

	return nil
}
