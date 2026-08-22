package spnego

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/messages"
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
// a NegTokenResp carrying the AP-REP, with the negotiation marked complete.
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

	resp := NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptCompleted),
		SupportedMech: mt.OID,
	}
	if mutualRequested(s.NegTokenInit) {
		rep, err := mt.APRepToken()
		if err != nil {
			return nil, err
		}
		resp.ResponseToken = rep
	}

	return resp.Marshal()
}

// mutualRequested reports whether the initiator asked to be told who it is talking to.
//
// The flag lives in the NegTokenInit's ReqFlags, which is optional and frequently absent; NewNegTokenInitKRB5 does not
// set it at all. A client that omits it has expressed no preference, and answering anyway costs one encryption while
// giving a client that DOES check something to check. So an absent ReqFlags is treated as "answer it": for an
// authentication feature the conservative direction is the one that proves more, not less.
func mutualRequested(n NegTokenInit) bool {
	if len(n.ReqFlags.Bytes) == 0 {
		return true
	}
	return n.ReqFlags.At(gssapiMutualFlagBit) == 1
}

// gssapiMutualFlagBit is GSS_C_MUTUAL_FLAG's position in the SPNEGO ContextFlags bit string
// (RFC 4178 §4.2.1: delegFlag(0), mutualFlag(1), …).
const gssapiMutualFlagBit = 1

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
