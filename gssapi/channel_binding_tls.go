package gssapi

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
)

// Channel binding type names as registered by RFC 5929 and RFC 9266. Each appears in the application data followed
// by a colon and the binding data itself.
const (
	ChannelBindingTypeTLSServerEndPoint = "tls-server-end-point"
	ChannelBindingTypeTLSUnique         = "tls-unique"
	ChannelBindingTypeTLSExporter       = "tls-exporter"
)

// ErrChannelBindingUndefined is returned when a channel binding cannot be derived from the connection. The binding
// is not merely unavailable: deriving one anyway would produce a value the peer computes differently, so
// authentication would fail with nothing to point at. Callers should either fall back to no channel binding or
// treat the connection as unusable, rather than substituting another value.
var ErrChannelBindingUndefined = errors.New("channel binding is undefined for this connection")

// NewChannelBindingTLSServerEndPoint returns the tls-server-end-point channel binding of RFC 5929 Section 4 for the
// server certificate provided. This is the binding type Microsoft's Extended Protection for Authentication uses and
// it applies to both TLS 1.2 and TLS 1.3.
//
// The hash is selected from the certificate's own signature algorithm per RFC 5929 Section 4.1. Certificates whose
// signature algorithm uses no single hash function, such as Ed25519, produce ErrChannelBindingUndefined.
func NewChannelBindingTLSServerEndPoint(cert *x509.Certificate) (*ChannelBinding, error) {
	if cert == nil {
		return nil, errors.New("no certificate provided")
	}

	h, err := tlsServerEndPointHash(cert.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	h.Write(cert.Raw)

	return newChannelBindingApplicationData(ChannelBindingTypeTLSServerEndPoint, h.Sum(nil)), nil
}

// NewChannelBindingTLSServerEndPointFromState returns the tls-server-end-point channel binding derived from the
// leaf certificate the peer presented in the TLS connection state provided.
//
// This is for initiator (client) use only: on a client connection, PeerCertificates holds the chain the server
// presented, which is exactly what tls-server-end-point requires. On a server connection, PeerCertificates instead
// holds the client's chain (only present at all when mTLS is in use), so calling this from acceptor code either
// errors out or, worse, computes a binding over the wrong certificate that every legitimate client will then fail
// to match. Acceptor-side callers must instead derive the binding from their own configured server certificate,
// via NewChannelBindingTLSServerEndPoint, and pass the result to service.RequireChannelBinding.
func NewChannelBindingTLSServerEndPointFromState(cs *tls.ConnectionState) (*ChannelBinding, error) {
	if cs == nil {
		return nil, errors.New("no TLS connection state provided")
	}

	if len(cs.PeerCertificates) == 0 {
		return nil, errors.New("TLS connection state contains no peer certificates")
	}

	return NewChannelBindingTLSServerEndPoint(cs.PeerCertificates[0])
}

// tlsServerEndPointHash returns the hash to digest the certificate with, per RFC 5929 Section 4.1: a signature
// algorithm based on MD5 or SHA-1 is upgraded to SHA-256, any other single hash function is used as is, and an
// algorithm using no single hash function leaves the binding undefined.
func tlsServerEndPointHash(alg x509.SignatureAlgorithm) (hash.Hash, error) {
	switch alg {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1,
		x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return sha256.New(), nil
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return sha512.New384(), nil
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return sha512.New(), nil
	case x509.MD2WithRSA:
		return nil, fmt.Errorf("%w: certificate signature algorithm %s uses a hash function Go does not implement", ErrChannelBindingUndefined, alg)
	default:
		return nil, fmt.Errorf("%w: certificate signature algorithm %s does not use a single hash function", ErrChannelBindingUndefined, alg)
	}
}

// newChannelBindingApplicationData builds a ChannelBinding whose application data is the binding type, a colon and
// the binding data, with the address fields left unset as is standard for the TLS binding types.
func newChannelBindingApplicationData(cbType string, data []byte) *ChannelBinding {
	d := make([]byte, 0, len(cbType)+1+len(data))
	d = append(d, cbType...)
	d = append(d, ':')
	d = append(d, data...)

	return &ChannelBinding{
		InitiatorAddrType: AddressTypeUnspecified,
		AcceptorAddrType:  AddressTypeUnspecified,
		ApplicationData:   d,
	}
}

// RFC 9266 Section 3 defines the tls-exporter binding as a TLS exporter run with this label and output length.
const (
	channelBindingExporterLabel  = "EXPORTER-Channel-Binding"
	channelBindingExporterLength = 32
)

// channelBindingExporterContext is the context RFC 9266 Section 3 specifies for the tls-exporter binding: "Context
// value: Zero-length string." That is a context that is present but empty, not an absent one. Go's
// ExportKeyingMaterial treats a nil context as omitted from the exporter seed entirely, which RFC 5705 (TLS 1.2)
// distinguishes from an explicit zero-length context; the two happen to coincide on TLS 1.3, whose exporter always
// hashes the context, but diverge on TLS 1.2. Keep this a non-nil, zero-length slice; do not simplify it to nil.
var channelBindingExporterContext = []byte{}

// NewChannelBindingTLSExporter returns the tls-exporter channel binding of RFC 9266 for the TLS connection state
// provided.
//
// RFC 9266 requires either TLS 1.3 or the extended master secret extension of RFC 7627. Go enforces exactly that
// precondition in ExportKeyingMaterial, and also refuses when renegotiation is enabled, so its error is wrapped in
// ErrChannelBindingUndefined and returned unchanged.
func NewChannelBindingTLSExporter(cs *tls.ConnectionState) (*ChannelBinding, error) {
	if cs == nil {
		return nil, errors.New("no TLS connection state provided")
	}

	b, err := cs.ExportKeyingMaterial(channelBindingExporterLabel, channelBindingExporterContext, channelBindingExporterLength)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrChannelBindingUndefined, err)
	}

	return newChannelBindingApplicationData(ChannelBindingTypeTLSExporter, b), nil
}

// NewChannelBindingTLSUnique returns the tls-unique channel binding of RFC 5929 Section 3 for the TLS connection
// state provided.
//
// Go does not populate TLSUnique for TLS 1.3 connections, nor for resumed connections without the extended master
// secret extension of RFC 7627, and this returns ErrChannelBindingUndefined in those cases. Prefer
// NewChannelBindingTLSExporter on TLS 1.3, or NewChannelBindingTLSServerEndPoint which works on both versions.
func NewChannelBindingTLSUnique(cs *tls.ConnectionState) (*ChannelBinding, error) {
	if cs == nil {
		return nil, errors.New("no TLS connection state provided")
	}

	if len(cs.TLSUnique) == 0 {
		return nil, fmt.Errorf("%w: tls-unique is not available for TLS 1.3 or for a resumed connection without extended master secret", ErrChannelBindingUndefined)
	}

	return newChannelBindingApplicationData(ChannelBindingTypeTLSUnique, cs.TLSUnique), nil
}
