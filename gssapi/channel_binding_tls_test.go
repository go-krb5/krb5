package gssapi

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTLSServerEndPointHashShouldFollowRFC5929 asserts the hash selection rules of RFC 5929 Section 4.1, including
// the mandatory upgrade of MD5 and SHA-1 to SHA-256.
func TestTLSServerEndPointHashShouldFollowRFC5929(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		alg  x509.SignatureAlgorithm
		size int
	}{
		{"MD5WithRSAUpgradesToSHA256", x509.MD5WithRSA, sha256.Size},
		{"SHA1WithRSAUpgradesToSHA256", x509.SHA1WithRSA, sha256.Size},
		{"ECDSAWithSHA1UpgradesToSHA256", x509.ECDSAWithSHA1, sha256.Size},
		{"DSAWithSHA1UpgradesToSHA256", x509.DSAWithSHA1, sha256.Size},
		{"SHA256WithRSA", x509.SHA256WithRSA, sha256.Size},
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, sha256.Size},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, sha256.Size},
		{"SHA384WithRSA", x509.SHA384WithRSA, sha512.Size384},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, sha512.Size384},
		{"SHA512WithRSA", x509.SHA512WithRSA, sha512.Size},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, sha512.Size},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, err := tlsServerEndPointHash(tc.alg)
			require.NoError(t, err)
			assert.Equal(t, tc.size, h.Size())
		})
	}
}

// TestTLSServerEndPointHashShouldRejectAlgorithmsWithoutASingleHash asserts the case upstream PR #572 got wrong.
// RFC 5929 Section 4.1 leaves the binding undefined when the signature algorithm uses no single hash function, so
// guessing SHA-256 would produce a binding the peer computes differently and fail authentication silently.
func TestTLSServerEndPointHashShouldRejectAlgorithmsWithoutASingleHash(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		alg  x509.SignatureAlgorithm
	}{
		{"PureEd25519", x509.PureEd25519},
		{"MD2WithRSA", x509.MD2WithRSA},
		{"Unknown", x509.UnknownSignatureAlgorithm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := tlsServerEndPointHash(tc.alg)
			require.ErrorIs(t, err, ErrChannelBindingUndefined)
		})
	}
}

func TestNewChannelBindingTLSServerEndPointShouldPrefixAndHashTheCertificate(t *testing.T) {
	t.Parallel()

	cert := testChannelBindingCertificate(t, x509.SHA256WithRSA)

	cb, err := NewChannelBindingTLSServerEndPoint(cert)
	require.NoError(t, err)

	sum := sha256.Sum256(cert.Raw)
	expected := append([]byte("tls-server-end-point:"), sum[:]...)

	assert.Equal(t, expected, cb.ApplicationData)
	assert.Equal(t, AddressTypeUnspecified, cb.InitiatorAddrType)
	assert.Equal(t, AddressTypeUnspecified, cb.AcceptorAddrType)
	assert.Nil(t, cb.InitiatorAddress)
	assert.Nil(t, cb.AcceptorAddress)
}

func TestNewChannelBindingTLSServerEndPointShouldUseSHA384ForSHA384Certificates(t *testing.T) {
	t.Parallel()

	cert := testChannelBindingCertificate(t, x509.SHA384WithRSA)

	cb, err := NewChannelBindingTLSServerEndPoint(cert)
	require.NoError(t, err)

	sum := sha512.Sum384(cert.Raw)

	assert.True(t, bytes.HasSuffix(cb.ApplicationData, sum[:]))
}

func TestNewChannelBindingTLSServerEndPointShouldRejectNilCertificate(t *testing.T) {
	t.Parallel()

	_, err := NewChannelBindingTLSServerEndPoint(nil)
	require.EqualError(t, err, "no certificate provided")
}

func TestNewChannelBindingTLSServerEndPointFromStateShouldRejectMissingInput(t *testing.T) {
	t.Parallel()

	_, err := NewChannelBindingTLSServerEndPointFromState(nil)
	require.EqualError(t, err, "no TLS connection state provided")

	_, err = NewChannelBindingTLSServerEndPointFromState(&tls.ConnectionState{})
	require.EqualError(t, err, "TLS connection state contains no peer certificates")
}

// testChannelBindingCertificate builds a self signed certificate carrying the requested signature algorithm.
func testChannelBindingCertificate(t *testing.T, alg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()

	der, _ := testChannelBindingSelfSignedCertificate(t, alg)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// testChannelBindingSelfSignedCertificate generates a self signed RSA certificate carrying the requested signature
// algorithm, returning both the DER encoding and the private key. testChannelBindingCertificate parses the DER for
// callers that only need the certificate; testChannelBindingTLSStates uses both to build a tls.Certificate for a
// real handshake.
func testChannelBindingSelfSignedCertificate(t *testing.T, alg x509.SignatureAlgorithm) ([]byte, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "channel-binding-test"},
		DNSNames:           []string{"localhost"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: alg,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return der, key
}

// TestNewChannelBindingTLSExporterShouldAgreeAcrossPeers asserts the property that actually matters for a channel
// binding: both ends of the same connection derive identical bytes.
func TestNewChannelBindingTLSExporterShouldAgreeAcrossPeers(t *testing.T) {
	t.Parallel()

	cs, ss := testChannelBindingTLSStates(t, tls.VersionTLS13)

	c, err := NewChannelBindingTLSExporter(&cs)
	require.NoError(t, err)

	s, err := NewChannelBindingTLSExporter(&ss)
	require.NoError(t, err)

	assert.Equal(t, c.ApplicationData, s.ApplicationData)
	assert.True(t, bytes.HasPrefix(c.ApplicationData, []byte("tls-exporter:")))
	assert.Len(t, c.ApplicationData, len("tls-exporter:")+32)
}

// TestNewChannelBindingTLSExporterShouldUseZeroLengthContextPerRFC9266 pins the choice of exporter context. The
// cross-peer agreement tests cannot catch a regression here because both peers run the same code and would agree on
// a wrong value just as happily. RFC 9266 Section 3 specifies a zero-length context, which Go's ExportKeyingMaterial
// treats differently from an absent (nil) one on TLS 1.2; see channelBindingExporterContext. This asserts the
// binding matches the zero-length-context computation and does not match the nil-context one, so the test fails if
// the implementation is ever reverted to nil.
func TestNewChannelBindingTLSExporterShouldUseZeroLengthContextPerRFC9266(t *testing.T) {
	t.Parallel()

	cs, _ := testChannelBindingTLSStates(t, tls.VersionTLS12)

	c, err := NewChannelBindingTLSExporter(&cs)
	require.NoError(t, err)

	wantZeroLength, err := cs.ExportKeyingMaterial(channelBindingExporterLabel, []byte{}, channelBindingExporterLength)
	require.NoError(t, err)

	nilContext, err := cs.ExportKeyingMaterial(channelBindingExporterLabel, nil, channelBindingExporterLength)
	require.NoError(t, err)

	require.NotEqual(t, nilContext, wantZeroLength,
		"TLS 1.2 exporter output is expected to differ between a nil and a zero-length context; if this fails, "+
			"Go's ExportKeyingMaterial behaviour changed and the regression guard below no longer proves anything")

	assert.Equal(t, append([]byte("tls-exporter:"), wantZeroLength...), c.ApplicationData)
	assert.NotEqual(t, append([]byte("tls-exporter:"), nilContext...), c.ApplicationData)
}

func TestNewChannelBindingTLSUniqueShouldAgreeAcrossPeersOnTLS12(t *testing.T) {
	t.Parallel()

	cs, ss := testChannelBindingTLSStates(t, tls.VersionTLS12)

	c, err := NewChannelBindingTLSUnique(&cs)
	require.NoError(t, err)

	s, err := NewChannelBindingTLSUnique(&ss)
	require.NoError(t, err)

	assert.Equal(t, c.ApplicationData, s.ApplicationData)
	assert.True(t, bytes.HasPrefix(c.ApplicationData, []byte("tls-unique:")))
}

// TestNewChannelBindingTLSUniqueShouldRejectTLS13 asserts the documented limitation: Go leaves TLSUnique nil on
// TLS 1.3, and binding to nothing must be an error rather than a silent empty binding.
func TestNewChannelBindingTLSUniqueShouldRejectTLS13(t *testing.T) {
	t.Parallel()

	cs, _ := testChannelBindingTLSStates(t, tls.VersionTLS13)

	_, err := NewChannelBindingTLSUnique(&cs)
	require.ErrorIs(t, err, ErrChannelBindingUndefined)
}

func TestChannelBindingTLSConstructorsShouldRejectNilState(t *testing.T) {
	t.Parallel()

	_, err := NewChannelBindingTLSExporter(nil)
	require.EqualError(t, err, "no TLS connection state provided")

	_, err = NewChannelBindingTLSUnique(nil)
	require.EqualError(t, err, "no TLS connection state provided")
}

// testChannelBindingTLSStates performs a real handshake over an in-memory pipe and returns the client and server
// connection states for it.
func testChannelBindingTLSStates(t *testing.T, version uint16) (client, server tls.ConnectionState) {
	t.Helper()

	der, key := testChannelBindingSelfSignedCertificate(t, x509.SHA256WithRSA)

	cp, sp := net.Pipe()

	t.Cleanup(func() {
		_ = cp.Close()
		_ = sp.Close()
	})

	serverConn := tls.Server(sp, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   version,
		MaxVersion:   version,
	})

	clientConn := tls.Client(cp, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Self signed fixture certificate in a test.
		MinVersion:         version,
		MaxVersion:         version,
	})

	errCh := make(chan error, 1)

	go func() { errCh <- serverConn.Handshake() }()

	require.NoError(t, clientConn.Handshake())
	require.NoError(t, <-errCh)

	return clientConn.ConnectionState(), serverConn.ConnectionState()
}
