package client

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-krb5/krb5/types"
)

// Settings holds optional client settings.
type Settings struct {
	disablePAFXFast         bool
	assumePreAuthentication atomic.Bool
	preAuthEType            atomic.Int32
	preAuthPAData           keptPAData
	logger                  *log.Logger
	dialer                  Dialer
}

type keptPAData struct {
	mu    sync.Mutex
	cname types.PrincipalName
	realm string
	pas   types.PADataSequence
}

func (k *keptPAData) store(cname types.PrincipalName, realm string, pas types.PADataSequence) {
	k.mu.Lock()
	defer k.mu.Unlock()

	cname.NameString = slices.Clone(cname.NameString)

	pas = slices.Clone(pas)
	for i := range pas {
		pas[i].PADataValue = slices.Clone(pas[i].PADataValue)
	}

	k.cname, k.realm, k.pas = cname, realm, pas
}

func (k *keptPAData) load(cname types.PrincipalName, realm string) types.PADataSequence {
	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.cname.Equal(cname) || k.realm != realm {
		return nil
	}

	return k.pas
}

// A Dialer is a means to establish a connection.
type Dialer interface {
	Dial(network, addr string) (c net.Conn, err error)
}

// jsonSettings is used when marshaling the Settings details to JSON format.
type jsonSettings struct {
	DisablePAFXFast         bool
	AssumePreAuthentication bool
}

// NewSettings creates a new client settings struct.
func NewSettings(settings ...func(*Settings)) *Settings {
	s := &Settings{
		dialer: &net.Dialer{
			Timeout: time.Second * 5,
		},
	}

	for _, set := range settings {
		set(s)
	}

	return s
}

// DisablePAFXFAST used to configure the client to not use PA_FX_FAST.
//
// s := NewSettings(DisablePAFXFAST(true)).
func DisablePAFXFAST(b bool) func(*Settings) {
	return func(s *Settings) {
		s.disablePAFXFast = b
	}
}

func UseDialer(dialer Dialer) func(*Settings) {
	return func(s *Settings) {
		s.dialer = dialer
	}
}

// DisablePAFXFAST indicates is the client should disable the use of PA_FX_FAST.
func (s *Settings) DisablePAFXFAST() bool {
	return s.disablePAFXFast
}

// AssumePreAuthentication used to configure the client to assume pre-authentication is required.
//
// s := NewSettings(AssumePreAuthentication(true)).
func AssumePreAuthentication(b bool) func(*Settings) {
	return func(s *Settings) {
		s.assumePreAuthentication.Store(b)
	}
}

// AssumePreAuthentication indicates if the client should proactively assume using pre-authentication.
func (s *Settings) AssumePreAuthentication() bool {
	return s.assumePreAuthentication.Load()
}

// Logger used to configure client with a logger.
//
// s := NewSettings(kt, Logger(l)).
func Logger(l *log.Logger) func(*Settings) {
	return func(s *Settings) {
		s.logger = l
	}
}

// Logger returns the client logger instance.
func (s *Settings) Logger() *log.Logger {
	return s.logger
}

// Log will write to the service's logger if it is configured.
func (cl *Client) Log(format string, v ...any) {
	if cl.settings.Logger() != nil {
		cl.settings.Logger().Output(2, fmt.Sprintf(format, v...))
	}
}

// JSON returns a JSON representation of the settings.
func (s *Settings) JSON() (string, error) {
	js := jsonSettings{
		DisablePAFXFast:         s.disablePAFXFast,
		AssumePreAuthentication: s.assumePreAuthentication.Load(),
	}

	b, err := json.MarshalIndent(js, "", "  ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}
