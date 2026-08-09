package service

import (
	"log"
	"net/http"
	"time"

	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/types"
)

// Settings defines service side configuration settings.
type Settings struct {
	Keytab             *keytab.Keytab
	ktprinc            *types.PrincipalName
	sname              string
	requireHostAddr    bool
	disablePACDecoding bool
	cAddr              types.HostAddress
	maxClockSkew       time.Duration
	logger             *log.Logger
	sessionMgr         SessionMgr
	channelBinding     *gssapi.ChannelBinding
}

// NewSettings creates a new service Settings.
func NewSettings(kt *keytab.Keytab, settings ...func(*Settings)) *Settings {
	s := new(Settings)

	s.Keytab = kt
	for _, set := range settings {
		set(s)
	}

	return s
}

// RequireHostAddr used to configure service side to required host addresses to be specified in Kerberos tickets.
//
// s := NewSettings(kt, RequireHostAddr(true)).
func RequireHostAddr(b bool) func(*Settings) {
	return func(s *Settings) {
		s.requireHostAddr = b
	}
}

// RequireHostAddr indicates if the service should require the host address to be included in the ticket.
func (s *Settings) RequireHostAddr() bool {
	return s.requireHostAddr
}

// DecodePAC used to configure service side to enable/disable PAC decoding if the PAC is present.
// Defaults to enabled if not specified.
//
// s := NewSettings(kt, DecodePAC(false)).
func DecodePAC(b bool) func(*Settings) {
	return func(s *Settings) {
		s.disablePACDecoding = !b
	}
}

// DecodePAC indicates whether the service should decode any PAC information present in the ticket.
func (s *Settings) DecodePAC() bool {
	return !s.disablePACDecoding
}

// ClientAddress used to configure service side with the clients host address to be used during validation.
//
// s := NewSettings(kt, ClientAddress(h)).
func ClientAddress(h types.HostAddress) func(*Settings) {
	return func(s *Settings) {
		s.cAddr = h
	}
}

// ClientAddress returns the client host address which has been provided to the service.
func (s *Settings) ClientAddress() types.HostAddress {
	return s.cAddr
}

// Logger used to configure service side with a logger.
//
// s := NewSettings(kt, Logger(l)).
func Logger(l *log.Logger) func(*Settings) {
	return func(s *Settings) {
		s.logger = l
	}
}

// Logger returns the logger instances configured for the service. If none is configured nill will be returned.
func (s *Settings) Logger() *log.Logger {
	return s.logger
}

// KeytabPrincipal used to override the principal name used to find the key in the keytab.
//
// s := NewSettings(kt, KeytabPrincipal("someaccount")).
func KeytabPrincipal(p string) func(*Settings) {
	return func(s *Settings) {
		pn, _ := types.ParseSPNString(p)
		s.ktprinc = &pn
	}
}

// KeytabPrincipal returns the principal name used to find the key in the keytab if it has been overridden.
func (s *Settings) KeytabPrincipal() *types.PrincipalName {
	return s.ktprinc
}

// MaxClockSkew used to configure service side with the maximum acceptable clock skew
// between the service and the issue time of kerberos tickets
//
// s := NewSettings(kt, MaxClockSkew(d)).
func MaxClockSkew(d time.Duration) func(*Settings) {
	return func(s *Settings) {
		s.maxClockSkew = d
	}
}

// MaxClockSkew returns the maximum acceptable clock skew between the service and the issue time of kerberos tickets.
// If none is defined a duration of 5 minutes is returned.
func (s *Settings) MaxClockSkew() time.Duration {
	if s.maxClockSkew.Nanoseconds() == 0 {
		return time.Duration(5) * time.Minute
	}

	return s.maxClockSkew
}

// SName used provide a specific service name to the service settings.
//
// s := NewSettings(kt, SName("HTTP/some.service.com")).
func SName(sname string) func(*Settings) {
	return func(s *Settings) {
		s.sname = sname
	}
}

// SName returns the specific service name to the service.
func (s *Settings) SName() string {
	return s.sname
}

// SessionManager configures a session manager to establish sessions with clients to avoid excessive authentication challenges.
//
// s := NewSettings(kt, SessionManager(sm)).
func SessionManager(sm SessionMgr) func(*Settings) {
	return func(s *Settings) {
		s.sessionMgr = sm
	}
}

// SessionManager returns any configured session manager.
func (s *Settings) SessionManager() SessionMgr {
	return s.sessionMgr
}

// RequireChannelBinding used to configure the service to require the GSS-API channel binding provided. The binding
// is compared against the Bnd field of the AP_REQ authenticator checksum described by RFC 4121 Section 4.1.1.
//
// When configured, a request that carries no channel binding is rejected: requiring a binding means requiring it.
// When left unset no verification is performed, which is the default.
//
// Passing a nil binding disables verification exactly as if this option were never supplied: there is no error and
// no log line, the service simply accepts requests without checking a binding. The gssapi.NewChannelBinding*
// constructors return a nil binding alongside a non-nil error in some cases (for example, no mTLS on the
// connection, or a certificate whose signature algorithm such as Ed25519 has no single hash to bind to), so callers
// must check that error rather than discarding it before passing the result here.
//
// s := NewSettings(kt, RequireChannelBinding(cb)).
func RequireChannelBinding(cb *gssapi.ChannelBinding) func(*Settings) {
	return func(s *Settings) {
		s.channelBinding = cb
	}
}

// RequireChannelBinding returns the channel binding the service requires, or nil if it does not require one.
func (s *Settings) RequireChannelBinding() *gssapi.ChannelBinding {
	return s.channelBinding
}

// SessionMgr must provide a ways to:
//
// - Create new sessions and in the process add a value to the session under the key provided.
//
// - Get an existing session returning the value in the session under the key provided.
// Return nil bytes and/or error if there is no session.
type SessionMgr interface {
	New(w http.ResponseWriter, r *http.Request, k any, v []byte) error
	Get(r *http.Request, k any) ([]byte, error)
}
