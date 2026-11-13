// Package config implements KRB5 client and service configuration as described at
// https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html.
//
// The file is read as MIT krb5's profile library reads it. Lines whose first non-blank character is '#' or ';' are
// comments, and nothing else is: a '#' or ';' later in a line is part of the value. Sections and subsections that
// appear more than once are merged, and where a relation that takes a single value appears more than once the first
// value is used. The include and includedir directives are honoured, and a '*' after a section header, a tag or a
// closing brace marks it final.
package config

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-krb5/x/encoding/asn1"
)

// Config represents the KRB5 configuration.
type Config struct {
	LibDefaults LibDefaults
	Realms      []Realm
	DomainRealm DomainRealm
	// CaPaths.
	// AppDefaults.
	// Plugins.

	realmLibDefaults map[string]LibDefaults
}

// WeakETypeList is a list of encryption types that have been deemed weak.
const WeakETypeList = "des-cbc-crc des-cbc-md4 des-cbc-md5 des-cbc-raw des3-cbc-raw des-hmac-sha1 arcfour-hmac-exp rc4-hmac-exp arcfour-hmac-md5-exp des"

// New creates a new config struct instance.
func New() *Config {
	d := make(DomainRealm)

	return &Config{
		LibDefaults: newLibDefaults(),
		DomainRealm: d,
	}
}

// LibDefaults represents the [libdefaults] section of the configuration. The defaults are those of MIT krb5.
// The following values are not implemented: ap_req_checksum_type int, kdc_req_checksum_type int, plugin_base_dir string.
type LibDefaults struct {
	// AllowWeakCrypto has a default value of false.
	AllowWeakCrypto bool

	// Canonicalize has a default value of false.
	Canonicalize bool

	// CCacheType has a default value of 4.
	CCacheType int

	// Clockskew is the max allowed skew and has a default value of 300 seconds. It is read from the clockskew
	// relation.
	Clockskew time.Duration

	// DefaultCCacheName is the name of the default credential cache, with its parameters expanded. It has a default
	// value of FILE:/tmp/krb5cc_%{uid}. Config.CCacheName also consults the KRB5CCNAME environment variable.
	DefaultCCacheName string

	// DefaultClientKeytabName has a default value of /usr/local/var/krb5/user/%{euid}/client.keytab, with its
	// parameters expanded. Config.ClientKeytabName also consults the KRB5_CLIENT_KTNAME environment variable.
	DefaultClientKeytabName string

	// DefaultKeytabName has a default value of /etc/krb5.keytab. Config.KeytabName also consults the KRB5_KTNAME
	// environment variable.
	DefaultKeytabName string

	DefaultRealm string

	// DefaultTGSEnctypes defaults to the value of permitted_enctypes.
	DefaultTGSEnctypes []string

	// DefaultTktEnctypes defaults to the value of permitted_enctypes.
	DefaultTktEnctypes []string

	// DefaultTGSEnctypeIDs are the encryption types DefaultTGSEnctypes resolves to.
	DefaultTGSEnctypeIDs []int32

	// DefaultTktEnctypeIDs are the encryption types DefaultTktEnctypes resolves to.
	DefaultTktEnctypeIDs []int32

	// DNSCanonicalizeHostname governs whether DNS is consulted to canonicalize a hostname when deriving a
	// service principal name. It has a default value of true.
	//
	// This decides which service key the KDC encrypts the ticket to, so leaving it enabled lets DNS choose that
	// principal. Set it to false where the resolver is not trusted to.
	DNSCanonicalizeHostname bool

	// DNSCanonicalizeHostnameFallback is set when dns_canonicalize_hostname is fallback. A service principal name
	// is then first derived from the hostname as given, which leaves DNSCanonicalizeHostname false, and is only
	// canonicalized with DNS if the KDC does not know the principal.
	DNSCanonicalizeHostnameFallback bool

	// DNSLookupKDC governs whether DNS SRV records are used to locate the KDCs and kpasswd servers of a realm the
	// configuration lists none for. It has a default value of true, and falls back to the value of dns_fallback.
	DNSLookupKDC bool

	// DNSLookupRealm has a default value of false, and falls back to the value of dns_fallback.
	DNSLookupRealm bool

	ExtraAddresses []net.IP

	// Forwardable has a default value of false.
	Forwardable bool

	// IgnoreAcceptorHostname has a default value of false.
	IgnoreAcceptorHostname bool

	// K5LoginAuthoritative has a default value of true.
	K5LoginAuthoritative bool

	// K5LoginDirectory has a default value based on the user's home directory. Must be owned by the user or root.
	K5LoginDirectory string

	// KDCDefaultOptions has a default value of 0x00000010 (KDC_OPT_RENEWABLE_OK). It may be given in decimal, or in
	// hexadecimal with a 0x prefix.
	KDCDefaultOptions asn1.BitString

	// KDCTimeSync has a default value of 1.
	KDCTimeSync int

	// NoAddresses has a default value of true.
	NoAddresses bool

	// PermittedEnctypes has a default value of DEFAULT, which stands for aes256-cts-hmac-sha1-96
	// aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128 des3-cbc-sha1 arcfour-hmac
	// camellia128-cts-cmac camellia256-cts-cmac.
	PermittedEnctypes []string

	PermittedEnctypeIDs []int32

	// PreferredPreauthTypes has a default value of 17, 16, 15, 14; which forces an attempt to use PKINIT if it is
	// supported.
	PreferredPreauthTypes []int

	// Proxiable has a default value of false.
	Proxiable bool

	// RDNS has a default value of true.
	//
	// It governs whether reverse name lookup is used in addition to forward lookup when canonicalizing a
	// hostname. This library performs no reverse lookup, so the setting is parsed and has no effect; forward
	// canonicalization is governed by DNSCanonicalizeHostname.
	RDNS bool

	// RealmTryDomains has a default value of -1.
	RealmTryDomains int

	// RenewLifetime has a default value of 0.
	RenewLifetime time.Duration

	// SafeChecksumType has a default value of 8.
	SafeChecksumType int

	// TicketLifetime has a default value of 1 day.
	TicketLifetime time.Duration

	// UDPPreferenceLimit determines if UDP is used, 1 means to always use tcp. A value above 32700 is treated as
	// 32700 and a negative value as the default, which is 1465.
	UDPPreferenceLimit int

	// VerifyAPReqNofail has a default value of false.
	VerifyAPReqNofail bool
}

const (
	defaultCCacheName       = "FILE:/tmp/krb5cc_%{uid}"
	defaultConfigPath       = "/etc/krb5.conf"
	defaultClientKeytabName = "/usr/local/var/krb5/user/%{euid}/client.keytab"
	defaultKDCOptions       = 0x00000010
	defaultUDPPreference    = 1465
	maxUDPPreference        = 32700
)

func newLibDefaults() LibDefaults {
	var hdir string

	if usr, _ := user.Current(); usr != nil {
		hdir = usr.HomeDir
	}

	l := LibDefaults{
		CCacheType:              4,
		Clockskew:               time.Duration(300) * time.Second,
		DefaultCCacheName:       mustExpandPath(defaultCCacheName),
		DefaultClientKeytabName: mustExpandPath(defaultClientKeytabName),
		DefaultKeytabName:       "/etc/krb5.keytab",
		DefaultTGSEnctypes:      slices.Clone(defaultETypeNames),
		DefaultTktEnctypes:      slices.Clone(defaultETypeNames),
		DNSCanonicalizeHostname: true,
		DNSLookupKDC:            true,
		K5LoginAuthoritative:    true,
		K5LoginDirectory:        hdir,
		KDCDefaultOptions:       kdcOptions(defaultKDCOptions),
		KDCTimeSync:             1,
		NoAddresses:             true,
		PermittedEnctypes:       slices.Clone(defaultETypeNames),
		RDNS:                    true,
		RealmTryDomains:         -1,
		SafeChecksumType:        8,
		TicketLifetime:          time.Duration(24) * time.Hour,
		UDPPreferenceLimit:      defaultUDPPreference,
		PreferredPreauthTypes:   []int{17, 16, 15, 14},
	}
	l.resolveETypes()

	return l
}

func mustExpandPath(path string) string {
	if v, err := ExpandPath(path); err == nil {
		return v
	}

	return path
}

func kdcOptions(v uint32) asn1.BitString {
	b := binary.BigEndian.AppendUint32(nil, v)

	return asn1.BitString{Bytes: b, BitLength: len(b) * 8}
}

func (l *LibDefaults) resolveETypes() {
	l.DefaultTGSEnctypeIDs = parseETypes(l.DefaultTGSEnctypes, l.AllowWeakCrypto)
	l.DefaultTktEnctypeIDs = parseETypes(l.DefaultTktEnctypes, l.AllowWeakCrypto)
	l.PermittedEnctypeIDs = parseETypes(l.PermittedEnctypes, l.AllowWeakCrypto)
}

type libDefaultSetter func(l *LibDefaults, v string) error

func booleanSetter(set func(l *LibDefaults, v bool)) libDefaultSetter {
	return func(l *LibDefaults, s string) error {
		v, err := parseBoolean(s)
		if err != nil {
			return err
		}

		set(l, v)

		return nil
	}
}

func integerSetter(set func(l *LibDefaults, v int)) libDefaultSetter {
	return func(l *LibDefaults, s string) error {
		v, err := parseInteger(s)
		if err != nil {
			return err
		}

		set(l, v)

		return nil
	}
}

func durationSetter(set func(l *LibDefaults, v time.Duration)) libDefaultSetter {
	return func(l *LibDefaults, s string) error {
		v, err := parseDuration(s)
		if err != nil {
			return err
		}

		set(l, v)

		return nil
	}
}

func pathSetter(set func(l *LibDefaults, v string)) libDefaultSetter {
	return func(l *LibDefaults, s string) error {
		v, err := ExpandPath(s)

		switch {
		case errors.Is(err, errUnresolvableToken):
			v = s
		case err != nil:
			return err
		}

		set(l, v)

		return nil
	}
}

var libDefaultSetters = map[string]libDefaultSetter{
	ConfigKeyAllowWeakCrypto: booleanSetter(func(l *LibDefaults, v bool) { l.AllowWeakCrypto = v }),
	ConfigKeyCanonicalize:    booleanSetter(func(l *LibDefaults, v bool) { l.Canonicalize = v }),
	ConfigKeyCredentialCacheType: integerSetter(func(l *LibDefaults, v int) {
		l.CCacheType = v
	}),
	ConfigKeyClockSkew:               durationSetter(func(l *LibDefaults, v time.Duration) { l.Clockskew = v }),
	ConfigKeyDefaultCCacheName:       pathSetter(func(l *LibDefaults, v string) { l.DefaultCCacheName = v }),
	ConfigKeyDefaultClientKeytabName: pathSetter(func(l *LibDefaults, v string) { l.DefaultClientKeytabName = v }),
	ConfigKeyDefaultKeytabName:       pathSetter(func(l *LibDefaults, v string) { l.DefaultKeytabName = v }),
	ConfigKeyDefaultRealm: func(l *LibDefaults, v string) error {
		l.DefaultRealm = v

		return nil
	},
	ConfigKeyDNSCanonicalizeHostname: func(l *LibDefaults, s string) error {
		if strings.EqualFold(s, "fallback") {
			l.DNSCanonicalizeHostname, l.DNSCanonicalizeHostnameFallback = false, true

			return nil
		}

		v, err := parseBoolean(s)
		if err != nil {
			return err
		}

		l.DNSCanonicalizeHostname, l.DNSCanonicalizeHostnameFallback = v, false

		return nil
	},
	ConfigKeyForwardable:            booleanSetter(func(l *LibDefaults, v bool) { l.Forwardable = v }),
	ConfigKeyIgnoreAcceptorHostname: booleanSetter(func(l *LibDefaults, v bool) { l.IgnoreAcceptorHostname = v }),
	ConfigKeyK5LoginAuthorative:     booleanSetter(func(l *LibDefaults, v bool) { l.K5LoginAuthoritative = v }),
	ConfigKeyK5LoginDirectory: func(l *LibDefaults, v string) error {
		l.K5LoginDirectory = v

		return nil
	},
	ConfigKeyKDCDefaultOptions: func(l *LibDefaults, s string) error {
		v, err := parseKDCOptions(s)
		if err != nil {
			return err
		}

		l.KDCDefaultOptions = kdcOptions(v)

		return nil
	},
	ConfigKeyKDCTimeSync: integerSetter(func(l *LibDefaults, v int) { l.KDCTimeSync = v }),
	ConfigKeyNoAddresses: booleanSetter(func(l *LibDefaults, v bool) { l.NoAddresses = v }),
	ConfigKeyProxiable:   booleanSetter(func(l *LibDefaults, v bool) { l.Proxiable = v }),
	ConfigKeyRDNS:        booleanSetter(func(l *LibDefaults, v bool) { l.RDNS = v }),
	ConfigKeyRenewLifetime: durationSetter(func(l *LibDefaults, v time.Duration) {
		l.RenewLifetime = v
	}),
	ConfigKeyPreferredPreAuthTypes: func(l *LibDefaults, s string) error {
		v, err := parsePreauthTypes(s)
		if err != nil {
			return err
		}

		l.PreferredPreauthTypes = v

		return nil
	},
	ConfigKeyRealmTryDomains: integerSetter(func(l *LibDefaults, v int) { l.RealmTryDomains = v }),
	ConfigKeySafeChecksumType: integerSetter(func(l *LibDefaults, v int) {
		l.SafeChecksumType = v
	}),
	ConfigKeyTicketLifetime: durationSetter(func(l *LibDefaults, v time.Duration) {
		l.TicketLifetime = v
	}),
	ConfigKeyUDPPreferenceLimit: integerSetter(func(l *LibDefaults, v int) {
		switch {
		case v < 0:
			v = defaultUDPPreference
		case v > maxUDPPreference:
			v = maxUDPPreference
		}

		l.UDPPreferenceLimit = v
	}),
	ConfigKeyVerifyAPReqNoFail: booleanSetter(func(l *LibDefaults, v bool) { l.VerifyAPReqNofail = v }),
}

var realmLibDefaultKeys = []string{
	ConfigKeyCanonicalize,
	ConfigKeyForwardable,
	ConfigKeyNoAddresses,
	ConfigKeyPreferredPreAuthTypes,
	ConfigKeyProxiable,
	ConfigKeyRenewLifetime,
	ConfigKeyTicketLifetime,
	ConfigKeyVerifyAPReqNoFail,
}

func (l *LibDefaults) set(key, value string) error {
	if err := libDefaultSetters[key](l, value); err != nil {
		return InvalidErrorf("libdefaults relation %s (%s): %v", key, value, err)
	}

	return nil
}

func (l *LibDefaults) load(p *profile) error {
	keys := make([]string, 0, len(libDefaultSetters))
	for key := range libDefaultSetters {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	for _, key := range keys {
		if v, ok := p.value(ConfigSectionLibDefaults, key); ok {
			if err := l.set(key, v); err != nil {
				return err
			}
		}
	}

	l.DNSLookupKDC = dnsLookup(p, ConfigKeyDNSLookupKDC, l.DNSLookupKDC)
	l.DNSLookupRealm = dnsLookup(p, ConfigKeyDNSLookupRealm, l.DNSLookupRealm)

	for _, v := range p.values(ConfigSectionLibDefaults, ConfigKeyExtraAddresses) {
		for _, a := range splitETypeList(v) {
			if ip := net.ParseIP(a); ip != nil {
				l.ExtraAddresses = append(l.ExtraAddresses, ip)
			}
		}
	}

	permitted, ok := p.value(ConfigSectionLibDefaults, ConfigKeyPermittedEncTypes)
	if ok {
		l.PermittedEnctypes = splitETypeList(permitted)
		l.DefaultTktEnctypes = slices.Clone(l.PermittedEnctypes)
		l.DefaultTGSEnctypes = slices.Clone(l.PermittedEnctypes)
	}

	if v, ok := p.value(ConfigSectionLibDefaults, ConfigKeyDefaultTKTENCtypes); ok {
		l.DefaultTktEnctypes = splitETypeList(v)
	}

	if v, ok := p.value(ConfigSectionLibDefaults, ConfigKeyDefaultTGSENCtypes); ok {
		l.DefaultTGSEnctypes = splitETypeList(v)
	}

	l.resolveETypes()

	return nil
}

func dnsLookup(p *profile, key string, def bool) bool {
	v, ok := p.value(ConfigSectionLibDefaults, key)
	if !ok {
		if v, ok = p.value(ConfigSectionLibDefaults, ConfigKeyDNSFallback); !ok {
			return def
		}
	}

	b, err := parseBoolean(v)

	return err == nil && b
}

// LibDefaultsForRealm returns the [libdefaults] settings that apply to a client principal of the realm. MIT krb5
// reads canonicalize, forwardable, noaddresses, preferred_preauth_types, proxiable, renew_lifetime, ticket_lifetime
// and verify_ap_req_nofail from a subsection of [libdefaults] named after the realm before the section itself.
func (c *Config) LibDefaultsForRealm(realm string) LibDefaults {
	if l, ok := c.realmLibDefaults[realm]; ok {
		return l
	}

	return c.LibDefaults
}

// Realm represents an entry in the [realms] section of the configuration. Currently the specific known options not
// implemented are auth_to_local and auth_to_local_names.
type Realm struct {
	Realm string

	AdminServer []string

	DefaultDomain string

	// KDC lists the KDCs as host:port, with the port defaulting to 88. An IPv6 address is enclosed in brackets.
	KDC []string

	// KPasswdServer lists the kpasswd servers as host:port, with the port defaulting to 464. Where the realm lists
	// none it holds port 464 of each admin_server.
	KPasswdServer []string

	// MasterKDC lists the primary KDCs, read from primary_kdc or, where that is not set, master_kdc.
	MasterKDC []string

	kpasswdFromAdmin bool
}

const (
	portKDC     = 88
	portKpasswd = 464
)

func loadRealm(p *profile, name string) (Realm, error) {
	r := Realm{Realm: name}

	values := func(key string) []string {
		return p.values(ConfigSectionRealms, name, key)
	}

	r.AdminServer = values(ConfigKeyAdminServer)

	if v := values(ConfigKeyDefaultDomain); len(v) > 0 {
		r.DefaultDomain = v[0]
	}

	for _, v := range values(ConfigKeyKDC) {
		hp, err := hostPort(v, portKDC)
		if err != nil {
			return r, InvalidErrorf("realm %s kdc (%s): %v", name, v, err)
		}

		r.KDC = append(r.KDC, hp)
	}

	for _, v := range values(ConfigKeyKPasswdServer) {
		hp, err := hostPort(v, portKpasswd)
		if err != nil {
			return r, InvalidErrorf("realm %s kpasswd_server (%s): %v", name, v, err)
		}

		r.KPasswdServer = append(r.KPasswdServer, hp)
	}

	if len(r.KPasswdServer) == 0 {
		for _, v := range r.AdminServer {
			host, _, err := splitHostPort(v)
			if err != nil || host == "" {
				continue
			}

			r.KPasswdServer = append(r.KPasswdServer, net.JoinHostPort(host, strconv.Itoa(portKpasswd)))
			r.kpasswdFromAdmin = true
		}
	}

	if r.MasterKDC = values(ConfigKeyPrimaryKDC); len(r.MasterKDC) == 0 {
		r.MasterKDC = values(ConfigKeyMasterKDC)
	}

	return r, nil
}

func unsupportedRealmDirective(p *profile, name string) error {
	for _, tag := range append(p.relations(ConfigSectionRealms, name), p.subsections(ConfigSectionRealms, name)...) {
		switch {
		case strings.HasPrefix(tag, "v4_"):
			return UnsupportedDirective{"v4 configurations are not supported"}
		case tag == "auth_to_local_names":
			return UnsupportedDirective{"auth_to_local_names are not supported"}
		}
	}

	return nil
}

func hostPort(v string, port int) (string, error) {
	if strings.Contains(v, "://") || strings.HasPrefix(v, "/") {
		return v, nil
	}

	host, p, err := splitHostPort(v)
	if err != nil {
		return "", err
	}

	if host == "" {
		return "", errors.New("no host")
	}

	if p < 0 {
		p = port
	}

	return net.JoinHostPort(host, strconv.Itoa(p)), nil
}

func splitHostPort(v string) (string, int, error) {
	if v == "" || v[0] == ':' {
		return "", 0, errors.New("no host")
	}

	var host, port string

	hasPort := false

	switch {
	case strings.Trim(v, "0123456789") == "":
		port, hasPort = v, true
	case v[0] == '[' && strings.IndexByte(v, ']') > 0:
		end := strings.IndexByte(v, ']')
		host = v[1:end]

		if rest := v[end+1:]; strings.HasPrefix(rest, ":") {
			port, hasPort = rest[1:], true
		}
	default:
		end := strings.IndexAny(v, " \t:")
		if end < 0 {
			end = len(v)
		}

		host = v[:end]

		if end < len(v) && v[end] == ':' {
			port, hasPort = v[end+1:], true
		}
	}

	if !hasPort {
		return host, -1, nil
	}

	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q", port)
	}

	return host, int(p), nil
}

// DomainRealm maps the domains to realms representing the [domain_realm] section of the configuration.
type DomainRealm map[string]string

// ResolveRealm resolves the kerberos realm for the specified domain name from the domain to realm mapping, as MIT
// krb5 does: the host itself is tried first, then each parent domain, first as a subdomain mapping with a leading
// period and then as a mapping of the domain and everything below it. A host given as an IP address is not mapped.
func (c *Config) ResolveRealm(domainName string) string {
	host := strings.ToLower(strings.TrimSuffix(domainName, "."))

	if net.ParseIP(host) != nil {
		return ""
	}

	for p := host; p != ""; {
		if r, ok := c.DomainRealm[p]; ok {
			return r
		}

		if p[0] == '.' {
			p = p[1:]

			continue
		}

		i := strings.IndexByte(p, '.')
		if i < 0 {
			break
		}

		p = p[i:]
	}

	return ""
}

// CCacheName returns the name of the default credential cache as MIT krb5 resolves it: the KRB5CCNAME environment
// variable, then default_ccache_name, then FILE:/tmp/krb5cc_%{uid}.
func (c *Config) CCacheName() string {
	if v, ok := os.LookupEnv("KRB5CCNAME"); ok {
		return v
	}

	return c.LibDefaults.DefaultCCacheName
}

// KeytabName returns the name of the default keytab as MIT krb5 resolves it: the KRB5_KTNAME environment variable,
// then default_keytab_name.
func (c *Config) KeytabName() string {
	if v, ok := os.LookupEnv("KRB5_KTNAME"); ok {
		return v
	}

	return c.LibDefaults.DefaultKeytabName
}

// ClientKeytabName returns the name of the default client keytab as MIT krb5 resolves it: the KRB5_CLIENT_KTNAME
// environment variable, then default_client_keytab_name.
func (c *Config) ClientKeytabName() string {
	if v, ok := os.LookupEnv("KRB5_CLIENT_KTNAME"); ok {
		return v
	}

	return c.LibDefaults.DefaultClientKeytabName
}

// Load the KRB5 configuration from the specified file path. A directory is read as an includedir directive reads
// it.
func Load(cfgPath string) (*Config, error) {
	root, err := readProfilePath(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("configuration file could not be opened: %s %w", cfgPath, err)
	}

	return newFromProfile(&profile{files: []*profileNode{root}})
}

// DefaultPaths returns the files MIT krb5 reads its configuration from: those listed in the KRB5_CONFIG environment
// variable, or where it is not set /etc/krb5.conf, preceded on macOS by the edu.mit.Kerberos preference files.
func DefaultPaths() []string {
	if v, ok := os.LookupEnv("KRB5_CONFIG"); ok {
		return filepath.SplitList(v)
	}

	if runtime.GOOS == "darwin" {
		return []string{"~/Library/Preferences/edu.mit.Kerberos", "/Library/Preferences/edu.mit.Kerberos", defaultConfigPath}
	}

	return []string{defaultConfigPath}
}

// LoadDefault loads the configuration from the files DefaultPaths returns, as MIT krb5 does: each file or directory
// that exists is read, those that are missing are skipped, and the files are consulted in order, so the first one to
// set a relation that takes a single value decides it. It is an error for none of them to exist.
func LoadDefault() (*Config, error) {
	return LoadFiles(DefaultPaths()...)
}

// LoadFiles loads the configuration from several files as LoadDefault does.
func LoadFiles(paths ...string) (*Config, error) {
	p := &profile{}

	var denied error

	for _, name := range paths {
		if rest, ok := strings.CutPrefix(name, "~/"); ok {
			home, err := os.UserHomeDir()
			if err != nil {
				continue
			}

			name = filepath.Join(home, rest)
		}

		root, err := readProfilePath(name)

		switch {
		case err == nil:
			p.files = append(p.files, root)
		case errors.Is(err, os.ErrNotExist):
			continue
		case errors.Is(err, os.ErrPermission):
			denied = fmt.Errorf("configuration file could not be opened: %s %w", name, err)
		default:
			return nil, fmt.Errorf("configuration file could not be opened: %s %w", name, err)
		}
	}

	if len(p.files) == 0 {
		if denied != nil {
			return nil, denied
		}

		return nil, fmt.Errorf("no configuration file was found in %s", strings.Join(paths, string(filepath.ListSeparator)))
	}

	return newFromProfile(p)
}

// NewFromString creates a new Config struct from a string.
func NewFromString(s string) (*Config, error) {
	reader := strings.NewReader(s)
	return NewFromReader(reader)
}

// NewFromReader creates a new Config struct from an io.Reader.
func NewFromReader(r io.Reader) (*Config, error) {
	scanner := bufio.NewScanner(r)
	return NewFromScanner(scanner)
}

// NewFromScanner creates a new Config struct from a bufio.Scanner. Files named by include and includedir directives
// are read relative to the working directory.
func NewFromScanner(scanner *bufio.Scanner) (*Config, error) {
	root, err := readProfileScanner(scanner)
	if err != nil {
		return nil, err
	}

	return newFromProfile(&profile{files: []*profileNode{root}})
}

func newFromProfile(p *profile) (*Config, error) {
	c := New()

	if err := c.LibDefaults.load(p); err != nil {
		return nil, fmt.Errorf("error processing %s section: %w", ConfigSectionLibDefaults, err)
	}

	for _, realm := range p.subsections(ConfigSectionLibDefaults) {
		l := c.LibDefaults

		for _, key := range realmLibDefaultKeys {
			if v, ok := p.value(ConfigSectionLibDefaults, realm, key); ok {
				if err := l.set(key, v); err != nil {
					return nil, fmt.Errorf("error processing %s section: realm %s: %w", ConfigSectionLibDefaults, realm, err)
				}
			}
		}

		if c.realmLibDefaults == nil {
			c.realmLibDefaults = make(map[string]LibDefaults)
		}

		c.realmLibDefaults[realm] = l
	}

	var unsupported error

	for _, name := range p.subsections(ConfigSectionRealms) {
		r, err := loadRealm(p, name)
		if err != nil {
			return nil, fmt.Errorf("error processing %s section: %w", ConfigSectionRealms, err)
		}

		if e := unsupportedRealmDirective(p, name); e != nil {
			unsupported = e
		}

		c.Realms = append(c.Realms, r)
	}

	for _, domain := range p.relations(ConfigSectionDomainRealm) {
		key := strings.ToLower(domain)
		if _, ok := c.DomainRealm[key]; ok {
			continue
		}

		if v, ok := p.value(ConfigSectionDomainRealm, domain); ok {
			c.DomainRealm[key] = v
		}
	}

	return c, unsupported
}

// JSON marshalls the config using the encoding/json package.
func (c *Config) JSON() (string, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func parseBoolean(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "y", "yes", "true", "t", "1", "on":
		return true, nil
	case "n", "no", "false", "nil", "0", "off":
		return false, nil
	default:
		return false, errors.New("invalid boolean value")
	}
}

func parseInteger(s string) (int, error) {
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, errors.New("invalid integer value")
	}

	return int(v), nil
}

func parseKDCOptions(s string) (uint32, error) {
	if h, ok := strings.CutPrefix(strings.ToLower(s), "0x"); ok {
		v, err := strconv.ParseUint(h, 16, 32)
		if err != nil {
			return 0, errors.New("invalid integer value")
		}

		return uint32(v), nil
	}

	v, err := parseInteger(s)
	if err != nil {
		return 0, err
	}

	return uint32(v), nil //nolint:gosec // G115: the options are a 32 bit field, which a negative value sets the high bit of.
}

func parsePreauthTypes(s string) ([]int, error) {
	var v []int

	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		i, err := strconv.ParseInt(f, 10, 32)
		if err != nil {
			return nil, err
		}

		v = append(v, int(i))
	}

	if len(v) == 0 {
		return nil, errors.New("no pre-authentication types")
	}

	return v, nil
}
