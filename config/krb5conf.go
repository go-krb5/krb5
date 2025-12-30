// Package config implements KRB5 client and service configuration as described at https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html
package config

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/iana/etypeID"
)

// Config represents the KRB5 configuration.
type Config struct {
	LibDefaults LibDefaults
	Realms      []Realm
	DomainRealm DomainRealm
	// CaPaths.
	// AppDefaults.
	// Plugins.
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

// LibDefaults represents the [libdefaults] section of the configuration.
// The following values are not implemented: ap_req_checksum_type int, kdc_req_checksum_type int, plugin_base_dir string.
type LibDefaults struct {
	// AllowWeakCrypto has a default value of false.
	AllowWeakCrypto bool

	// Canonicalize has a default value of false.
	Canonicalize bool

	// CCacheType has a default value of 4.
	CCacheType int

	// Clockskew is the max allowed skew in seconds and has a default value of 300.
	Clockskew time.Duration

	// DefaultClientKeytabName has a default vakue of /usr/local/var/krb5/user/%{euid}/client.keytab.
	DefaultClientKeytabName string

	// DefaultKeytabName has a default value of /etc/krb5.keytab.
	DefaultKeytabName string

	DefaultRealm string

	// DefaultTGSEnctypes has a default value of
	// aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
	// des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4.
	DefaultTGSEnctypes []string

	// DefaultTktEnctypes has a default value of
	// aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des3-cbc-sha1
	// arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4.
	DefaultTktEnctypes []string

	// DefaultTGSEnctypeIDs has a default value of
	// aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des3-cbc-sha1
	// arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4.
	DefaultTGSEnctypeIDs []int32

	// DefaultTktEnctypeIDs has a default value of
	// aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
	// des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4.
	DefaultTktEnctypeIDs []int32

	// DNSCanonicalizeHostname has a default value of true.
	DNSCanonicalizeHostname bool

	// DNSLookupKDC has a default value of false.
	DNSLookupKDC bool

	DNSLookupRealm bool

	ExtraAddresses []net.IP

	// Forwardable has a default value of false.
	Forwardable bool

	// IgnoreAcceptorHostname has a default value of false.
	IgnoreAcceptorHostname bool

	// K5LoginAuthoritative has a default value of false.
	K5LoginAuthoritative bool

	// K5LoginDirectory has a default value based on the user's home directory. Must be owned by the user or root.
	K5LoginDirectory string

	// KDCDefaultOptions has a default value of 0x00000010 (KDC_OPT_RENEWABLE_OK).
	KDCDefaultOptions asn1.BitString

	// KDCTimeSync has a default value of 1.
	KDCTimeSync int

	// NoAddresses has a default value of true.
	NoAddresses bool

	// PermittedEnctypes has a default value of
	// aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
	// des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4.
	PermittedEnctypes []string

	PermittedEnctypeIDs []int32

	// PreferredPreauthTypes has a defaultb value of 17, 16, 15, 14; which forces an attempt to use PKINIT if it is
	// supported.
	PreferredPreauthTypes []int

	// Proxiable has a default value of false.
	Proxiable bool

	// RDNS has a default value of true.
	RDNS bool

	// RealmTryDomains has a default value of -1.
	RealmTryDomains int

	// RenewLifetime has a default value of 0.
	RenewLifetime time.Duration

	// SafeChecksumType has a default value of 8.
	SafeChecksumType int

	// TicketLifetime has a default value of 1 day.
	TicketLifetime time.Duration

	// UDPPreferenceLimit determines if UDP is used, 1 means to always use tcp. Must be less than 32700, and has a
	// default value of 1465.
	UDPPreferenceLimit int

	// VerifyAPReqNofail has a default value of false.
	VerifyAPReqNofail bool
}

// Create a new LibDefaults struct.
func newLibDefaults() LibDefaults {
	uid := "0"

	var hdir string

	usr, _ := user.Current()
	if usr != nil {
		uid = usr.Uid
		hdir = usr.HomeDir
	}

	opts := asn1.BitString{}
	opts.Bytes, _ = hex.DecodeString("00000010")
	opts.BitLength = len(opts.Bytes) * 8
	l := LibDefaults{
		CCacheType:              4,
		Clockskew:               time.Duration(300) * time.Second,
		DefaultClientKeytabName: fmt.Sprintf("/usr/local/var/krb5/user/%s/client.keytab", uid),
		DefaultKeytabName:       "/etc/krb5.keytab",
		DefaultTGSEnctypes:      []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des3-cbc-sha1", "arcfour-hmac-md5", "camellia256-cts-cmac", "camellia128-cts-cmac", "des-cbc-crc", "des-cbc-md5", "des-cbc-md4"},
		DefaultTktEnctypes:      []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des3-cbc-sha1", "arcfour-hmac-md5", "camellia256-cts-cmac", "camellia128-cts-cmac", "des-cbc-crc", "des-cbc-md5", "des-cbc-md4"},
		DNSCanonicalizeHostname: true,
		K5LoginDirectory:        hdir,
		KDCDefaultOptions:       opts,
		KDCTimeSync:             1,
		NoAddresses:             true,
		PermittedEnctypes:       []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des3-cbc-sha1", "arcfour-hmac-md5", "camellia256-cts-cmac", "camellia128-cts-cmac", "des-cbc-crc", "des-cbc-md5", "des-cbc-md4"},
		RDNS:                    true,
		RealmTryDomains:         -1,
		SafeChecksumType:        8,
		TicketLifetime:          time.Duration(24) * time.Hour,
		UDPPreferenceLimit:      1465,
		PreferredPreauthTypes:   []int{17, 16, 15, 14},
	}
	l.DefaultTGSEnctypeIDs = parseETypes(l.DefaultTGSEnctypes, l.AllowWeakCrypto)
	l.DefaultTktEnctypeIDs = parseETypes(l.DefaultTktEnctypes, l.AllowWeakCrypto)
	l.PermittedEnctypeIDs = parseETypes(l.PermittedEnctypes, l.AllowWeakCrypto)

	return l
}

// Parse the lines of the libdefaults section of the configuration into the LibDefaults struct.
func (l *LibDefaults) parseLines(lines []string) error {
	for _, line := range lines {
		if idx := strings.IndexAny(line, "#;"); idx != -1 {
			line = line[:idx]
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if !strings.Contains(line, "=") {
			return InvalidErrorf("libdefaults section line (%s)", line)
		}

		p := strings.Split(line, "=")

		key := strings.TrimSpace(strings.ToLower(p[0]))
		switch key {
		case ConfigKeyAllowWeakCrypto:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.AllowWeakCrypto = v
		case ConfigKeyCanonicalize:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.Canonicalize = v
		case ConfigKeyCredentialCacheType:
			p[1] = strings.TrimSpace(p[1])

			v, err := strconv.ParseUint(p[1], 10, 32)
			if err != nil || v <= 0 || v > 4 {
				return InvalidErrorf("libdefaults section line (%s)", line)
			}

			l.CCacheType = int(v)
		case ConfigKeyClockSkew:
			d, err := parseDuration(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.Clockskew = d
		case ConfigKeyDefaultClientKeytabName:
			l.DefaultClientKeytabName = strings.TrimSpace(p[1])
		case ConfigKeyDefaultKeytabName:
			l.DefaultKeytabName = strings.TrimSpace(p[1])
		case ConfigKeyDefaultRealm:
			l.DefaultRealm = strings.TrimSpace(p[1])
		case ConfigKeyDefaultTGSENCtypes:
			l.DefaultTGSEnctypes = strings.Fields(p[1])
		case ConfigKeyDefaultTKTENCtypes:
			l.DefaultTktEnctypes = strings.Fields(p[1])
		case ConfigKeyDNSCanonicalizeHostname:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.DNSCanonicalizeHostname = v
		case ConfigKeyDNSLookupKDC:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.DNSLookupKDC = v
		case ConfigKeyDNSLookupRealm:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.DNSLookupRealm = v
		case ConfigKeyExtraAddresses:
			ipStr := strings.TrimSpace(p[1])
			for _, ip := range strings.Split(ipStr, ",") {
				if eip := net.ParseIP(ip); eip != nil {
					l.ExtraAddresses = append(l.ExtraAddresses, eip)
				}
			}
		case ConfigKeyForwardable:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.Forwardable = v
		case ConfigKeyIgnoreAcceptorHostname:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.IgnoreAcceptorHostname = v
		case ConfigKeyK5LoginAuthorative:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.K5LoginAuthoritative = v
		case ConfigKeyK5LoginDirectory:
			l.K5LoginDirectory = strings.TrimSpace(p[1])
		case ConfigKeyKDCDefaultOptions:
			v := strings.TrimSpace(p[1])
			v = strings.ReplaceAll(v, "0x", "")

			b, err := hex.DecodeString(v)
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.KDCDefaultOptions.Bytes = b
			l.KDCDefaultOptions.BitLength = len(b) * 8
		case ConfigKeyKDCTimeSync:
			p[1] = strings.TrimSpace(p[1])

			v, err := strconv.ParseInt(p[1], 10, 32)
			if err != nil || v < 0 {
				return InvalidErrorf("libdefaults section line (%s)", line)
			}

			l.KDCTimeSync = int(v)
		case ConfigKeyNoAddresses:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.NoAddresses = v
		case ConfigKeyPermittedEncTypes:
			l.PermittedEnctypes = strings.Fields(p[1])
		case ConfigKeyPreferredPreAuthTypes:
			p[1] = strings.TrimSpace(p[1])
			t := strings.Split(p[1], ",")

			var v []int

			for _, s := range t {
				i, err := strconv.ParseInt(s, 10, 32)
				if err != nil {
					return InvalidErrorf("libdefaults section line (%s): %v", line, err)
				}

				v = append(v, int(i))
			}

			l.PreferredPreauthTypes = v
		case ConfigKeyProxiable:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.Proxiable = v
		case ConfigKeyRDNS:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.RDNS = v
		case ConfigKeyRealmTryDomains:
			p[1] = strings.TrimSpace(p[1])

			v, err := strconv.ParseInt(p[1], 10, 32)
			if err != nil || v < -1 {
				return InvalidErrorf("libdefaults section line (%s)", line)
			}

			l.RealmTryDomains = int(v)
		case ConfigKeyRenewLifetime:
			d, err := parseDuration(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.RenewLifetime = d
		case ConfigKeySafeChecksumType:
			p[1] = strings.TrimSpace(p[1])

			v, err := strconv.ParseInt(p[1], 10, 32)
			if err != nil || v < 0 {
				return InvalidErrorf("libdefaults section line (%s)", line)
			}

			l.SafeChecksumType = int(v)
		case ConfigKeyTicketLifetime:
			d, err := parseDuration(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.TicketLifetime = d
		case ConfigKeyUDPPreferenceLimit:
			p[1] = strings.TrimSpace(p[1])

			v, err := strconv.ParseUint(p[1], 10, 32)
			if err != nil || v > 32700 {
				return InvalidErrorf("libdefaults section line (%s)", line)
			}

			l.UDPPreferenceLimit = int(v)
		case ConfigKeyVerifyAPReqNoFail:
			v, err := parseBoolean(p[1])
			if err != nil {
				return InvalidErrorf("libdefaults section line (%s): %v", line, err)
			}

			l.VerifyAPReqNofail = v
		}
	}

	l.DefaultTGSEnctypeIDs = parseETypes(l.DefaultTGSEnctypes, l.AllowWeakCrypto)
	l.DefaultTktEnctypeIDs = parseETypes(l.DefaultTktEnctypes, l.AllowWeakCrypto)
	l.PermittedEnctypeIDs = parseETypes(l.PermittedEnctypes, l.AllowWeakCrypto)

	return nil
}

// Realm represents an entry in the [realms] section of the configuration. Currently the specific known options not
// implemented are auth_to_local and auth_to_local_names.
type Realm struct {
	Realm string

	AdminServer []string

	DefaultDomain string

	KDC []string

	// KPasswdServer has a default of 'admin_server:464'.
	KPasswdServer []string

	MasterKDC []string
}

// Parse the lines of a realms entry into the Realm struct.
func (r *Realm) parseLines(name string, lines []string) (err error) {
	r.Realm = name

	var (
		adminServerFinal   bool
		KDCFinal           bool
		kpasswdServerFinal bool
		masterKDCFinal     bool
		ignore             bool
	)

	var c int
	for _, line := range lines {
		if ignore && c > 0 && !strings.Contains(line, "{") && !strings.Contains(line, "}") {
			continue
		}

		if idx := strings.IndexAny(line, "#;"); idx != -1 {
			line = line[:idx]
		}

		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		if !strings.Contains(line, "=") && !strings.Contains(line, "}") {
			return InvalidErrorf("realms section line (%s)", line)
		}

		if strings.Contains(line, "v4_") {
			ignore = true
			err = UnsupportedDirective{"v4 configurations are not supported"}
		}

		if strings.Contains(line, "auth_to_local_names") {
			ignore = true
			err = UnsupportedDirective{"auth_to_local_names are not supported"}
		}

		if strings.Contains(line, "{") {
			c++

			if ignore {
				continue
			}
		}

		if strings.Contains(line, "}") {
			c--
			if c < 0 {
				return InvalidErrorf("unpaired curly brackets")
			}

			if ignore {
				if c < 1 {
					c = 0
					ignore = false
				}

				continue
			}
		}

		p := strings.Split(line, "=")
		key := strings.TrimSpace(strings.ToLower(p[0]))
		v := strings.TrimSpace(p[1])

		switch key {
		case ConfigKeyAdminServer:
			appendUntilFinal(&r.AdminServer, v, &adminServerFinal)
		case ConfigKeyDefaultDomain:
			r.DefaultDomain = v
		case ConfigKeyKDC:
			if !strings.Contains(v, ":") {
				if strings.HasSuffix(v, `*`) {
					v = strings.TrimSpace(strings.TrimSuffix(v, `*`)) + ":88*"
				} else {
					v = strings.TrimSpace(v) + ":88"
				}
			}

			appendUntilFinal(&r.KDC, v, &KDCFinal)
		case ConfigKeyKPasswdServer:
			appendUntilFinal(&r.KPasswdServer, v, &kpasswdServerFinal)
		case ConfigKeyMasterKDC:
			appendUntilFinal(&r.MasterKDC, v, &masterKDCFinal)
		}
	}

	if len(r.KPasswdServer) < 1 {
		for _, a := range r.AdminServer {
			s := strings.Split(a, ":")
			r.KPasswdServer = append(r.KPasswdServer, s[0]+":464")
		}
	}

	return
}

// Parse the lines of the [realms] section of the configuration into an slice of Realm structs.
func parseRealms(lines []string) (realms []Realm, err error) {
	var (
		name  string
		start int
		c     int
	)

	for i, l := range lines {
		if idx := strings.IndexAny(l, "#;"); idx != -1 {
			l = l[:idx]
		}

		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}

		if strings.Contains(l, "{") {
			c++

			if !strings.Contains(l, "=") {
				return nil, fmt.Errorf("realm configuration line invalid: %s", l)
			}

			if c == 1 {
				start = i
				p := strings.Split(l, "=")
				name = strings.TrimSpace(p[0])
			}
		}

		if strings.Contains(l, "}") {
			if c < 1 {
				// but not started a block!!!
				return nil, errors.New("invalid Realms section in configuration")
			}

			c--
			if c == 0 {
				var r Realm

				e := r.parseLines(name, lines[start+1:i])
				if e != nil {
					if _, ok := e.(UnsupportedDirective); !ok {
						err = e
						return
					}

					err = e
				}

				realms = append(realms, r)
			}
		}
	}

	return
}

// DomainRealm maps the domains to realms representing the [domain_realm] section of the configuration.
type DomainRealm map[string]string

// Parse the lines of the [domain_realm] section of the configuration and add to the mapping.
func (d *DomainRealm) parseLines(lines []string) error {
	for _, line := range lines {
		if idx := strings.IndexAny(line, "#;"); idx != -1 {
			line = line[:idx]
		}

		if strings.TrimSpace(line) == "" {
			continue
		}

		if !strings.Contains(line, "=") {
			return InvalidErrorf("realm line (%s)", line)
		}

		p := strings.Split(line, "=")
		domain := strings.TrimSpace(strings.ToLower(p[0]))
		realm := strings.TrimSpace(p[1])
		d.addMapping(domain, realm)
	}

	return nil
}

// Add a domain to realm mapping.
func (d *DomainRealm) addMapping(domain, realm string) {
	(*d)[domain] = realm
}

// Delete a domain to realm mapping.
func (d *DomainRealm) deleteMapping(domain, realm string) {
	delete(*d, domain)
}

// ResolveRealm resolves the kerberos realm for the specified domain name from the domain to realm mapping.
// The most specific mapping is returned.
func (c *Config) ResolveRealm(domainName string) string {
	domainName = strings.TrimSuffix(domainName, ".")

	// Try to match the entire hostname first.
	if r, ok := c.DomainRealm[domainName]; ok {
		return r
	}

	// Try to match all DNS domain parts.
	periods := strings.Count(domainName, ".") + 1
	for i := 2; i <= periods; i++ {
		z := strings.SplitN(domainName, ".", i)
		if r, ok := c.DomainRealm["."+z[len(z)-1]]; ok {
			return r
		}
	}

	return ""
}

// Load the KRB5 configuration from the specified file path.
func Load(cfgPath string) (*Config, error) {
	fh, err := os.Open(cfgPath)
	if err != nil {
		return nil, errors.New("configuration file could not be opened: " + cfgPath + " " + err.Error())
	}
	defer fh.Close()

	scanner := bufio.NewScanner(fh)

	return NewFromScanner(scanner)
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

// NewFromScanner creates a new Config struct from a bufio.Scanner.
func NewFromScanner(scanner *bufio.Scanner) (*Config, error) {
	c := New()

	var e error

	sections := make(map[int]string)

	var (
		sectionLineNum []int
		lines          []string
	)

	for scanner.Scan() {
		if reCommentsAndBlankLines.MatchString(scanner.Text()) {
			continue
		}

		if reLibDefaults.MatchString(scanner.Text()) {
			sections[len(lines)] = ConfigSectionLibDefaults
			sectionLineNum = append(sectionLineNum, len(lines))

			continue
		}

		if reRealms.MatchString(scanner.Text()) {
			sections[len(lines)] = ConfigSectionRealms
			sectionLineNum = append(sectionLineNum, len(lines))

			continue
		}

		if reDomainRealm.MatchString(scanner.Text()) {
			sections[len(lines)] = ConfigSectionDomainRealm
			sectionLineNum = append(sectionLineNum, len(lines))

			continue
		}

		if reUnknownSection.MatchString(scanner.Text()) {
			sections[len(lines)] = ConfigSectionUnknown
			sectionLineNum = append(sectionLineNum, len(lines))

			continue
		}

		lines = append(lines, scanner.Text())
	}

	for i, start := range sectionLineNum {
		var end int
		if i+1 >= len(sectionLineNum) {
			end = len(lines)
		} else {
			end = sectionLineNum[i+1]
		}

		switch section := sections[start]; section {
		case ConfigSectionLibDefaults:
			err := c.LibDefaults.parseLines(lines[start:end])
			if err != nil {
				if _, ok := err.(UnsupportedDirective); !ok {
					return nil, fmt.Errorf("error processing %s section: %w", section, err)
				}

				e = err
			}
		case ConfigSectionRealms:
			realms, err := parseRealms(lines[start:end])
			if err != nil {
				if _, ok := err.(UnsupportedDirective); !ok {
					return nil, fmt.Errorf("error processing %s section: %w", section, err)
				}

				e = err
			}

			c.Realms = realms
		case ConfigSectionDomainRealm:
			err := c.DomainRealm.parseLines(lines[start:end])
			if err != nil {
				if _, ok := err.(UnsupportedDirective); !ok {
					return nil, fmt.Errorf("error processing %s section: %w", section, err)
				}

				e = err
			}
		}
	}

	return c, e
}

// Parse a space delimited list of ETypes into a list of EType numbers optionally filtering out weak ETypes.
func parseETypes(s []string, w bool) []int32 {
	var eti []int32

	for _, et := range s {
		if !w {
			var weak bool

			for _, wet := range strings.Fields(WeakETypeList) {
				if et == wet {
					weak = true
					break
				}
			}

			if weak {
				continue
			}
		}

		i := etypeID.EtypeSupported(et)
		if i != 0 {
			eti = append(eti, i)
		}
	}

	return eti
}

// Parse a time duration string in the configuration to a golang time.Duration.
func parseDuration(s string) (time.Duration, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")

	if strings.Contains(s, timeUnitDays) {
		ds := strings.SplitN(s, timeUnitDays, 2)

		dn, err := strconv.ParseUint(ds[0], 10, 32)
		if err != nil {
			return time.Duration(0), errors.New("invalid time duration")
		}

		d := time.Hour * 24 * time.Duration(dn)

		if ds[1] != "" {
			dp, err := time.ParseDuration(ds[1])
			if err != nil {
				return time.Duration(0), errors.New("invalid time duration")
			}

			d += dp
		}

		return d, nil
	}

	d, err := time.ParseDuration(s)
	if err == nil {
		return d, nil
	}

	v, err := strconv.ParseUint(s, 10, 32)
	if err == nil && v > 0 {
		return time.Duration(v) * time.Second, nil
	}

	if strings.Contains(s, timeDelimiterColon) {
		t := strings.Split(s, timeDelimiterColon)
		if 2 > len(t) || len(t) > 3 {
			return time.Duration(0), errors.New("invalid time duration value")
		}

		var i []int

		for _, n := range t {
			j, err := strconv.ParseInt(n, 10, 16)
			if err != nil {
				return time.Duration(0), errors.New("invalid time duration value")
			}

			i = append(i, int(j))
		}

		d := time.Duration(i[0])*time.Hour + time.Duration(i[1])*time.Minute
		if len(i) == 3 {
			d += time.Duration(i[2]) * time.Second
		}

		return d, nil
	}

	return time.Duration(0), errors.New("invalid time duration value")
}

// Parse possible boolean values to golang bool.
func parseBoolean(s string) (bool, error) {
	s = strings.TrimSpace(s)

	v, err := strconv.ParseBool(s)
	if err == nil {
		return v, nil
	}

	switch strings.ToLower(s) {
	case "yes":
		return true, nil
	case "y":
		return true, nil
	case "no":
		return false, nil
	case "n":
		return false, nil
	}

	return false, errors.New("invalid boolean value")
}

// Parse array of strings but stop if an asterisk is placed at the end of a line.
func appendUntilFinal(s *[]string, value string, final *bool) {
	if *final {
		return
	}

	if last := len(value) - 1; last >= 0 && value[last] == '*' {
		*final = true
		value = value[:len(value)-1]
	}

	*s = append(*s, value)
}

// JSON marshalls the config using the encoding/json package.
func (c *Config) JSON() (string, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}
