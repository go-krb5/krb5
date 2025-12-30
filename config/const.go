package config

import "regexp"

var (
	reCommentsAndBlankLines = regexp.MustCompile(`^\s*[#;\n]`)
	reLibDefaults           = regexp.MustCompile(`^\s*\[libdefaults]\s*`)
	reRealms                = regexp.MustCompile(`^\s*\[realms]\s*`)
	reDomainRealm           = regexp.MustCompile(`^\s*\[domain_realm]\s*`)
	reUnknownSection        = regexp.MustCompile(`^\s*\[.*]\s*`)
)

const (
	ConfigKeyAllowWeakCrypto         = "allow_weak_crypto"
	ConfigKeyCanonicalize            = "canonicalize"
	ConfigKeyCredentialCacheType     = "ccache_type"
	ConfigKeyClockSkew               = "clock_skew"
	ConfigKeyDefaultClientKeytabName = "default_client_keytab_name"
	ConfigKeyDefaultKeytabName       = "default_keytab_name"
	ConfigKeyDefaultRealm            = "default_realm"
	ConfigKeyDefaultTGSENCtypes      = "default_tgs_enctypes"
	ConfigKeyDefaultTKTENCtypes      = "default_tkt_enctypes"
	ConfigKeyDNSCanonicalizeHostname = "dns_canonicalize_hostname"
	ConfigKeyDNSLookupKDC            = "dns_lookup_kdc"
	ConfigKeyDNSLookupRealm          = "dns_lookup_realm"
	ConfigKeyExtraAddresses          = "extra_addresses"
	ConfigKeyForwardable             = "forwardable"
	ConfigKeyIgnoreAcceptorHostname  = "ignore_acceptor_hostname"
	ConfigKeyK5LoginAuthorative      = "k5login_authoritative"
	ConfigKeyK5LoginDirectory        = "k5login_directory"
	ConfigKeyKDCDefaultOptions       = "kdc_default_options"
	ConfigKeyKDCTimeSync             = "kdc_timesync"
	ConfigKeyNoAddresses             = "noaddresses"
	ConfigKeyPermittedEncTypes       = "permitted_enctypes"
	ConfigKeyPreferredPreAuthTypes   = "preferred_preauth_types"
	ConfigKeyProxiable               = "proxiable"
	ConfigKeyRDNS                    = "rdns"
	ConfigKeyRealmTryDomains         = "realm_try_domains"
	ConfigKeyRenewLifetime           = "renew_lifetime"
	ConfigKeySafeChecksumType        = "safe_checksum_type"
	ConfigKeyTicketLifetime          = "ticket_lifetime"
	ConfigKeyUDPPreferenceLimit      = "udp_preference_limit"
	ConfigKeyVerifyAPReqNoFail       = "verify_ap_req_nofail"
	ConfigKeyAdminServer             = "admin_server"
	ConfigKeyDefaultDomain           = "default_domain"
	ConfigKeyKDC                     = "kdc"
	ConfigKeyKPasswdServer           = "kpasswd_server"
	ConfigKeyMasterKDC               = "master_kdc"
	ConfigSectionLibDefaults         = "libdefaults"
	ConfigSectionRealms              = "realms"
	ConfigSectionDomainRealm         = "domain_realm"
	ConfigSectionUnknown             = "unknown_section"
)

const (
	timeUnitDays       = "d"
	timeDelimiterColon = ":"
)

const (
	protoUDP = "udp"
	protoTCP = "tcp"

	svcKerberos         = "kerberos"
	svcKerberosAdmin    = "kerberos-adm"
	svcKerberosPassword = "kpasswd"
)
