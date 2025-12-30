package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	krb5Conf = `
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
 kdc = FILE:/var/log/kerberos/krb5kdc.log
 admin_server = FILE:/var/log/kerberos/kadmind.log

[libdefaults]
 default_realm = TEST.GOKRB5 ; comment to be ignored
 dns_lookup_realm = false

 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
#dns_lookup_kdc = true
;dns_lookup_kdc = true
 ticket_lifetime = 10h ;comment to be ignored
 forwardable = yes #comment to be ignored
 default_keytab_name = FILE:/etc/krb5.keytab

 default_client_keytab_name = FILE:/home/krb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 # comment to be ignored


[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88 #comment to be ignored
  kdc = assume.port.num ;comment to be ignored
  kdc = some.other.port:1234 # comment to be ignored

  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88

  admin_server = 10.80.88.88:749 ; comment to be ignored
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
 }
 lowercase.org = {
  kdc = kerberos.lowercase.org
  admin_server = kerberos.lowercase.org
 }


[domain_realm]
 .test.gokrb5 = TEST.GOKRB5 #comment to be ignored

 test.gokrb5 = TEST.GOKRB5 ;comment to be ignored

  .example.com = EXAMPLE.COM # comment to be ignored
 hostname1.example.com = EXAMPLE.COM ; comment to be ignored
 hostname2.example.com = TEST.GOKRB5
 .testlowercase.org = lowercase.org


[appdefaults]
 pam = {
   debug = false

   ticket_lifetime = 36000

   renew_lifetime = 36000
   forwardable = true
   krb4_convert = false
 }
`
	krb5ConfJson = `{
  "LibDefaults": {
    "AllowWeakCrypto": false,
    "Canonicalize": false,
    "CCacheType": 4,
    "Clockskew": 300000000000,
    "DefaultClientKeytabName": "FILE:/home/krb5/client.keytab",
    "DefaultKeytabName": "FILE:/etc/krb5.keytab",
    "DefaultRealm": "TEST.GOKRB5",
    "DefaultTGSEnctypes": [
      "aes256-cts-hmac-sha1-96",
      "aes128-cts-hmac-sha1-96",
      "des3-cbc-sha1",
      "arcfour-hmac-md5",
      "camellia256-cts-cmac",
      "camellia128-cts-cmac",
      "des-cbc-crc",
      "des-cbc-md5",
      "des-cbc-md4"
    ],
    "DefaultTktEnctypes": [
      "aes256-cts-hmac-sha1-96",
      "aes128-cts-hmac-sha1-96"
    ],
    "DefaultTGSEnctypeIDs": [
      18,
      17,
      23
    ],
    "DefaultTktEnctypeIDs": [
      18,
      17
    ],
    "DNSCanonicalizeHostname": true,
    "DNSLookupKDC": false,
    "DNSLookupRealm": false,
    "ExtraAddresses": null,
    "Forwardable": true,
    "IgnoreAcceptorHostname": false,
    "K5LoginAuthoritative": false,
    "K5LoginDirectory": "/home/test",
    "KDCDefaultOptions": {
      "Bytes": "AAAAEA==",
      "BitLength": 32
    },
    "KDCTimeSync": 1,
    "NoAddresses": true,
    "PermittedEnctypes": [
      "aes256-cts-hmac-sha1-96",
      "aes128-cts-hmac-sha1-96",
      "des3-cbc-sha1",
      "arcfour-hmac-md5",
      "camellia256-cts-cmac",
      "camellia128-cts-cmac",
      "des-cbc-crc",
      "des-cbc-md5",
      "des-cbc-md4"
    ],
    "PermittedEnctypeIDs": [
      18,
      17,
      23
    ],
    "PreferredPreauthTypes": [
      17,
      16,
      15,
      14
    ],
    "Proxiable": false,
    "RDNS": true,
    "RealmTryDomains": -1,
    "RenewLifetime": 0,
    "SafeChecksumType": 8,
    "TicketLifetime": 36000000000000,
    "UDPPreferenceLimit": 1465,
    "VerifyAPReqNofail": false
  },
  "Realms": [
    {
      "Realm": "TEST.GOKRB5",
      "AdminServer": [
        "10.80.88.88:749"
      ],
      "DefaultDomain": "test.gokrb5",
      "KDC": [
        "10.80.88.88:88",
        "assume.port.num:88",
        "some.other.port:1234",
        "10.80.88.88:88"
      ],
      "KPasswdServer": [
        "10.80.88.88:464"
      ],
      "MasterKDC": null
    },
    {
      "Realm": "EXAMPLE.COM",
      "AdminServer": [
        "kerberos.example.com"
      ],
      "DefaultDomain": "",
      "KDC": [
        "kerberos.example.com:88",
        "kerberos-1.example.com:88"
      ],
      "KPasswdServer": [
        "kerberos.example.com:464"
      ],
      "MasterKDC": null
    },
    {
      "Realm": "lowercase.org",
      "AdminServer": [
        "kerberos.lowercase.org"
      ],
      "DefaultDomain": "",
      "KDC": [
        "kerberos.lowercase.org:88"
      ],
      "KPasswdServer": [
        "kerberos.lowercase.org:464"
      ],
      "MasterKDC": null
    }
  ],
  "DomainRealm": {
    ".example.com": "EXAMPLE.COM",
    ".test.gokrb5": "TEST.GOKRB5",
    ".testlowercase.org": "lowercase.org",
    "hostname1.example.com": "EXAMPLE.COM",
    "hostname2.example.com": "TEST.GOKRB5",
    "test.gokrb5": "TEST.GOKRB5"
  }
}`
	krb5Conf2 = `
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
 kdc = FILE:/var/log/kerberos/krb5kdc.log
 admin_server = FILE:/var/log/kerberos/kadmind.log

[libdefaults]
 noaddresses = true
 default_realm = TEST.GOKRB5
 dns_lookup_realm = false

 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
#dns_lookup_kdc = true
;dns_lookup_kdc = true
 ticket_lifetime = 10h
 forwardable = yes
 default_keytab_name = FILE:/etc/krb5.keytab

 default_client_keytab_name = FILE:/home/krb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5

 test.gokrb5 = TEST.GOKRB5

[appdefaults]
 pam = {
   debug = false

   ticket_lifetime = 36000

   renew_lifetime = 36000
   forwardable = true
   krb4_convert = false
 }
 [realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  kdc = assume.port.num
  kdc = some.other.port:1234

  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88

  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
 }
`
	krb5ConfNoBlankLines = `
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
 kdc = FILE:/var/log/kerberos/krb5kdc.log
 admin_server = FILE:/var/log/kerberos/kadmind.log
[libdefaults]
 default_realm = TEST.GOKRB5
 dns_lookup_realm = false
 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
#dns_lookup_kdc = true
;dns_lookup_kdc = true
 ticket_lifetime = 10h
 forwardable = yes
 default_keytab_name = FILE:/etc/krb5.keytab
 default_client_keytab_name = FILE:/home/krb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  kdc = assume.port.num
  kdc = some.other.port:1234
  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88
  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
 }
[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
`
	krb5ConfTabs = `
[logging]
	default = FILE:/var/log/kerberos/krb5libs.log
	kdc = FILE:/var/log/kerberos/krb5kdc.log
	admin_server = FILE:/var/log/kerberos/kadmind.log

[libdefaults]
	default_realm = TEST.GOKRB5
	dns_lookup_realm = false

	dns_lookup_kdc = false
	#dns_lookup_kdc = true
	;dns_lookup_kdc = true
	#dns_lookup_kdc = true
	;dns_lookup_kdc = true
	ticket_lifetime = 10h
	forwardable = yes
	default_keytab_name = FILE:/etc/krb5.keytab

	default_client_keytab_name = FILE:/home/krb5/client.keytab
	default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96


[realms]
	TEST.GOKRB5 = {
		kdc = 10.80.88.88:88
		kdc = assume.port.num
		kdc = some.other.port:1234

		kdc = 10.80.88.88*
		kdc = 10.1.2.3.4:88

		admin_server = 10.80.88.88:749
		default_domain = test.gokrb5
	}
	EXAMPLE.COM = {
		kdc = kerberos.example.com
		kdc = kerberos-1.example.com
		admin_server = kerberos.example.com
		auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
	}


[domain_realm]
	.test.gokrb5 = TEST.GOKRB5

	test.gokrb5 = TEST.GOKRB5

	.example.com = EXAMPLE.COM
	hostname1.example.com = EXAMPLE.COM
	hostname2.example.com = TEST.GOKRB5


[appdefaults]
	pam = {
	debug = false

	ticket_lifetime = 36000

	renew_lifetime = 36000
	forwardable = true
	krb4_convert = false
}`

	krb5ConfV4Lines = `
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
 kdc = FILE:/var/log/kerberos/krb5kdc.log
 admin_server = FILE:/var/log/kerberos/kadmind.log

[libdefaults]
 default_realm = TEST.GOKRB5
 dns_lookup_realm = false

 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
#dns_lookup_kdc = true
;dns_lookup_kdc = true
 ticket_lifetime = 10h
 forwardable = yes
 default_keytab_name = FILE:/etc/krb5.keytab

 default_client_keytab_name = FILE:/home/krb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96


[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  kdc = assume.port.num
  kdc = some.other.port:1234

  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88

  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
    v4_name_convert = {
     host = {
        rcmd = host
     }
   }
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
 }


[domain_realm]
 .test.gokrb5 = TEST.GOKRB5

 test.gokrb5 = TEST.GOKRB5

  .example.com = EXAMPLE.COM
 hostname1.example.com = EXAMPLE.COM
 hostname2.example.com = TEST.GOKRB5


[appdefaults]
 pam = {
   debug = false

   ticket_lifetime = 36000

   renew_lifetime = 36000
   forwardable = true
   krb4_convert = false
 }
`
)

func TestLoad(t *testing.T) {
	t.Parallel()

	cf, _ := os.CreateTemp(os.TempDir(), "TEST-krb5-krb5.conf")
	defer os.Remove(cf.Name())

	_, err := cf.WriteString(krb5Conf)
	require.NoError(t, err)

	c, err := Load(cf.Name())
	require.NoError(t, err)

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm)
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC)
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime)
	assert.Equal(t, true, c.LibDefaults.Forwardable)
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName)
	assert.Equal(t, "FILE:/home/krb5/client.keytab", c.LibDefaults.DefaultClientKeytabName)
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes)

	assert.Equal(t, 3, len(c.Realms))
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm)
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer)
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer)
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain)
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC)
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC)
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer)

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"])
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"])
}

func TestLoadWithV4Lines(t *testing.T) {
	t.Parallel()

	cf, _ := os.CreateTemp(os.TempDir(), "TEST-krb5-krb5.conf")
	defer os.Remove(cf.Name())

	_, err := cf.WriteString(krb5ConfV4Lines)
	require.NoError(t, err)

	c, err := Load(cf.Name())
	require.EqualError(t, err, "v4 configurations are not supported")

	if _, ok := err.(UnsupportedDirective); !ok {
		t.Fatalf("error should be of type UnsupportedDirective: %v", err)
	}

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm)
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC)
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime)
	assert.Equal(t, true, c.LibDefaults.Forwardable)
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName)
	assert.Equal(t, "FILE:/home/krb5/client.keytab", c.LibDefaults.DefaultClientKeytabName)
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes)

	assert.Equal(t, 2, len(c.Realms))
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm)
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer)
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer)
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain)
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC)
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC)
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer)

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"])
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"])
}

func TestLoad2(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(krb5Conf2)
	require.NoError(t, err)

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm)
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC)
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime)
	assert.Equal(t, true, c.LibDefaults.Forwardable)
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName)
	assert.Equal(t, "FILE:/home/krb5/client.keytab", c.LibDefaults.DefaultClientKeytabName)
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes)

	assert.Equal(t, 2, len(c.Realms))
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm)
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer)
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer)
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain)
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC)
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC)
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer)

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"])
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"])
	assert.True(t, c.LibDefaults.NoAddresses)
}

func TestLoadNoBlankLines(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(krb5ConfNoBlankLines)
	require.NoError(t, err)

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm)
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC)
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime)
	assert.Equal(t, true, c.LibDefaults.Forwardable)
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName)
	assert.Equal(t, "FILE:/home/krb5/client.keytab", c.LibDefaults.DefaultClientKeytabName)
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes)

	assert.Equal(t, 2, len(c.Realms))
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm)
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer)
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer)
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain)
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC)
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC)
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer)

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"])
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"])
}

func TestLoadTabs(t *testing.T) {
	t.Parallel()

	cf, _ := os.CreateTemp(os.TempDir(), "TEST-krb5-krb5.conf")
	defer os.Remove(cf.Name())

	_, err := cf.WriteString(krb5ConfTabs)
	require.NoError(t, err)

	c, err := Load(cf.Name())
	require.NoError(t, err)

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm)
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC)
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime)
	assert.Equal(t, true, c.LibDefaults.Forwardable)
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName)
	assert.Equal(t, "FILE:/home/krb5/client.keytab", c.LibDefaults.DefaultClientKeytabName)
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes)

	assert.Equal(t, 2, len(c.Realms))
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm)
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer)
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer)
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain)
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC)
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC)
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer)

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"])
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"])
}

func TestParseDuration(t *testing.T) {
	t.Parallel()
	// https://web.mit.edu/kerberos/krb5-1.12/doc/basic/date_format.html#duration
	hms, _ := time.ParseDuration("12h30m15s")
	hm, _ := time.ParseDuration("12h30m")
	h, _ := time.ParseDuration("12h")

	var tests = []struct {
		timeStr  string
		duration time.Duration
	}{
		{"100", time.Duration(100) * time.Second},
		{"12:30", hm},
		{"12:30:15", hms},
		{"1d12h30m15s", time.Duration(24)*time.Hour + hms},
		{"1d12h30m", time.Duration(24)*time.Hour + hm},
		{"1d12h", time.Duration(24)*time.Hour + h},
		{"1d", time.Duration(24) * time.Hour},
	}
	for _, test := range tests {
		d, err := parseDuration(test.timeStr)
		assert.NoError(t, err)

		assert.Equal(t, test.duration, d, "Duration not as expected for: "+test.timeStr)
	}
}

func TestResolveRealm(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(krb5Conf)
	require.NoError(t, err)

	tests := []struct {
		domainName string
		want       string
	}{
		{"unknown.com", ""},
		{"hostname1.example.com", "EXAMPLE.COM"},
		{"hostname2.example.com", "TEST.GOKRB5"},
		{"one.two.three.example.com", "EXAMPLE.COM"},
		{".test.gokrb5", "TEST.GOKRB5"},
		{"foo.testlowercase.org", "lowercase.org"},
	}
	for _, tt := range tests {
		t.Run(tt.domainName, func(t *testing.T) {
			have := c.ResolveRealm(tt.domainName)
			assert.Equal(t, tt.want, have)
		})
	}
}

func TestJSON(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(krb5Conf)
	require.NoError(t, err)

	c.LibDefaults.K5LoginDirectory = "/home/test"

	j, err := c.JSON()
	require.NoError(t, err)

	assert.Equal(t, krb5ConfJson, j)

	t.Log(j)
}
