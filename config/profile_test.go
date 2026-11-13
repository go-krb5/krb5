package config

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/etypeID"
)

func TestProfileTreatsOnlyWholeLinesAsComments(t *testing.T) {
	t.Parallel()

	c, err := NewFromString("[libdefaults]\n  # default_realm = COMMENTED.OUT\n  ; default_realm = COMMENTED.OUT\n  default_keytab_name = FILE:/etc/a#b;c\n  default_realm = TEST.GOKRB5\n")
	require.NoError(t, err)

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
	assert.Equal(t, "FILE:/etc/a#b;c", c.LibDefaults.DefaultKeytabName)
}

func TestProfileIgnoresLinesBeforeTheFirstSection(t *testing.T) {
	t.Parallel()

	c, err := NewFromString("default_realm = IGNORED\nnot a relation at all\n[libdefaults]\n default_realm = TEST.GOKRB5\n")
	require.NoError(t, err)

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
}

func TestProfileUsesTheFirstValueOfARelation(t *testing.T) {
	t.Parallel()

	c, err := NewFromString("[libdefaults]\n default_realm = FIRST.GOKRB5\n forwardable = true\n[realms]\n[libdefaults]\n default_realm = SECOND.GOKRB5\n forwardable = false\n")
	require.NoError(t, err)

	assert.Equal(t, "FIRST.GOKRB5", c.LibDefaults.DefaultRealm)
	assert.True(t, c.LibDefaults.Forwardable)
}

func TestProfileMergesARealmThatAppearsTwice(t *testing.T) {
	t.Parallel()

	c, err := NewFromString("[realms]\n TEST.GOKRB5 = {\n  kdc = kdc1.test.gokrb5\n }\n[domain_realm]\n[realms]\n TEST.GOKRB5 = {\n  kdc = kdc2.test.gokrb5\n }\n")
	require.NoError(t, err)

	require.Len(t, c.Realms, 1)
	assert.Equal(t, []string{nestedRealmKDC, secondRealmKDC}, c.Realms[0].KDC)
}

func TestProfileHonoursFinalMarkers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		conf string
		kdcs []string
	}{
		{
			"Relation",
			"[realms]\n TEST.GOKRB5 = {\n  kdc* = kdc1.test.gokrb5\n  kdc = kdc2.test.gokrb5\n }\n",
			[]string{nestedRealmKDC},
		},
		{
			"SubsectionTag",
			"[realms]\n TEST.GOKRB5* = {\n  kdc = kdc1.test.gokrb5\n }\n TEST.GOKRB5 = {\n  kdc = kdc2.test.gokrb5\n }\n",
			[]string{nestedRealmKDC},
		},
		{
			"SubsectionBrace",
			"[realms]\n TEST.GOKRB5 = {\n  kdc = kdc1.test.gokrb5\n }*\n TEST.GOKRB5 = {\n  kdc = kdc2.test.gokrb5\n }\n",
			[]string{nestedRealmKDC},
		},
		{
			"Section",
			"[realms]*\n TEST.GOKRB5 = {\n  kdc = kdc1.test.gokrb5\n }\n[realms]\n TEST.GOKRB5 = {\n  kdc = kdc2.test.gokrb5\n }\n",
			[]string{nestedRealmKDC},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := NewFromString(tc.conf)
			require.NoError(t, err)

			require.Len(t, c.Realms, 1)
			assert.Equal(t, tc.kdcs, c.Realms[0].KDC)
		})
	}
}

func TestProfileReadsQuotedValues(t *testing.T) {
	t.Parallel()

	c, err := NewFromString("[libdefaults]\n default_realm = \"  TEST.GOKRB5  \" trailing text\n default_keytab_name = \"a\\tb\\\\c\\\"d\"\n")
	require.NoError(t, err)

	assert.Equal(t, "  TEST.GOKRB5  ", c.LibDefaults.DefaultRealm)
	assert.Equal(t, "a\tb\\c\"d", c.LibDefaults.DefaultKeytabName)
}

func TestProfileReadsAnOpeningBraceOnTheNextLine(t *testing.T) {
	t.Parallel()

	c, err := NewFromString("[realms]\n TEST.GOKRB5 =\n {\n  kdc = kdc1.test.gokrb5\n }\n")
	require.NoError(t, err)

	require.Len(t, c.Realms, 1)
	assert.Equal(t, []string{nestedRealmKDC}, c.Realms[0].KDC)
}

func TestProfileRefusesInvalidSyntax(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		conf string
	}{
		{"UnclosedSectionHeader", "[libdefaults\n"},
		{"TextAfterSectionHeader", "[libdefaults] extra\n"},
		{"SectionInsideSubsection", "[realms]\n TEST.GOKRB5 = {\n  sub = {\n[libdefaults]\n"},
		{"RelationWithoutEquals", "[libdefaults]\n default_realm\n"},
		{"TagWithWhitespace", "[libdefaults]\n default realm = TEST.GOKRB5\n"},
		{"EmptyTag", "[libdefaults]\n = TEST.GOKRB5\n"},
		{"MissingOpeningBrace", "[realms]\n TEST.GOKRB5 =\n kdc = kdc1.test.gokrb5\n"},
		{"Module", "module /usr/lib/krb5/plugins/profile.so:residual\n[libdefaults]\n"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewFromString(tc.conf)
			assert.Error(t, err)
		})
	}
}

func TestProfileIncludesAFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inc := filepath.Join(dir, "realms.conf")

	require.NoError(t, os.WriteFile(inc, []byte("[realms]\n TEST.GOKRB5 = {\n  kdc = kdc1.test.gokrb5\n }\n"), 0o600))

	c, err := NewFromString("[libdefaults]\n default_realm = TEST.GOKRB5\ninclude " + inc + "\n[domain_realm]\n .test.gokrb5 = TEST.GOKRB5\n")
	require.NoError(t, err)

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
	require.Len(t, c.Realms, 1)
	assert.Equal(t, []string{nestedRealmKDC}, c.Realms[0].KDC)
	assert.Equal(t, "TEST.GOKRB5", c.ResolveRealm("host.test.gokrb5"))
}

func TestProfileIncludesADirectoryInOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	files := map[string]string{
		"20-second.conf":    "[realms]\n TEST.GOKRB5 = {\n  kdc = kdc2.test.gokrb5\n }\n",
		"10_first":          "[realms]\n TEST.GOKRB5 = {\n  kdc = kdc1.test.gokrb5\n }\n",
		".hidden.conf":      "[realms]\n TEST.GOKRB5 = {\n  kdc = hidden.test.gokrb5\n }\n",
		"30-third.rpmsave":  "[realms]\n TEST.GOKRB5 = {\n  kdc = rpmsave.test.gokrb5\n }\n",
		"40-fourth.conf~":   "[realms]\n TEST.GOKRB5 = {\n  kdc = backup.test.gokrb5\n }\n",
		"50-fifth-settings": "[libdefaults]\n default_realm = TEST.GOKRB5\n",
	}

	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}

	c, err := NewFromString("includedir " + dir + "\n")
	require.NoError(t, err)

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
	require.Len(t, c.Realms, 1)
	assert.Equal(t, []string{nestedRealmKDC, secondRealmKDC}, c.Realms[0].KDC)
}

func TestProfileIncludedFilesAreSyntacticallyIndependent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inc := filepath.Join(dir, "fragment.conf")

	require.NoError(t, os.WriteFile(inc, []byte(" default_realm = INCLUDED.GOKRB5\n"), 0o600))

	c, err := NewFromString("[libdefaults]\ninclude " + inc + "\n default_realm = TEST.GOKRB5\n")
	require.NoError(t, err)

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
}

func TestProfileRefusesAMissingInclude(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	for _, d := range []string{"include " + filepath.Join(dir, "missing.conf"), "includedir " + filepath.Join(dir, "missing")} {
		_, err := NewFromString("[libdefaults]\n" + d + "\n")
		assert.Error(t, err, d)
	}
}

func TestProfileRefusesAnIncludeLoop(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inc := filepath.Join(dir, "loop.conf")

	require.NoError(t, os.WriteFile(inc, []byte("include "+inc+"\n"), 0o600))

	var err error

	require.NotPanics(t, func() { _, err = NewFromString("include " + inc + "\n") })
	assert.Error(t, err)
}

func TestProfileOnlyHonoursIncludeAtTheStartOfALine(t *testing.T) {
	t.Parallel()

	_, err := NewFromString("[libdefaults]\n include /nonexistent/krb5.conf\n")
	assert.Error(t, err, "an indented include is a relation without an equals sign")
}

func TestLoadFilesConsultsEachFileInOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	first := filepath.Join(dir, "first.conf")
	second := filepath.Join(dir, "second.conf")

	require.NoError(t, os.WriteFile(first, []byte("[libdefaults]\n default_realm = FIRST.GOKRB5\n[realms]\n TEST.GOKRB5 = {\n  kdc = kdc1.test.gokrb5\n }\n FINAL.GOKRB5 = {\n  kdc* = kdc1.final.gokrb5\n }\n"), 0o600))
	require.NoError(t, os.WriteFile(second, []byte("[libdefaults]\n default_realm = SECOND.GOKRB5\n forwardable = true\n[realms]\n TEST.GOKRB5 = {\n  kdc = kdc2.test.gokrb5\n }\n FINAL.GOKRB5 = {\n  kdc = kdc2.final.gokrb5\n }\n"), 0o600))

	c, err := LoadFiles(filepath.Join(dir, "missing.conf"), first, second)
	require.NoError(t, err)

	assert.Equal(t, "FIRST.GOKRB5", c.LibDefaults.DefaultRealm)
	assert.True(t, c.LibDefaults.Forwardable)
	require.Len(t, c.Realms, 2)
	assert.Equal(t, []string{nestedRealmKDC, secondRealmKDC}, c.Realms[0].KDC)
	assert.Equal(t, []string{"kdc1.final.gokrb5:88"}, c.Realms[1].KDC)
}

func TestLoadFilesReadsADirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "realm.conf"), []byte("[libdefaults]\n default_realm = TEST.GOKRB5\n"), 0o600))

	c, err := LoadFiles(dir)
	require.NoError(t, err)
	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)

	c, err = Load(dir)
	require.NoError(t, err)
	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
}

func TestLoadFilesRefusesWhenNoFileExists(t *testing.T) {
	t.Parallel()

	_, err := LoadFiles(filepath.Join(t.TempDir(), "missing.conf"))
	assert.Error(t, err)
}

func TestLoadDefaultReadsKRB5CONFIG(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.conf")
	second := filepath.Join(dir, "second.conf")

	require.NoError(t, os.WriteFile(second, []byte("[libdefaults]\n default_realm = TEST.GOKRB5\n"), 0o600))

	t.Setenv("KRB5_CONFIG", first+string(filepath.ListSeparator)+second)

	assert.Equal(t, []string{first, second}, DefaultPaths())

	c, err := LoadDefault()
	require.NoError(t, err)
	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm)
}

func TestParseBooleanAcceptsWhatMITAccepts(t *testing.T) {
	t.Parallel()

	for _, v := range []string{"y", "YES", "true", "T", "1", "On"} {
		b, err := parseBoolean(v)
		require.NoError(t, err, v)
		assert.True(t, b, v)
	}

	for _, v := range []string{"n", "No", "FALSE", "nil", "0", "off"} {
		b, err := parseBoolean(v)
		require.NoError(t, err, v)
		assert.False(t, b, v)
	}

	for _, v := range []string{"", "2", "enabled", confFallback} {
		_, err := parseBoolean(v)
		assert.Error(t, err, v)
	}
}

func TestParseDurationMatchesMIT(t *testing.T) {
	t.Parallel()

	day := 24 * time.Hour

	testCases := []struct {
		value    string
		expected time.Duration
	}{
		{"28s", 28 * time.Second},
		{"7m ", 7 * time.Minute},
		{"6m 9s", 6*time.Minute + 9*time.Second},
		{"2h", 2 * time.Hour},
		{"2h-5s", time.Hour + 59*time.Minute + 55*time.Second},
		{"2h3m", 2*time.Hour + 3*time.Minute},
		{"2h3m5s", 2*time.Hour + 3*time.Minute + 5*time.Second},
		{"5d ", 5 * day},
		{"5d-48s", 4*day + 23*time.Hour + 59*time.Minute + 12*time.Second},
		{"5d18m", 5*day + 18*time.Minute},
		{"5d -6m56s", 4*day + 23*time.Hour + 54*time.Minute + 56*time.Second},
		{"5d4h", 5*day + 4*time.Hour},
		{"5d4h 1s", 5*day + 4*time.Hour + time.Second},
		{"5d4h3m", 5*day + 4*time.Hour + 3*time.Minute},
		{" \t 15d \n 4h  3m  2s", 15*day + 4*time.Hour + 3*time.Minute + 2*time.Second},
		{"10-8:45:0", 10*day + 8*time.Hour + 45*time.Minute},
		{"1000:67:99", 41*day + 17*time.Hour + 8*time.Minute + 39*time.Second},
		{"999:11", 41*day + 15*time.Hour + 11*time.Minute},
		{"382512", 4*day + 10*time.Hour + 15*time.Minute + 12*time.Second},
	}

	for _, tc := range testCases {
		d, err := parseDuration(tc.value)
		require.NoError(t, err, tc.value)
		assert.Equal(t, tc.expected, d, tc.value)
	}

	for _, v := range []string{"", "1.5h", "300ms", "2s ", "1m1h", "1:2:3:4", "1:234", "1d1d", "abc", "99999999999", "24856d"} {
		_, err := parseDuration(v)
		assert.Error(t, err, v)
	}
}

func TestLibDefaultsMatchMITDefaults(t *testing.T) {
	t.Parallel()

	c, err := NewFromString("[libdefaults]\n default_realm = TEST.GOKRB5\n")
	require.NoError(t, err)

	l := c.LibDefaults

	assert.True(t, l.DNSLookupKDC)
	assert.False(t, l.DNSLookupRealm)
	assert.True(t, l.DNSCanonicalizeHostname)
	assert.False(t, l.DNSCanonicalizeHostnameFallback)
	assert.True(t, l.K5LoginAuthoritative)
	assert.True(t, l.RDNS)
	assert.True(t, l.NoAddresses)
	assert.Equal(t, 300*time.Second, l.Clockskew)
	assert.Equal(t, 24*time.Hour, l.TicketLifetime)
	assert.Equal(t, 1465, l.UDPPreferenceLimit)
	assert.Equal(t, []byte{0, 0, 0, 0x10}, l.KDCDefaultOptions.Bytes)
	assert.Equal(t, defaultETypeNames, l.PermittedEnctypes)
	assert.Equal(t, defaultETypeNames, l.DefaultTktEnctypes)
	assert.Equal(t, defaultETypeNames, l.DefaultTGSEnctypes)
	assert.Equal(t, "FILE:/tmp/krb5cc_"+strconv.Itoa(os.Getuid()), l.DefaultCCacheName)
}

func TestLibDefaultsReadDNSCanonicalizeHostnameFallback(t *testing.T) {
	t.Parallel()

	for _, v := range []string{confFallback, "Fallback"} {
		c, err := NewFromString("[libdefaults]\n dns_canonicalize_hostname = " + v + "\n")
		require.NoError(t, err, v)

		assert.False(t, c.LibDefaults.DNSCanonicalizeHostname, v)
		assert.True(t, c.LibDefaults.DNSCanonicalizeHostnameFallback, v)
	}

	_, err := NewFromString("[libdefaults]\n dns_canonicalize_hostname = sometimes\n")
	assert.Error(t, err)
}

func TestLibDefaultsReadDNSFallback(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		conf   string
		kdc    bool
		lookup bool
	}{
		{"FallbackOff", " dns_fallback = no\n", false, false},
		{"FallbackOn", " dns_fallback = yes\n", true, true},
		{"ExplicitWins", " dns_fallback = yes\n dns_lookup_kdc = false\n", false, true},
		{"UnrecognizedIsFalse", " dns_lookup_kdc = maybe\n", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := NewFromString("[libdefaults]\n" + tc.conf)
			require.NoError(t, err)

			assert.Equal(t, tc.kdc, c.LibDefaults.DNSLookupKDC)
			assert.Equal(t, tc.lookup, c.LibDefaults.DNSLookupRealm)
		})
	}
}

func TestLibDefaultsReadMITKeysAndValues(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(`[libdefaults]
 clockskew = 600
 kdc_default_options = 0x40000010
 udp_preference_limit = 100000
 ticket_lifetime = 10:00
 renew_lifetime = 7d
 extra_addresses = 10.0.0.1, 10.0.0.2 not-an-address
 extra_addresses = 10.0.0.3
`)
	require.NoError(t, err)

	l := c.LibDefaults

	assert.Equal(t, 600*time.Second, l.Clockskew)
	assert.Equal(t, []byte{0x40, 0, 0, 0x10}, l.KDCDefaultOptions.Bytes)
	assert.Equal(t, 32700, l.UDPPreferenceLimit)
	assert.Equal(t, 10*time.Hour, l.TicketLifetime)
	assert.Equal(t, 7*24*time.Hour, l.RenewLifetime)
	assert.Equal(t, []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3")}, l.ExtraAddresses)

	c, err = NewFromString("[libdefaults]\n kdc_default_options = 16\n udp_preference_limit = -1\n")
	require.NoError(t, err)

	assert.Equal(t, []byte{0, 0, 0, 0x10}, c.LibDefaults.KDCDefaultOptions.Bytes)
	assert.Equal(t, 1465, c.LibDefaults.UDPPreferenceLimit)
}

func TestLibDefaultsReadEnctypeListsAsMITDoes(t *testing.T) {
	t.Parallel()

	aes := []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA384_192, etypeID.AES128_CTS_HMAC_SHA256_128}

	testCases := []struct {
		name     string
		conf     string
		permit   []int32
		tkt, tgs []int32
	}{
		{
			"CommaSeparated",
			" default_tkt_enctypes = aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96\n",
			aes, aes[:2], aes,
		},
		{
			"PermittedIsTheDefault",
			" permitted_enctypes = aes256-sha2 aes128-sha2\n",
			aes[2:], aes[2:], aes[2:],
		},
		{
			"FamiliesAndModifiers",
			" permitted_enctypes = DEFAULT -aes128-cts\n default_tgs_enctypes = aes -aes256-sha1 +AES256-CTS\n",
			[]int32{aes[0], aes[2], aes[3]}, []int32{aes[0], aes[2], aes[3]}, []int32{aes[1], aes[2], aes[3], aes[0]},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := NewFromString("[libdefaults]\n" + tc.conf)
			require.NoError(t, err)

			assert.Equal(t, tc.permit, c.LibDefaults.PermittedEnctypeIDs)
			assert.Equal(t, tc.tkt, c.LibDefaults.DefaultTktEnctypeIDs)
			assert.Equal(t, tc.tgs, c.LibDefaults.DefaultTGSEnctypeIDs)
		})
	}
}

func TestETypeNamesFollowMIT(t *testing.T) {
	t.Parallel()

	for name, expected := range map[string]int32{
		"des3-cbc-sha1":  etypeID.DES3_CBC_SHA1_KD,
		"des3-hmac-sha1": etypeID.DES3_CBC_SHA1_KD,
		"ARCFOUR-HMAC":   etypeID.RC4_HMAC,
		"aes256-sha2":    etypeID.AES256_CTS_HMAC_SHA384_192,
	} {
		id, ok := etypeByName(name)
		require.True(t, ok, name)
		assert.Equal(t, expected, id, name)
	}
}

func TestLibDefaultsForRealm(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(`[libdefaults]
 forwardable = false
 ticket_lifetime = 10h
 TEST.GOKRB5 = {
  forwardable = true
  ticket_lifetime = 1h
  default_realm = IGNORED.GOKRB5
 }
`)
	require.NoError(t, err)

	assert.False(t, c.LibDefaults.Forwardable)
	assert.Equal(t, 10*time.Hour, c.LibDefaults.TicketLifetime)
	assert.Empty(t, c.LibDefaults.DefaultRealm)

	l := c.LibDefaultsForRealm("TEST.GOKRB5")
	assert.True(t, l.Forwardable)
	assert.Equal(t, time.Hour, l.TicketLifetime)
	assert.Empty(t, l.DefaultRealm)

	assert.Equal(t, c.LibDefaults, c.LibDefaultsForRealm("OTHER.GOKRB5"))
}

func TestRealmsReadAddressesAsMITDoes(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(`[realms]
 TEST.GOKRB5 = {
  kdc = kdc1.test.gokrb5
  kdc = kdc2.test.gokrb5:750
  kdc = [2001:db8::1]
  kdc = [2001:db8::2]:750
  kdc = https://kdc.test.gokrb5/KdcProxy
  admin_server = [2001:db8::3]:749
  primary_kdc = primary.test.gokrb5
  master_kdc = master.test.gokrb5
 }
 OTHER.GOKRB5 = {
  kpasswd_server = kpasswd.other.gokrb5
  master_kdc = master.other.gokrb5
 }
`)
	require.NoError(t, err)

	require.Len(t, c.Realms, 2)

	r := c.Realms[0]
	assert.Equal(t, []string{nestedRealmKDC, "kdc2.test.gokrb5:750", "[2001:db8::1]:88", "[2001:db8::2]:750", "https://kdc.test.gokrb5/KdcProxy"}, r.KDC)
	assert.Equal(t, []string{"[2001:db8::3]:464"}, r.KPasswdServer)
	assert.Equal(t, []string{"primary.test.gokrb5"}, r.MasterKDC)

	r = c.Realms[1]
	assert.Equal(t, []string{"kpasswd.other.gokrb5:464"}, r.KPasswdServer)
	assert.Equal(t, []string{"master.other.gokrb5"}, r.MasterKDC)

	for _, kdc := range []string{"kdc1.test.gokrb5:notaport", "750", ":750", "kdc1.test.gokrb5:65536"} {
		_, err = NewFromString("[realms]\n TEST.GOKRB5 = {\n  kdc = " + kdc + "\n }\n")
		assert.Error(t, err, kdc)
	}
}

func TestResolveRealmMatchesMIT(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(`[domain_realm]
 crash.mit.edu = TEST.ATHENA.MIT.EDU
 .dev.mit.edu = TEST.ATHENA.MIT.EDU
 mit.edu = ATHENA.MIT.EDU
 mit.edu = SECOND.MIT.EDU
 10.0.0.1 = ADDRESS.MIT.EDU
`)
	require.NoError(t, err)

	testCases := map[string]string{
		"crash.mit.edu":      realmTestAthena,
		"host.dev.mit.edu":   realmTestAthena,
		"dev.mit.edu":        realmAthena,
		"mit.edu":            realmAthena,
		"www.MIT.edu.":       realmAthena,
		"a.b.c.mit.edu":      realmAthena,
		"notmit.edu":         "",
		"10.0.0.1":           "",
		"example.com":        "",
		"crash.mit.edu.evil": "",
	}

	for host, expected := range testCases {
		assert.Equal(t, expected, c.ResolveRealm(host), host)
	}
}

func TestExpandPath(t *testing.T) {
	t.Parallel()

	uid := strconv.Itoa(os.Getuid())
	euid := strconv.Itoa(os.Geteuid())

	testCases := map[string]string{
		"FILE:/tmp/krb5cc_%{uid}":   "FILE:/tmp/krb5cc_" + uid,
		"/var/%{euid}/%{USERID}.kt": "/var/" + euid + "/" + uid + ".kt",
		"a%{null}b":                 "ab",
		pathNoParameters:            pathNoParameters,
		"%{uid}%{uid}":              uid + uid,
		pathWithPercent:             pathWithPercent,
	}

	for in, expected := range testCases {
		v, err := ExpandPath(in)
		require.NoError(t, err, in)
		assert.Equal(t, expected, v, in)
	}

	for _, in := range []string{"%{unknown}", "%{uid", "%{}", "%{LIBDIR}/krb5"} {
		_, err := ExpandPath(in)
		assert.Error(t, err, in)
	}
}

func TestLibDefaultsExpandPathParameters(t *testing.T) {
	t.Parallel()

	uid := strconv.Itoa(os.Getuid())

	c, err := NewFromString(`[libdefaults]
 default_ccache_name = FILE:/run/user/%{uid}/krb5cc
 default_keytab_name = FILE:/etc/%{uid}.keytab
 default_client_keytab_name = FILE:%{LIBDIR}/client.keytab
`)
	require.NoError(t, err)

	assert.Equal(t, "FILE:/run/user/"+uid+"/krb5cc", c.LibDefaults.DefaultCCacheName)
	assert.Equal(t, "FILE:/etc/"+uid+".keytab", c.LibDefaults.DefaultKeytabName)
	assert.Equal(t, "FILE:%{LIBDIR}/client.keytab", c.LibDefaults.DefaultClientKeytabName)

	_, err = NewFromString("[libdefaults]\n default_keytab_name = FILE:/etc/%{bogus}.keytab\n")
	assert.Error(t, err)
}

func TestConfigNamesPreferTheEnvironment(t *testing.T) {
	c, err := NewFromString("[libdefaults]\n default_ccache_name = FILE:/conf/cc\n default_keytab_name = FILE:/conf/kt\n default_client_keytab_name = FILE:/conf/ckt\n")
	require.NoError(t, err)

	t.Setenv("KRB5CCNAME", "")
	t.Setenv("KRB5_KTNAME", "")
	t.Setenv("KRB5_CLIENT_KTNAME", "")

	require.NoError(t, os.Unsetenv("KRB5CCNAME"))
	require.NoError(t, os.Unsetenv("KRB5_KTNAME"))
	require.NoError(t, os.Unsetenv("KRB5_CLIENT_KTNAME"))

	assert.Equal(t, "FILE:/conf/cc", c.CCacheName())
	assert.Equal(t, "FILE:/conf/kt", c.KeytabName())
	assert.Equal(t, "FILE:/conf/ckt", c.ClientKeytabName())

	t.Setenv("KRB5CCNAME", "FILE:/env/%{uid}")
	t.Setenv("KRB5_KTNAME", "FILE:/env/kt")
	t.Setenv("KRB5_CLIENT_KTNAME", "FILE:/env/ckt")

	assert.Equal(t, "FILE:/env/%{uid}", c.CCacheName())
	assert.Equal(t, "FILE:/env/kt", c.KeytabName())
	assert.Equal(t, "FILE:/env/ckt", c.ClientKeytabName())
}

const (
	confFallback     = "fallback"
	secondRealmKDC   = "kdc2.test.gokrb5:88"
	realmTestAthena  = "TEST.ATHENA.MIT.EDU"
	realmAthena      = "ATHENA.MIT.EDU"
	pathNoParameters = "no parameters"
	pathWithPercent  = "FILE:/etc/krb5.keytab?a=b%c"
)
