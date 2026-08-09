package client

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/encoding/asn1"
)

func TestCache_addEntry_getEntry_remove_clear(t *testing.T) {
	t.Parallel()

	c := NewCache()
	cnt := 10

	var wg sync.WaitGroup
	for i := 0; i < cnt; i++ {
		wg.Add(1)

		tkt := messages.Ticket{
			SName: types.PrincipalName{
				NameType:   1,
				NameString: []string{fmt.Sprintf("%d", i), "test.cache"},
			},
		}

		key := types.EncryptionKey{
			KeyType:  1,
			KeyValue: []byte{byte(i)},
		}
		go func(i int) {
			e := c.addEntry(tkt, time.Unix(int64(0+i), 0).UTC(), time.Unix(int64(10+i), 0).UTC(), time.Unix(int64(20+i), 0).UTC(), time.Unix(int64(30+i), 0).UTC(), key, 0, asn1.BitString{})
			assert.Equal(t, fmt.Sprintf("%d/test.cache", i), e.SPN)
			wg.Done()
		}(i)
	}

	wg.Wait()

	for i := 0; i < cnt; i++ {
		wg.Add(1)

		go func(i int) {
			e, ok := c.getEntry(fmt.Sprintf("%d/test.cache", i))
			assert.True(t, ok)
			assert.Equal(t, time.Unix(int64(0+i), 0).UTC(), e.AuthTime)
			assert.Equal(t, time.Unix(int64(10+i), 0).UTC(), e.StartTime)
			assert.Equal(t, time.Unix(int64(20+i), 0).UTC(), e.EndTime)
			assert.Equal(t, time.Unix(int64(30+i), 0).UTC(), e.RenewTill)
			assert.Equal(t, []string{fmt.Sprintf("%d", i), "test.cache"}, e.Ticket.SName.NameString)
			assert.Equal(t, []byte{byte(i)}, e.SessionKey.KeyValue)
			wg.Done()
		}(i)
	}

	wg.Wait()

	_, ok := c.getEntry(fmt.Sprintf("%d/test.cache", cnt+1))
	assert.False(t, ok)

	for i := 0; i < cnt; i += 2 {
		wg.Add(1)

		go func(i int) {
			c.RemoveEntry(fmt.Sprintf("%d/test.cache", i))
			wg.Done()
		}(i)
	}

	wg.Wait()

	for i := 0; i < cnt; i++ {
		wg.Add(1)

		go func(i int) {
			if i%2 == 0 {
				_, ok := c.getEntry(fmt.Sprintf("%d/test.cache", cnt+1))
				assert.False(t, ok)
			} else {
				e, ok := c.getEntry(fmt.Sprintf("%d/test.cache", i))
				assert.True(t, ok)
				assert.Equal(t, time.Unix(int64(0+i), 0).UTC(), e.AuthTime)
				assert.Equal(t, time.Unix(int64(10+i), 0).UTC(), e.StartTime)
				assert.Equal(t, time.Unix(int64(20+i), 0).UTC(), e.EndTime)
				assert.Equal(t, time.Unix(int64(30+i), 0).UTC(), e.RenewTill)
				assert.Equal(t, []string{fmt.Sprintf("%d", i), "test.cache"}, e.Ticket.SName.NameString)
				assert.Equal(t, []byte{byte(i)}, e.SessionKey.KeyValue)
			}

			wg.Done()
		}(i)
	}

	wg.Wait()

	c.clear()

	for i := 0; i < cnt; i++ {
		wg.Add(1)

		go func(i int) {
			_, ok := c.getEntry(fmt.Sprintf("%d/test.cache", i+1))
			assert.False(t, ok)
			wg.Done()
		}(i)
	}

	wg.Wait()
}

func TestCache_JSON(t *testing.T) {
	t.Parallel()

	c := NewCache()

	cnt := 3
	for i := 0; i < cnt; i++ {
		tkt := messages.Ticket{
			SName: types.PrincipalName{
				NameType:   1,
				NameString: []string{fmt.Sprintf("%d", i), "test.cache"},
			},
		}
		key := types.EncryptionKey{
			KeyType:  1,
			KeyValue: []byte{byte(i)},
		}
		e := c.addEntry(tkt, time.Unix(int64(0+i), 0).UTC(), time.Unix(int64(10+i), 0).UTC(), time.Unix(int64(20+i), 0).UTC(), time.Unix(int64(30+i), 0).UTC(), key, 0, asn1.BitString{})
		assert.Equal(t, fmt.Sprintf("%d/test.cache", i), e.SPN)
	}

	expected := `[
  {
    "SPN": "0/test.cache",
    "AuthTime": "1970-01-01T00:00:00Z",
    "StartTime": "1970-01-01T00:00:10Z",
    "EndTime": "1970-01-01T00:00:20Z",
    "RenewTill": "1970-01-01T00:00:30Z"
  },
  {
    "SPN": "1/test.cache",
    "AuthTime": "1970-01-01T00:00:01Z",
    "StartTime": "1970-01-01T00:00:11Z",
    "EndTime": "1970-01-01T00:00:21Z",
    "RenewTill": "1970-01-01T00:00:31Z"
  },
  {
    "SPN": "2/test.cache",
    "AuthTime": "1970-01-01T00:00:02Z",
    "StartTime": "1970-01-01T00:00:12Z",
    "EndTime": "1970-01-01T00:00:22Z",
    "RenewTill": "1970-01-01T00:00:32Z"
  }
]`

	j, err := c.JSON()
	assert.NoError(t, err)

	assert.Equal(t, expected, j)
}

// TestCacheShouldRetainTheServerSupportedEncryptionTypes asserts the application server's PA-SUPPORTED-ENCTYPES
// advertisement is kept against its SPN. Delegation happens long after the TGS exchange that learned it, and
// ForwardedTGT has only the SPN to look it up by.
func TestCacheShouldRetainTheServerSupportedEncryptionTypes(t *testing.T) {
	t.Parallel()

	want := types.NewSupportedETypesFromIDs([]int32{etypeID.AES256_CTS_HMAC_SHA1_96})

	c := NewCache()
	tkt := messages.Ticket{
		SName: types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"HTTP", "host.test.gokrb5"}},
	}

	c.addEntry(tkt, time.Unix(0, 0).UTC(), time.Unix(10, 0).UTC(), time.Unix(20, 0).UTC(), time.Unix(30, 0).UTC(),
		types.EncryptionKey{}, want, asn1.BitString{})

	e, ok := c.getEntry("HTTP/host.test.gokrb5")
	require.True(t, ok)
	assert.Equal(t, want, e.SupportedETypes)
}

// TestOKAsDelegateShouldReportTheCachedTicketFlag asserts the gate ContextFlagDelegPolicy consults. The flag lives
// in the ticket's encrypted part, which the client cannot read, so the TGS-REP is the only source and it has to
// survive into the cache.
func TestOKAsDelegateShouldReportTheCachedTicketFlag(t *testing.T) {
	t.Parallel()

	c, err := config.NewFromString(testdata.KRB5_CONF)
	require.NoError(t, err)

	cl := NewWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue", c)
	spn := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"HTTP", "host.test.gokrb5"}}

	assert.False(t, cl.OKAsDelegate(spn), "a ticket that is not cached must not be treated as delegable")

	tkt := messages.Ticket{SName: spn}

	cl.cache.addEntry(tkt, time.Unix(0, 0).UTC(), time.Unix(10, 0).UTC(), time.Unix(20, 0).UTC(),
		time.Unix(30, 0).UTC(), types.EncryptionKey{}, 0, types.NewKrbFlags())
	assert.False(t, cl.OKAsDelegate(spn))

	okFlags := types.NewKrbFlags()
	types.SetFlag(&okFlags, flags.OKAsDelegate)

	cl.cache.addEntry(tkt, time.Unix(0, 0).UTC(), time.Unix(10, 0).UTC(), time.Unix(20, 0).UTC(),
		time.Unix(30, 0).UTC(), types.EncryptionKey{}, 0, okFlags)
	assert.True(t, cl.OKAsDelegate(spn))
}
