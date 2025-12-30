package client

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestMultiThreadedClientSession(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	require.NotNil(t, cl.Login())

	s, ok := cl.sessions.get("TEST.GOKRB5")
	require.True(t, ok)

	go func() {
		for {
			assert.NoError(t, cl.renewTGT(s))

			time.Sleep(time.Millisecond * 100)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(10)

	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()

			tgt, _, err := cl.sessionTGT("TEST.GOKRB5")
			if err != nil || tgt.Realm != "TEST.GOKRB5" {
				t.Logf("error getting session: %v", err)
			}

			_, _, _, r, _ := cl.sessionTimes("TEST.GOKRB5")
			fmt.Fprintf(io.Discard, "%v", r)
		}()

		time.Sleep(time.Second)
	}

	wg.Wait()
}

func TestClient_AutoRenew_Goroutine(t *testing.T) {
	test.Integration(t)

	// Tests that the auto renew of client credentials is not spawning goroutines out of control.
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	b, err := hex.DecodeString(testdata.KEYTAB_TESTUSER2_TEST_GOKRB5)
	require.NoError(t, err)

	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_SHORTTICKETS}
	c.LibDefaults.PreferredPreauthTypes = []int{int(etypeID.DES3_CBC_SHA1_KD)} // a preauth etype the KDC does not support. Test this does not cause renewal to fail.
	cl := NewWithKeytab("testuser2", "TEST.GOKRB5", kt, c)

	require.NotNil(t, cl.Login())

	n := runtime.NumGoroutine()

	for i := 0; i < 24; i++ {
		time.Sleep(time.Second * 5)

		_, endTime, _, _, err := cl.sessionTimes("TEST.GOKRB5")
		assert.NoError(t, err)

		require.False(t, time.Now().UTC().After(endTime))

		spn := "HTTP/host.test.gokrb5"

		tkt, key, err := cl.GetServiceTicket(spn)
		require.NoError(t, err)

		b, err := hex.DecodeString(testdata.HTTP_KEYTAB)
		require.NoError(t, err)

		skt := keytab.New()
		require.NoError(t, skt.Unmarshal(b))
		require.NoError(t, tkt.DecryptEncPart(skt, nil))
		assert.Equal(t, spn, tkt.SName.PrincipalNameString())
		assert.Equal(t, int32(18), key.KeyType)

		require.LessOrEqual(t, runtime.NumGoroutine(), n)
	}
}

func TestSessions_JSON(t *testing.T) {
	s := &sessions{
		Entries: make(map[string]*session),
	}

	for i := 0; i < 3; i++ {
		realm := fmt.Sprintf("test%d", i)
		e := &session{
			realm:                realm,
			authTime:             time.Unix(int64(0+i), 0).UTC(),
			endTime:              time.Unix(int64(10+i), 0).UTC(),
			renewTill:            time.Unix(int64(20+i), 0).UTC(),
			sessionKeyExpiration: time.Unix(int64(30+i), 0).UTC(),
		}
		s.Entries[realm] = e
	}

	j, err := s.JSON()
	assert.NoError(t, err)

	expected := `[
  {
    "Realm": "test0",
    "AuthTime": "1970-01-01T00:00:00Z",
    "EndTime": "1970-01-01T00:00:10Z",
    "RenewTill": "1970-01-01T00:00:20Z",
    "SessionKeyExpiration": "1970-01-01T00:00:30Z"
  },
  {
    "Realm": "test1",
    "AuthTime": "1970-01-01T00:00:01Z",
    "EndTime": "1970-01-01T00:00:11Z",
    "RenewTill": "1970-01-01T00:00:21Z",
    "SessionKeyExpiration": "1970-01-01T00:00:31Z"
  },
  {
    "Realm": "test2",
    "AuthTime": "1970-01-01T00:00:02Z",
    "EndTime": "1970-01-01T00:00:12Z",
    "RenewTill": "1970-01-01T00:00:22Z",
    "SessionKeyExpiration": "1970-01-01T00:00:32Z"
  }
]`
	assert.Equal(t, expected, j)
}
