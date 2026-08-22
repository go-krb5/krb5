package service

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/types"
)

func TestIsReplayAcceptsOnceAndRejectsAfter(t *testing.T) {
	t.Parallel()

	c := newTestCache()
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.test.gokrb5")
	a := testAuthenticator("testuser", "TEST.GOKRB5", time.Now().UTC())

	assert.False(t, c.IsReplay(sname, testSRealm, a), "the first presentation is not a replay")
	assert.True(t, c.IsReplay(sname, testSRealm, a), "the second presentation of the same authenticator is a replay")
	assert.True(t, c.IsReplay(sname, testSRealm, a), "and so is the third")
}

func TestIsReplayIsAtomicUnderConcurrency(t *testing.T) {
	t.Parallel()

	const (
		rounds     = 200
		goroutines = 64
	)

	c := newTestCache()
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.test.gokrb5")

	worst := 0

	for round := range rounds {
		a := testAuthenticator("raceuser", "TEST.GOKRB5", time.Now().UTC().Add(time.Duration(round)*time.Millisecond))

		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			fresh   int
			release = make(chan struct{})
		)

		for range goroutines {
			wg.Add(1)

			go func() {
				defer wg.Done()

				<-release

				if !c.IsReplay(sname, testSRealm, a) {
					mu.Lock()
					fresh++
					mu.Unlock()
				}
			}()
		}

		close(release)
		wg.Wait()

		worst = max(worst, fresh)
	}

	assert.Equal(t, 1, worst,
		"%d concurrent presentations of one authenticator were accepted as fresh; exactly one is correct", worst)
}

func TestIsReplayDistinguishesClientRealms(t *testing.T) {
	t.Parallel()

	c := newTestCache()
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.test.gokrb5")
	ct := time.Now().UTC()

	assert.False(t, c.IsReplay(sname, testSRealm, testAuthenticator("collide", "REALM-A.GOKRB5", ct)))
	assert.False(t, c.IsReplay(sname, testSRealm, testAuthenticator("collide", "REALM-B.GOKRB5", ct)),
		"a different realm is a different principal, not a replay")

	assert.True(t, c.IsReplay(sname, testSRealm, testAuthenticator("collide", "REALM-A.GOKRB5", ct)))
	assert.True(t, c.IsReplay(sname, testSRealm, testAuthenticator("collide", "REALM-B.GOKRB5", ct)))
}

func TestIsReplayDistinguishesServices(t *testing.T) {
	t.Parallel()

	c := newTestCache()
	a := testAuthenticator("testuser", "TEST.GOKRB5", time.Now().UTC())

	assert.False(t, c.IsReplay(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/one.test.gokrb5"), testSRealm, a))
	assert.False(t, c.IsReplay(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/two.test.gokrb5"), testSRealm, a))
}

func TestClearOldEntriesRemovesExpiredAndKeepsCurrent(t *testing.T) {
	t.Parallel()

	c := newTestCache()
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.test.gokrb5")

	old := testAuthenticator("olduser", "TEST.GOKRB5", time.Now().UTC())
	require.False(t, c.IsReplay(sname, testSRealm, old))

	c.mux.Lock()
	for k, ce := range c.entries {
		for t2, e := range ce.replayMap {
			e.presentedTime = time.Now().UTC().Add(-time.Hour)
			ce.replayMap[t2] = e
		}

		c.entries[k] = ce
	}
	c.mux.Unlock()

	current := testAuthenticator("currentuser", "TEST.GOKRB5", time.Now().UTC())
	require.False(t, c.IsReplay(sname, testSRealm, current))

	c.ClearOldEntries(time.Minute)

	assert.False(t, c.IsReplay(sname, testSRealm, old), "the expired entry should have been cleared")
	assert.True(t, c.IsReplay(sname, testSRealm, current), "the current entry should have been kept")
}

func TestIsReplayIsRaceFree(t *testing.T) {
	t.Parallel()

	c := newTestCache()
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.test.gokrb5")

	var wg sync.WaitGroup

	for i := range 32 {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			for j := range 32 {
				a := testAuthenticator(fmt.Sprintf("user%d", i), "TEST.GOKRB5",
					time.Now().UTC().Add(time.Duration(j)*time.Millisecond))
				c.IsReplay(sname, testSRealm, a)
			}
		}(i)
	}

	wg.Wait()
}
func TestClientKeyDoesNotCollideAcrossNameAndRealm(t *testing.T) {
	t.Parallel()

	a := clientKey(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user@REALM-B.GOKRB5"), "")
	b := clientKey(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"), "REALM-B.GOKRB5")

	assert.NotEqual(t, a, b, "a name containing the separator must not collide with a name plus realm")
}

func TestIsReplayKeepsAnEntryWhenAnotherServiceIsPresented(t *testing.T) {
	t.Parallel()

	c := newTestCache()
	a := testAuthenticator("evicteduser", "TEST.GOKRB5", time.Now().UTC())

	one := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/one.test.gokrb5")
	two := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/two.test.gokrb5")

	require.False(t, c.IsReplay(one, testSRealm, a), "the first presentation is not a replay")
	require.False(t, c.IsReplay(two, testSRealm, a), "a different service is a different presentation, not a replay")

	assert.True(t, c.IsReplay(one, testSRealm, a), "the entry for the first service must survive the second being recorded")
	assert.True(t, c.IsReplay(two, testSRealm, a))
}

func TestIsReplayDistinguishesServiceRealms(t *testing.T) {
	t.Parallel()

	c := newTestCache()
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.test.gokrb5")
	a := testAuthenticator("crossrealmuser", "TEST.GOKRB5", time.Now().UTC())

	// RFC 4120 Section 3.2.3: a server may be "registered in multiple realms, with different keys in each", so the
	// same name in two realms is two service principals, not one.
	require.False(t, c.IsReplay(sname, "REALM-A.GOKRB5", a))
	assert.False(t, c.IsReplay(sname, "REALM-B.GOKRB5", a),
		"the same service name in another realm is another principal, not a replay")

	assert.True(t, c.IsReplay(sname, "REALM-A.GOKRB5", a))
	assert.True(t, c.IsReplay(sname, "REALM-B.GOKRB5", a))
}

const testSRealm = "TEST.GOKRB5"

func newTestCache() *Cache {
	return &Cache{entries: make(map[string]clientEntries)}
}

func testAuthenticator(cname, crealm string, ct time.Time) types.Authenticator {
	return types.Authenticator{
		CName:  types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, cname),
		CRealm: crealm,
		CTime:  ct,
		Cusec:  12345,
	}
}
