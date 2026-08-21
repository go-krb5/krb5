// Package service provides server side integrations for Kerberos authentication.
package service

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-krb5/krb5/types"
)

// Replay cache is required as specified in RFC 4120 section 3.2.3.

// Cache for tickets received from clients keyed by fully qualified client name. Used to track replay of tickets.
type Cache struct {
	entries map[string]clientEntries
	mux     sync.RWMutex
}

// clientEntries holds entries of client details sent to the service.
type clientEntries struct {
	replayMap map[time.Time]replayCacheEntry
	seqNumber int64
	subKey    types.EncryptionKey
}

// Cache entry tracking client time values of tickets sent to the service.
type replayCacheEntry struct {
	presentedTime time.Time

	sName types.PrincipalName

	// This combines the ticket's CTime and Cusec.
	cTime time.Time
}

// clientKey identifies the client an entry belongs to.
func clientKey(cname types.PrincipalName, crealm string) string {
	return fmt.Sprintf("%q@%q", cname.PrincipalNameString(), crealm)
}

// getClientEntries returns the entries held for a client. The caller must hold at least the read lock.
func (c *Cache) getClientEntries(cname types.PrincipalName, crealm string) (clientEntries, bool) {
	ce, ok := c.entries[clientKey(cname, crealm)]

	return ce, ok
}

// Instance of the ServiceCache. This needs to be a singleton.
var replayCache Cache

var once sync.Once

// GetReplayCache returns a pointer to the Cache singleton.
func GetReplayCache(d time.Duration) *Cache {
	// Create a singleton of the ReplayCache and start a background thread to regularly clean out old entries.
	once.Do(func() {
		replayCache = Cache{
			entries: make(map[string]clientEntries),
		}

		go func() {
			for {
				// TODO consider using a context here.
				time.Sleep(d)
				replayCache.ClearOldEntries(d)
			}
		}()
	})

	return &replayCache
}

// AddEntry adds an entry to the Cache.
func (c *Cache) AddEntry(sname types.PrincipalName, a types.Authenticator) {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.addEntry(sname, a)
}

// addEntry records an authenticator against its client. The caller must hold the write lock.
func (c *Cache) addEntry(sname types.PrincipalName, a types.Authenticator) {
	ct := a.CTime.Add(time.Duration(a.Cusec) * time.Microsecond)

	ce, ok := c.getClientEntries(a.CName, a.CRealm)
	if !ok {
		ce = clientEntries{replayMap: make(map[time.Time]replayCacheEntry)}
	}

	ce.replayMap[ct] = replayCacheEntry{
		presentedTime: time.Now().UTC(),
		sName:         sname,
		cTime:         ct,
	}
	ce.seqNumber = a.SeqNumber
	ce.subKey = a.SubKey

	// clientEntries is a value, so the sequence number and subkey above are set on a copy of it. Storing it back
	// is what makes them observable; the replay map alone survives without this because a map is a reference.
	c.entries[clientKey(a.CName, a.CRealm)] = ce
}

// ClearOldEntries clears entries from the Cache that are older than the duration provided.
func (c *Cache) ClearOldEntries(d time.Duration) {
	c.mux.Lock()
	defer c.mux.Unlock()

	for ke, ce := range c.entries {
		for k, e := range ce.replayMap {
			if time.Now().UTC().Sub(e.presentedTime) > d {
				delete(ce.replayMap, k)
			}
		}

		if len(ce.replayMap) == 0 {
			delete(c.entries, ke)
		}
	}
}

// IsReplay tests if the Authenticator provided is a replay within the duration defined. If this is not a replay
// the entry is added to the cache for tracking.
func (c *Cache) IsReplay(sname types.PrincipalName, a types.Authenticator) bool {
	ct := a.CTime.Add(time.Duration(a.Cusec) * time.Microsecond)

	c.mux.Lock()
	defer c.mux.Unlock()

	if ce, ok := c.getClientEntries(a.CName, a.CRealm); ok {
		if e, ok := ce.replayMap[ct]; ok && e.sName.Equal(sname) {
			return true
		}
	}

	c.addEntry(sname, a)

	return false
}
