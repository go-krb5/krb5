// Package service provides server side integrations for Kerberos authentication.
package service

import (
	"fmt"
	"sync"
	"sync/atomic"
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
	replayMap map[replayKey]replayCacheEntry
	seqNumber int64
	subKey    types.EncryptionKey
}

// replayKey identifies one presentation of an authenticator to one service.
//
// RFC 4120 Section 3.2.3 has the cache "store at least the server name, along with the client name, time, and
// microsecond fields from the recently-seen authenticators, and if a matching tuple is found, the KRB_AP_ERR_REPEAT
// error is returned". The client name and realm choose the clientEntries this is looked up in; the rest of that
// tuple is here.
//
// The server name and realm are part of the key rather than of the value. The same section requires that losing
// track of a presentation reject rather than admit; "If a server loses track of authenticators presented within
// the allowable clock skew, it MUST reject all requests until the clock skew interval has passed"; and a value can
// be displaced by the next presentation under a different server name where a key cannot.
type replayKey struct {
	cTime  time.Time
	sName  string
	sRealm string
}

// Cache entry tracking when a presentation was seen, so that ClearOldEntries can retire it.
type replayCacheEntry struct {
	presentedTime time.Time
}

// clientKey identifies the client an entry belongs to.
func clientKey(cname types.PrincipalName, crealm string) string {
	return fmt.Sprintf("%q@%q", cname.PrincipalNameString(), crealm)
}

// newReplayKey identifies the presentation of the authenticator to the service named by sname in srealm.
//
// The name is compared by its components only, as PrincipalName.Equal does, because RFC 4120 Section 6.2 makes the
// name type insignificant when comparing principal names.
func newReplayKey(sname types.PrincipalName, srealm string, a types.Authenticator) replayKey {
	return replayKey{
		cTime:  a.CTime.Add(time.Duration(a.Cusec) * time.Microsecond).UTC(),
		sName:  sname.PrincipalNameString(),
		sRealm: srealm,
	}
}

// getClientEntries returns the entries held for a client. The caller must hold at least the read lock.
func (c *Cache) getClientEntries(cname types.PrincipalName, crealm string) (clientEntries, bool) {
	ce, ok := c.entries[clientKey(cname, crealm)]

	return ce, ok
}

var (
	replayCache     Cache
	once            sync.Once
	janitorInterval atomic.Int64
)

// defaultJanitorInterval is the interval used when a caller asks for a non-positive one. It matches the floor
// Settings.MaxClockSkew applies, because an entry has to outlive the skew it is protecting against.
const defaultJanitorInterval = 5 * time.Minute

// setJanitorInterval raises the janitor's interval to d and returns the interval now in force.
//
// A non-positive d is floored: zero would turn the janitor into a busy loop taking the cache's write lock and
// retiring every entry the moment it was recorded, which is no replay protection at all. The interval only ever
// grows, because the cache is a process-wide singleton and an entry must outlive the clock skew of every service
// sharing it; letting a service with a narrower skew shorten it would retire presentations that are still
// replayable against a service with a wider one.
func setJanitorInterval(d time.Duration) time.Duration {
	if d <= 0 {
		d = defaultJanitorInterval
	}

	for {
		current := janitorInterval.Load()
		if int64(d) <= current {
			return time.Duration(current)
		}

		if janitorInterval.CompareAndSwap(current, int64(d)) {
			return d
		}
	}
}

// GetReplayCache returns a pointer to the Cache singleton.
//
// d is the age at which a presentation is retired, and how often the janitor looks for one to retire. Callers
// share one cache, so the longest duration any of them has asked for is the one in force; see setJanitorInterval.
func GetReplayCache(d time.Duration) *Cache {
	setJanitorInterval(d)

	// Create a singleton of the ReplayCache and start a background thread to regularly clean out old entries.
	once.Do(func() {
		replayCache = Cache{
			entries: make(map[string]clientEntries),
		}

		go func() {
			for {
				// The interval is read each pass rather than captured, so a caller arriving later with a wider
				// clock skew is honoured by the janitor already running.
				d := time.Duration(janitorInterval.Load())

				time.Sleep(d)
				replayCache.ClearOldEntries(d)
			}
		}()
	})

	return &replayCache
}

// AddEntry adds an entry to the Cache, recording that a was presented to the service named by sname in srealm.
//
// sname and srealm must identify the service principal whose key decrypted the ticket, not the service the ticket
// claims in its unencrypted portion; see IsReplay.
func (c *Cache) AddEntry(sname types.PrincipalName, srealm string, a types.Authenticator) {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.addEntry(sname, srealm, a)
}

// addEntry records an authenticator against its client. The caller must hold the write lock.
func (c *Cache) addEntry(sname types.PrincipalName, srealm string, a types.Authenticator) {
	ce, ok := c.getClientEntries(a.CName, a.CRealm)
	if !ok {
		ce = clientEntries{replayMap: make(map[replayKey]replayCacheEntry)}
	}

	ce.replayMap[newReplayKey(sname, srealm, a)] = replayCacheEntry{
		presentedTime: time.Now().UTC(),
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

// IsReplay tests if the Authenticator provided has already been presented to the service named by sname in srealm
// within the duration defined. If this is not a replay the entry is added to the cache for tracking.
//
// sname and srealm must identify the service principal whose key decrypted the ticket the authenticator arrived in,
// which is the ticket's SName and Realm only where those chose the key. A ticket's unencrypted portion is covered
// by no checksum, so keying the cache on what it claims would let a captured AP_REQ be replayed indefinitely by
// rewriting the claim; see service.VerifyAPREQ, which resolves this before calling.
func (c *Cache) IsReplay(sname types.PrincipalName, srealm string, a types.Authenticator) bool {
	k := newReplayKey(sname, srealm, a)

	c.mux.Lock()
	defer c.mux.Unlock()

	if ce, ok := c.getClientEntries(a.CName, a.CRealm); ok {
		if _, ok := ce.replayMap[k]; ok {
			return true
		}
	}

	c.addEntry(sname, srealm, a)

	return false
}
