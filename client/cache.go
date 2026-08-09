package client

import (
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// Cache for service tickets held by the client.
type Cache struct {
	Entries map[string]CacheEntry
	mux     sync.RWMutex
}

// CacheEntry holds details for a cache entry.
type CacheEntry struct {
	SPN        string
	Ticket     messages.Ticket `json:"-"`
	AuthTime   time.Time
	StartTime  time.Time
	EndTime    time.Time
	RenewTill  time.Time
	SessionKey types.EncryptionKey `json:"-"`

	// SupportedETypes are the encryption types the application server advertised in the PA-SUPPORTED-ENCTYPES
	// pre-authentication data of the TGS-REP that issued this ticket, or zero if it advertised none. MS-KILE
	// Section 3.3.5.7.4 has a client requesting a forwardable TGT for that server build its own
	// PA-SUPPORTED-ENCTYPES from what the KDC and that server both support; this is the server half.
	//
	// Excluded from the JSON rendering, like Ticket and SessionKey, so that Client.Diagnostics keeps the output
	// it had before delegation existed.
	SupportedETypes types.SupportedETypes `json:"-"`

	// TicketFlags are the flags the KDC reported for this ticket in the TGS-REP. The client cannot read them from
	// the ticket itself, which is encrypted to the service, so the reply is the only source. Excluded from the
	// JSON rendering for the same reason as the fields above.
	TicketFlags asn1.BitString `json:"-"`
}

// NewCache creates a new client ticket cache instance.
func NewCache() *Cache {
	return &Cache{
		Entries: map[string]CacheEntry{},
	}
}

// getEntry returns a cache entry that matches the SPN.
func (c *Cache) getEntry(spn string) (CacheEntry, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()

	e, ok := c.Entries[spn]

	return e, ok
}

// JSON returns information about the cached service tickets in a JSON format.
func (c *Cache) JSON() (string, error) {
	c.mux.RLock()
	defer c.mux.RUnlock()

	keys := make([]string, 0, len(c.Entries))
	for k := range c.Entries {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	es := make([]CacheEntry, len(keys))

	for i, k := range keys {
		es[i] = c.Entries[k]
	}

	b, err := json.MarshalIndent(&es, "", "  ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// addEntry adds a ticket to the cache.
func (c *Cache) addEntry(tkt messages.Ticket, authTime, startTime, endTime, renewTill time.Time, sessionKey types.EncryptionKey, supported types.SupportedETypes, ticketFlags asn1.BitString) CacheEntry {
	spn := tkt.SName.PrincipalNameString()

	c.mux.Lock()
	defer c.mux.Unlock()

	c.Entries[spn] = CacheEntry{
		SPN:        spn,
		Ticket:     tkt,
		AuthTime:   authTime,
		StartTime:  startTime,
		EndTime:    endTime,
		RenewTill:  renewTill,
		SessionKey: sessionKey,

		SupportedETypes: supported,
		TicketFlags:     ticketFlags,
	}

	return c.Entries[spn]
}

// clear deletes all the cache entries.
func (c *Cache) clear() {
	c.mux.Lock()
	defer c.mux.Unlock()

	for k := range c.Entries {
		delete(c.Entries, k)
	}
}

// RemoveEntry removes the cache entry for the defined SPN.
func (c *Cache) RemoveEntry(spn string) {
	c.mux.Lock()
	defer c.mux.Unlock()

	delete(c.Entries, spn)
}

// GetCachedTicket returns a ticket from the cache for the SPN.
// Only a ticket that is currently valid will be returned.
func (cl *Client) GetCachedTicket(spn string) (messages.Ticket, types.EncryptionKey, bool) {
	if e, ok := cl.cache.getEntry(spn); ok {
		// If within time window of ticket return it.
		if time.Now().UTC().After(e.StartTime) && time.Now().UTC().Before(e.EndTime) {
			cl.Log("ticket received from cache for %s", spn)
			return e.Ticket, e.SessionKey, true
		} else if time.Now().UTC().Before(e.RenewTill) {
			e, err := cl.renewTicket(e)
			if err != nil {
				return e.Ticket, e.SessionKey, false
			}

			return e.Ticket, e.SessionKey, true
		}
	}

	var (
		tkt messages.Ticket
		key types.EncryptionKey
	)

	return tkt, key, false
}

// renewTicket renews a cache entry ticket.
// To renew from outside the client package use GetCachedTicket.
func (cl *Client) renewTicket(e CacheEntry) (CacheEntry, error) {
	spn := e.Ticket.SName

	_, _, err := cl.TGSREQGenerateAndExchange(spn, e.Ticket.Realm, e.Ticket, e.SessionKey, true)
	if err != nil {
		return e, err
	}

	e, ok := cl.cache.getEntry(e.Ticket.SName.PrincipalNameString())
	if !ok {
		return e, errors.New("ticket was not added to cache")
	}

	cl.Log("ticket renewed for %s (EndTime: %v)", spn.PrincipalNameString(), e.EndTime)

	return e, nil
}

// OKAsDelegate reports whether the cached service ticket for the principal given was issued with the
// OK-AS-DELEGATE flag, which RFC 4120 Section 2.8 defines and MS-KILE Section 3.3.1.1 has the KDC set when the
// service account is trusted for delegation.
//
// A ticket that is not cached reports false. The flag gates handing a service the client's whole identity, so an
// unknown answer is treated as a refusal rather than as permission.
func (cl *Client) OKAsDelegate(spn types.PrincipalName) bool {
	e, ok := cl.cache.getEntry(spn.PrincipalNameString())
	if !ok {
		return false
	}

	return types.IsFlagSet(&e.TicketFlags, flags.OKAsDelegate)
}
