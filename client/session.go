package client

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// sessions hold TGTs and are keyed on the realm name.
type sessions struct {
	Entries map[string]*session
	mux     sync.RWMutex
}

// destroy erases all sessions.
func (s *sessions) destroy() {
	s.mux.Lock()
	defer s.mux.Unlock()

	for k, e := range s.Entries {
		e.destroy()
		delete(s.Entries, k)
	}
}

// update replaces a session with the one provided or adds it as a new one.
func (s *sessions) update(sess *session) {
	s.mux.Lock()
	defer s.mux.Unlock()
	// if a session already exists for this, cancel its auto renew.
	if i, ok := s.Entries[sess.realm]; ok {
		if i != sess {
			// Session in the sessions cache is not the same as one provided.
			// Cancel the one in the cache and add this one.
			i.mux.Lock()
			defer i.mux.Unlock()

			if i.cancel != nil {
				i.cancel <- true
			}

			s.Entries[sess.realm] = sess

			return
		}
	}
	// No session for this realm was found so just add it.
	s.Entries[sess.realm] = sess
}

// get returns the session for the realm specified.
func (s *sessions) get(realm string) (*session, bool) {
	s.mux.RLock()
	defer s.mux.RUnlock()

	sess, ok := s.Entries[realm]

	return sess, ok
}

// session holds the TGT details for a realm.
type session struct {
	realm                string
	authTime             time.Time
	endTime              time.Time
	renewTill            time.Time
	tgt                  messages.Ticket
	sessionKey           types.EncryptionKey
	sessionKeyExpiration time.Time
	flags                asn1.BitString
	addresses            types.HostAddresses
	supportedETypes      types.SupportedETypes
	cancel               chan bool
	mux                  sync.RWMutex
}

// jsonSession is used to enable marshaling some information of a session in a JSON format.
type jsonSession struct {
	Realm                string
	AuthTime             time.Time
	EndTime              time.Time
	RenewTill            time.Time
	SessionKeyExpiration time.Time
}

// AddSession adds a session for a realm with a TGT to the client's session cache.
// A goroutine is started to automatically renew the TGT before expiry.
func (cl *Client) addSession(tgt messages.Ticket, dep messages.EncKDCRepPart) {
	if len(tgt.SName.NameString) == 0 || strings.ToLower(tgt.SName.NameString[0]) != "krbtgt" {
		// Not a TGT.
		return
	}

	realm := tgt.SName.NameString[len(tgt.SName.NameString)-1]
	s := &session{
		realm:                realm,
		authTime:             dep.AuthTime,
		endTime:              dep.EndTime,
		renewTill:            dep.RenewTill,
		tgt:                  tgt,
		sessionKey:           dep.Key,
		sessionKeyExpiration: dep.KeyExpiration,
		flags:                dep.Flags,
		supportedETypes:      types.SupportedETypesFromPAData(dep.EncPAData),
		addresses:            types.HostAddresses(dep.CAddr),
	}
	cl.sessions.update(s)
	cl.enableAutoSessionRenewal(s)
	cl.Log("TGT session added for %s (EndTime: %v)", realm, dep.EndTime)
}

// update overwrites the session details with those from the TGT and decrypted encPart.
func (s *session) update(tgt messages.Ticket, dep messages.EncKDCRepPart) {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.authTime = dep.AuthTime
	s.endTime = dep.EndTime
	s.renewTill = dep.RenewTill
	s.tgt = tgt
	s.sessionKey = dep.Key
	s.sessionKeyExpiration = dep.KeyExpiration
	s.flags = dep.Flags
	s.supportedETypes = types.SupportedETypesFromPAData(dep.EncPAData)
	s.addresses = types.HostAddresses(dep.CAddr)
}

// destroy will cancel any auto renewal of the session and set the expiration times to the current time.
func (s *session) destroy() {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.cancel != nil {
		s.cancel <- true
	}

	s.endTime = time.Now().UTC()
	s.renewTill = s.endTime
	s.sessionKeyExpiration = s.endTime
}

// valid informs if the TGT is still within the valid time window.
func (s *session) valid() bool {
	s.mux.RLock()
	defer s.mux.RUnlock()

	t := time.Now().UTC()
	if t.Before(s.endTime) && s.authTime.Before(t) {
		return true
	}

	return false
}

// tgtDetails is a thread safe way to get the session's realm, TGT and session key values.
func (s *session) tgtDetails() (string, messages.Ticket, types.EncryptionKey) {
	s.mux.RLock()
	defer s.mux.RUnlock()

	return s.realm, s.tgt, s.sessionKey
}

// timeDetails is a thread safe way to get the session's validity time values.
func (s *session) timeDetails() (string, time.Time, time.Time, time.Time, time.Time) {
	s.mux.RLock()
	defer s.mux.RUnlock()

	return s.realm, s.authTime, s.endTime, s.renewTill, s.sessionKeyExpiration
}

// forwardable reports whether the session's TGT has the FORWARDABLE flag set. RFC 4120 Section 3.3 makes the
// FORWARDED KDC option honoured "only if the FORWARDABLE flag is set in the TGT", so a TGT without it cannot be
// forwarded and the KDC would answer KDC_ERR_BADOPTION.
func (s *session) forwardable() bool {
	s.mux.RLock()
	defer s.mux.RUnlock()

	return types.IsFlagSet(&s.flags, flags.Forwardable)
}

// addressed reports whether the session's TGT carries host addresses. A forwarding request supplies addresses only
// when the source TGT has them, matching MIT's krb5_fwd_tgt_creds; with this library's NoAddresses default it does
// not, and the forwarded ticket is addressless as RFC 4120 Section 2.6 permits.
func (s *session) addressed() bool {
	s.mux.RLock()
	defer s.mux.RUnlock()

	return len(s.addresses) > 0
}

// supported returns the encryption types the KDC advertised in the PA-SUPPORTED-ENCTYPES pre-authentication data
// of its reply, or zero if it advertised none. MS-KILE Section 3.3.5.7.4 has a client requesting a forwardable TGT
// build its own PA-SUPPORTED-ENCTYPES from the types the KDC and the application server both support, and this is
// the KDC half of that.
func (s *session) supported() types.SupportedETypes {
	s.mux.RLock()
	defer s.mux.RUnlock()

	return s.supportedETypes
}

// JSON return information about the held sessions in a JSON format.
func (s *sessions) JSON() (string, error) {
	s.mux.RLock()
	defer s.mux.RUnlock()

	keys := make([]string, 0, len(s.Entries))
	for k := range s.Entries {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	js := make([]jsonSession, len(keys))

	for i, k := range keys {
		r, at, et, rt, kt := s.Entries[k].timeDetails()
		j := jsonSession{
			Realm:                r,
			AuthTime:             at,
			EndTime:              et,
			RenewTill:            rt,
			SessionKeyExpiration: kt,
		}

		js[i] = j
	}

	b, err := json.MarshalIndent(js, "", "  ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// enableAutoSessionRenewal turns on the automatic renewal for the client's TGT session.
func (cl *Client) enableAutoSessionRenewal(s *session) {
	var timer *time.Timer

	s.mux.Lock()
	s.cancel = make(chan bool, 1)
	s.mux.Unlock()

	go func(s *session) {
		for {
			s.mux.RLock()
			w := (s.endTime.Sub(time.Now().UTC()) * 5) / 6
			s.mux.RUnlock()

			if w < 0 {
				return
			}

			timer = time.NewTimer(w)
			select {
			case <-timer.C:
				renewal, err := cl.refreshSession(s)
				if err != nil {
					cl.Log("error refreshing session: %v", err)
				}

				if !renewal && err == nil {
					// end this goroutine as there will have been a new login and new auto renewal goroutine created.
					return
				}
			case <-s.cancel:
				// cancel has been called. Stop the timer and exit.
				timer.Stop()
				return
			}
		}
	}(s)
}

// renewTGT renews the client's TGT session.
func (cl *Client) renewTGT(s *session) error {
	realm, tgt, skey := s.tgtDetails()
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	_, tgsRep, err := cl.TGSREQGenerateAndExchange(spn, cl.Credentials.Domain(), tgt, skey, true)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "error renewing TGT for %s", realm)
	}

	s.update(tgsRep.Ticket, tgsRep.DecryptedEncPart)
	cl.sessions.update(s)
	cl.Log("TGT session renewed for %s (EndTime: %v)", realm, tgsRep.DecryptedEncPart.EndTime)

	return nil
}

// refreshSession updates either through renewal or creating a new login.
// The boolean indicates if the update was a renewal.
func (cl *Client) refreshSession(s *session) (bool, error) {
	s.mux.RLock()
	realm := s.realm
	renewTill := s.renewTill
	s.mux.RUnlock()
	cl.Log("refreshing TGT session for %s", realm)

	if time.Now().UTC().Before(renewTill) {
		err := cl.renewTGT(s)
		return true, err
	}

	err := cl.realmLogin(realm)

	return false, err
}

// ensureValidSession makes sure there is a valid session for the realm.
func (cl *Client) ensureValidSession(realm string) error {
	s, ok := cl.sessions.get(realm)
	if ok {
		s.mux.RLock()

		d := s.endTime.Sub(s.authTime) / 6
		if s.endTime.Sub(time.Now().UTC()) > d {
			s.mux.RUnlock()
			return nil
		}

		s.mux.RUnlock()
		_, err := cl.refreshSession(s)

		return err
	}

	return cl.realmLogin(realm)
}

// sessionTGTDetails is a thread safe way to get the TGT and session key values for a realm.
func (cl *Client) sessionTGT(realm string) (tgt messages.Ticket, sessionKey types.EncryptionKey, err error) {
	err = cl.ensureValidSession(realm)
	if err != nil {
		return tgt, sessionKey, err
	}

	s, ok := cl.sessions.get(realm)
	if !ok {
		return tgt, sessionKey, fmt.Errorf("could not find TGT session for %s", realm)
	}

	_, tgt, sessionKey = s.tgtDetails()

	return
}

// sessionTimes provides the timing information with regards to a session for the realm specified.
func (cl *Client) sessionTimes(realm string) (authTime, endTime, renewTime, sessionExp time.Time, err error) {
	s, ok := cl.sessions.get(realm)
	if !ok {
		return authTime, endTime, renewTime, sessionExp, fmt.Errorf("could not find TGT session for %s", realm)
	}

	_, authTime, endTime, renewTime, sessionExp = s.timeDetails()

	return authTime, endTime, renewTime, sessionExp, nil
}

// spnRealm resolves the realm name of a service principal name.
func (cl *Client) spnRealm(spn types.PrincipalName) string {
	return cl.Config.ResolveRealm(spn.NameString[len(spn.NameString)-1])
}
