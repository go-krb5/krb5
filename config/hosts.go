package config

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/go-krb5/x/dns"
)

// GetKDCs returns the count of KDCs available and a map of KDC host names keyed on preference order.
func (c *Config) GetKDCs(realm string, tcp bool) (int, map[int]string, error) {
	if realm == "" {
		realm = c.LibDefaults.DefaultRealm
	}

	kdcs := make(map[int]string)

	var count int

	var ks []string

	for _, r := range c.Realms {
		if r.Realm != realm {
			continue
		}

		ks = r.KDC
	}

	count = len(ks)

	if count > 0 {
		kdcs = randServOrder(ks)
		return count, kdcs, nil
	}

	if !c.LibDefaults.DNSLookupKDC {
		return count, kdcs, fmt.Errorf("no KDCs defined in configuration for realm %s", realm)
	}

	proto := protoUDP
	if tcp {
		proto = protoTCP
	}

	index, addrs, err := dns.OrderedSRV(svcKerberos, proto, realm)
	if err != nil {
		return count, kdcs, err
	}

	if len(addrs) < 1 {
		return count, kdcs, fmt.Errorf("no KDC SRV records found for realm %s", realm)
	}

	count = index

	for k, v := range addrs {
		kdcs[k] = strings.TrimRight(v.Target, ".") + ":" + strconv.Itoa(int(v.Port))
	}

	return count, kdcs, nil
}

// GetKpasswdServers returns the count of kpasswd servers available and a map of kpasswd host names keyed on preference
// order.
//
// See Also: https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html#realms.
func (c *Config) GetKpasswdServers(realm string, tcp bool) (int, map[int]string, error) {
	var (
		explicit []string
		admin    []string
	)

	for _, r := range c.Realms {
		if r.Realm != realm {
			continue
		}

		if r.kpasswdFromAdmin {
			admin = r.KPasswdServer
		} else {
			explicit = r.KPasswdServer
		}

		if len(admin) == 0 {
			for _, a := range r.AdminServer {
				if host, _, err := splitHostPort(a); err == nil && host != "" {
					admin = append(admin, net.JoinHostPort(host, strconv.Itoa(portKpasswd)))
				}
			}
		}

		break
	}

	proto := protoUDP
	if tcp {
		proto = protoTCP
	}

	// MIT krb5 looks for kpasswd servers in the configuration and then in DNS, and only where neither lists any does
	// it use the admin servers, again from the configuration and then from DNS, with the kpasswd port in place of
	// theirs.
	if len(explicit) > 0 {
		return len(explicit), randServOrder(explicit), nil
	}

	if c.LibDefaults.DNSLookupKDC {
		if n, servers := srvServers(svcKerberosPassword, proto, realm, 0); n > 0 {
			return n, servers, nil
		}
	}

	if len(admin) > 0 {
		return len(admin), randServOrder(admin), nil
	}

	if c.LibDefaults.DNSLookupKDC {
		if n, servers := srvServers(svcKerberosAdmin, proto, realm, portKpasswd); n > 0 {
			return n, servers, nil
		}
	}

	return 0, make(map[int]string), fmt.Errorf("no kpasswd or kadmin servers found for realm %s", realm)
}

func srvServers(service, proto, realm string, port int) (int, map[int]string) {
	servers := make(map[int]string)

	n, addrs, err := dns.OrderedSRV(service, proto, realm)
	if err != nil || len(addrs) == 0 {
		return 0, servers
	}

	for k, v := range addrs {
		p := int(v.Port)
		if port != 0 {
			p = port
		}

		servers[k] = net.JoinHostPort(strings.TrimRight(v.Target, "."), strconv.Itoa(p))
	}

	return n, servers
}

// randServOrder returns the servers keyed by a randomised preference order.
//
// The shuffle works on a copy. The slice a caller passes is the Config's own, and a *Config is documented as
// shareable between clients with every exchange calling GetKDCs, so permuting it in place would both reorder the
// configured servers permanently and race with any concurrent call reading the same array.
func randServOrder(ks []string) map[int]string {
	ks = append([]string(nil), ks...)

	kdcs := make(map[int]string)
	count := len(ks)
	i := 1

	if count > 1 {
		l := len(ks)
		for l > 0 {
			ri := rand.Intn(l)

			kdcs[i] = ks[ri]
			if l > 1 {
				// Remove the entry from the source slice by swapping with the last entry and truncating.
				ks[len(ks)-1], ks[ri] = ks[ri], ks[len(ks)-1]
				ks = ks[:len(ks)-1]
				l = len(ks)
			} else {
				l = 0
			}

			i++
		}
	} else {
		kdcs[i] = ks[0]
	}

	return kdcs
}
