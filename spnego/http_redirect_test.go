package spnego

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPNEGOHTTPClient_ShouldStopAtARedirectAwayFromTheConfiguredSPNsHost(t *testing.T) {
	var reached atomic.Bool

	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://elsewhere.test/", http.StatusFound)
	}))
	defer origin.Close()

	httpCl := hostRoutingClient(map[string]string{
		hostOrigin:    origin.Listener.Addr().String(),
		hostElsewhere: elsewhere.Listener.Addr().String(),
	})

	spnegoCl := NewClient(nil, httpCl, "HTTP/origin.test")

	resp, err := spnegoCl.Get("http://origin.test/")
	if resp != nil {
		resp.Body.Close()
	}

	require.Error(t, err)
	assert.Contains(t, err.Error(), "elsewhere.test")
	assert.False(t, reached.Load(), "the redirect target must not be sent a ticket minted for another host")
}

func TestSPNEGOHTTPClient_ShouldFollowARedirectWithinTheConfiguredSPNsHost(t *testing.T) {
	var moved atomic.Bool

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			moved.Store(true)
			w.WriteHeader(http.StatusOK)

			return
		}

		http.Redirect(w, r, "/moved", http.StatusFound)
	}))
	defer origin.Close()

	httpCl := hostRoutingClient(map[string]string{hostOrigin: origin.Listener.Addr().String()})

	spnegoCl := NewClient(nil, httpCl, "HTTP/origin.test")

	resp, err := spnegoCl.Get("http://origin.test/")
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, moved.Load(), "a redirect that stays with the configured service must still be followed")
}

func TestSPNEGOHTTPClient_ShouldFollowARedirectToAnotherPortOnTheConfiguredSPNsHost(t *testing.T) {
	var reached atomic.Bool

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://origin.test:9090/", http.StatusFound)
	}))
	defer first.Close()

	httpCl := hostRoutingClient(map[string]string{
		"origin.test:8080": first.Listener.Addr().String(),
		"origin.test:9090": second.Listener.Addr().String(),
	})

	spnegoCl := NewClient(nil, httpCl, "HTTP/origin.test")

	resp, err := spnegoCl.Get("http://origin.test:8080/")
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.True(t, reached.Load(), "another port on the same host is the same service principal")
}

func TestSPNEGOHTTPClient_ShouldFollowACrossHostRedirectWhenNoSPNIsConfigured(t *testing.T) {
	var reached atomic.Bool

	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://elsewhere.test/", http.StatusFound)
	}))
	defer origin.Close()

	httpCl := hostRoutingClient(map[string]string{
		hostOrigin:    origin.Listener.Addr().String(),
		hostElsewhere: elsewhere.Listener.Addr().String(),
	})

	spnegoCl := NewClient(nil, httpCl, "")

	resp, err := spnegoCl.Get("http://origin.test/")
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.True(t, reached.Load(), "a derived SPN follows the host being addressed and is not pinned")
}

func hostRoutingClient(hosts map[string]string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				target, ok := hosts[addr]
				if !ok {
					host, _, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, err
					}

					if target, ok = hosts[host]; !ok {
						return nil, fmt.Errorf("no test server for host %q", host)
					}
				}

				var d net.Dialer

				return d.DialContext(ctx, network, target)
			},
		},
	}
}

const (
	hostOrigin    = "origin.test"
	hostElsewhere = "elsewhere.test"
)
