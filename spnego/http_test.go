package spnego

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/go-krb5/x/identity"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/test/testdata"
)

func TestClient_SetSPNEGOHeader(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	l := log.New(os.Stderr, "SPNEGO Client:", log.LstdFlags)
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c, client.Logger(l))

	require.NoError(t, cl.Login())

	urls := []string{
		"http://cname.test.gokrb5",
		"http://host.test.gokrb5",
	}

	paths := []string{
		"/modkerb/index.html",
		// "/modgssapi/index.html",.
	}
	for _, url := range urls {
		for _, p := range paths {
			r, _ := http.NewRequest(http.MethodGet, url+p, nil)

			httpResp, err := http.DefaultClient.Do(r)
			require.NoError(t, err)

			assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode)

			require.NoError(t, SetSPNEGOHeader(cl, r, ""))

			httpResp, err = http.DefaultClient.Do(r)
			require.NoError(t, err)

			assert.Equal(t, http.StatusOK, httpResp.StatusCode)
		}
	}
}

func TestSPNEGOHTTPClient(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	l := log.New(os.Stderr, "SPNEGO Client:", log.LstdFlags)
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c, client.Logger(l))

	require.NoError(t, cl.Login())

	urls := []string{
		"http://cname.test.gokrb5",
		"http://host.test.gokrb5",
	}

	paths := []string{
		"/modgssapi", "/modgssapi",
		"/redirect",
	}
	for _, url := range urls {
		for _, p := range paths {
			r, _ := http.NewRequest(http.MethodGet, url+p, nil)
			httpCl := http.DefaultClient
			httpCl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				t.Logf("http client redirect: %+v", *req)
				return nil
			}
			spnegoCl := NewClient(cl, httpCl, "")

			httpResp, err := spnegoCl.Do(r)
			require.NoError(t, err)

			assert.Equal(t, http.StatusOK, httpResp.StatusCode)
		}
	}
}

func TestService_SPNEGOKRB_NoAuthHeader(t *testing.T) {
	s := httpServer(t)
	defer s.Close()

	r, _ := http.NewRequest(http.MethodGet, s.URL, nil)

	httpResp, err := http.DefaultClient.Do(r)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode)
	assert.Equal(t, "Negotiate", httpResp.Header.Get("WWW-Authenticate"))
}

func TestService_SPNEGOKRB_ValidUser(t *testing.T) {
	test.Integration(t)

	s := httpServer(t)
	defer s.Close()

	r, _ := http.NewRequest(http.MethodGet, s.URL, nil)

	cl := getClient(t)

	require.NoError(t, SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5"))

	httpResp, err := http.DefaultClient.Do(r)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, httpResp.StatusCode)
}

func TestService_SPNEGOKRB_ValidUser_RawKRB5Token(t *testing.T) {
	test.Integration(t)

	s := httpServer(t)
	defer s.Close()

	r, _ := http.NewRequest(http.MethodGet, s.URL, nil)

	cl := getClient(t)
	sc := SPNEGOClient(cl, "HTTP/host.test.gokrb5")

	require.NoError(t, sc.AcquireCred())

	st, err := sc.InitSecContext()
	require.NoError(t, err)

	nb := st.(*SPNEGOToken).NegTokenInit.MechTokenBytes
	hs := "Negotiate " + base64.StdEncoding.EncodeToString(nb)
	r.Header.Set(HTTPHeaderAuthRequest, hs)

	httpResp, err := http.DefaultClient.Do(r)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, httpResp.StatusCode)
}

func TestService_SPNEGOKRB_Replay(t *testing.T) {
	test.Integration(t)

	s := httpServerWithoutSessionManager(t)
	defer s.Close()

	r1, _ := http.NewRequest(http.MethodGet, s.URL, nil)

	cl := getClient(t)

	require.NoError(t, SetSPNEGOHeader(cl, r1, "HTTP/host.test.gokrb5"))

	httpResp, err := http.DefaultClient.Do(r1)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, httpResp.StatusCode)

	httpResp, err = http.DefaultClient.Do(r1)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode)

	r2, err := http.NewRequest(http.MethodGet, s.URL, nil)
	require.NoError(t, err)

	require.NoError(t, SetSPNEGOHeader(cl, r2, "HTTP/host.test.gokrb5"))

	httpResp, err = http.DefaultClient.Do(r2)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, httpResp.StatusCode)

	httpResp, err = http.DefaultClient.Do(r1)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode)

	httpResp, err = http.DefaultClient.Do(r2)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode)
}

func TestService_SPNEGOKRB_ReplayCache_Concurrency(t *testing.T) {
	test.Integration(t)

	s := httpServerWithoutSessionManager(t)
	defer s.Close()

	r1, err := http.NewRequest(http.MethodGet, s.URL, nil)
	require.NoError(t, err)

	cl := getClient(t)

	require.NoError(t, SetSPNEGOHeader(cl, r1, "HTTP/host.test.gokrb5"))

	r1h := r1.Header.Get(HTTPHeaderAuthRequest)

	r2, err := http.NewRequest(http.MethodGet, s.URL, nil)
	require.NoError(t, err)

	require.NoError(t, SetSPNEGOHeader(cl, r2, "HTTP/host.test.gokrb5"))

	r2h := r2.Header.Get(HTTPHeaderAuthRequest)

	var wg sync.WaitGroup
	wg.Add(2)

	go httpGet(r1, &wg)
	go httpGet(r2, &wg)

	wg.Wait()

	var wg2 sync.WaitGroup

	noReq := 10
	wg2.Add(noReq * 2)

	for i := 0; i < noReq; i++ {
		rr1, err := http.NewRequest(http.MethodGet, s.URL, nil)
		require.NoError(t, err)

		rr1.Header.Set(HTTPHeaderAuthRequest, r1h)

		rr2, err := http.NewRequest(http.MethodGet, s.URL, nil)
		require.NoError(t, err)

		rr2.Header.Set(HTTPHeaderAuthRequest, r2h)

		go httpGet(rr1, &wg2)
		go httpGet(rr2, &wg2)
	}

	wg2.Wait()
}

func TestService_SPNEGOKRB_Upload(t *testing.T) {
	test.Integration(t)

	s := httpServer(t)
	defer s.Close()

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	fileWriter, err := bodyWriter.CreateFormFile("uploadfile", "testfile.bin")
	require.NoError(t, err)

	data := make([]byte, 10240)
	_, err = rand.Read(data)
	require.NoError(t, err)

	br := bytes.NewReader(data)

	_, err = io.Copy(fileWriter, br)
	require.NoError(t, err)

	bodyWriter.Close()

	r, err := http.NewRequest(http.MethodPost, s.URL, bodyBuf)
	require.NoError(t, err)

	r.Header.Set("Content-Type", bodyWriter.FormDataContentType())

	cl := getClient(t)
	cookieJar, _ := cookiejar.New(nil)
	httpCl := http.DefaultClient
	httpCl.Jar = cookieJar
	spnegoCl := NewClient(cl, httpCl, "HTTP/host.test.gokrb5")

	httpResp, err := spnegoCl.Do(r)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, httpResp.StatusCode)
}

func httpGet(r *http.Request, wg *sync.WaitGroup) {
	defer wg.Done()

	http.DefaultClient.Do(r)
}

func httpServerWithoutSessionManager(t *testing.T) *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service Tests: ", log.LstdFlags)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(SPNEGOKRB5Authenticate(th, kt, service.Logger(l)))

	return s
}

func httpServer(t *testing.T) *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service Tests: ", log.LstdFlags)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(SPNEGOKRB5Authenticate(th, kt, service.Logger(l), service.SessionManager(NewSessionMgr("krb5"))))

	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		maxUploadSize := int64(11240)
		if err := r.ParseMultipartForm(maxUploadSize); err != nil {
			http.Error(w, fmt.Sprintf("cannot parse multipart form: %v", err), http.StatusBadRequest)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

		file, _, err := r.FormFile("uploadfile")
		if err != nil {
			http.Error(w, "INVALID_FILE", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// write out to /dev/null.
		_, err = io.Copy(io.Discard, file)
		if err != nil {
			http.Error(w, "WRITE_ERR", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)

	id := identity.FromHTTPRequestContext(r)
	fmt.Fprintf(w, "<html>\nTEST.GOKRB5 Handler\nAuthenticed user: %s\nUser's realm: %s\n</html>",
		id.UserName(),
		id.Domain())
}

func getClient(t *testing.T) *client.Client {
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	c, _ := config.NewFromString(testdata.KRB5_CONF)
	c.LibDefaults.NoAddresses = true

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}

	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	c.Realms[0].KPasswdServer = []string{addr + ":464"}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	return cl
}

type SessionMgr struct {
	skey       []byte
	store      sessions.Store
	cookieName string
}

func NewSessionMgr(cookieName string) SessionMgr {
	skey := []byte("thisistestsecret") // Best practice is to load this key from a secure location.

	return SessionMgr{
		skey:       skey,
		store:      sessions.NewCookieStore(skey),
		cookieName: cookieName,
	}
}

func (smgr SessionMgr) Get(r *http.Request, k any) ([]byte, error) {
	s, err := smgr.store.Get(r, smgr.cookieName)
	if err != nil {
		return nil, err
	}

	if s == nil {
		return nil, errors.New("nil session")
	}

	b, ok := s.Values[k].([]byte)
	if !ok {
		return nil, fmt.Errorf("could not get bytes held in session at %s", k)
	}

	return b, nil
}

func (smgr SessionMgr) New(w http.ResponseWriter, r *http.Request, k any, v []byte) error {
	s, err := smgr.store.New(r, smgr.cookieName)
	if err != nil {
		return fmt.Errorf("could not get new session from session manager: %v", err)
	}

	s.Values[k] = v

	return s.Save(r, w)
}
