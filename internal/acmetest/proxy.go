// SPDX-License-Identifier: MPL-2.0

package acmetest

import (
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// ProxyOptions configure a test forward proxy.
type ProxyOptions struct {
	// TLS serves the proxy itself over https.
	TLS bool
	// User and Password, when set, are required as proxy credentials.
	User, Password string
}

// Proxy is a forward proxy that tunnels CONNECT requests and records their
// targets. It refuses anything else.
type Proxy struct {
	// URL is the proxy's address, without credentials.
	URL *url.URL
	// CAPEM is the proxy's own TLS certificate when TLS is set.
	CAPEM string

	mu      sync.Mutex
	targets []string
	refused int
}

// StartProxy runs a proxy until the test ends.
func StartProxy(t testing.TB, opts ProxyOptions) *Proxy {
	t.Helper()
	p := &Proxy{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || !p.authorised(r, opts) {
			p.mu.Lock()
			p.refused++
			p.mu.Unlock()
			w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
			http.Error(w, "refused", http.StatusProxyAuthRequired)
			return
		}
		p.mu.Lock()
		p.targets = append(p.targets, r.Host)
		p.mu.Unlock()

		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		client, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() {
			_, _ = io.Copy(upstream, buf)
			upstream.Close()
		}()
		go func() {
			_, _ = io.Copy(client, upstream)
			client.Close()
		}()
	})

	srv := httptest.NewUnstartedServer(handler)
	if opts.TLS {
		srv.EnableHTTP2 = false
		srv.StartTLS()
		p.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p.URL = u
	return p
}

func (p *Proxy) authorised(r *http.Request, opts ProxyOptions) bool {
	if opts.User == "" {
		return true
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(opts.User+":"+opts.Password))
	return r.Header.Get("Proxy-Authorization") == want
}

// Targets are the host:port pairs clients tunnelled to, in order.
func (p *Proxy) Targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

// Refused counts requests the proxy turned away.
func (p *Proxy) Refused() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refused
}
