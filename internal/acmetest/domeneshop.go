// SPDX-License-Identifier: MPL-2.0

package acmetest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
)

// Domeneshop fakes the parts of the Domeneshop API that lego uses, publishing
// records into a test DNS server.
type Domeneshop struct {
	// Requests counts calls that passed authentication.
	Requests int

	mu      sync.Mutex
	srv     *httptest.Server
	dns     *DNS
	zone    string
	records map[int]record
	nextID  int
}

type record struct {
	ID   int    `json:"id"`
	Host string `json:"host"`
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

// StartDomeneshop serves zone, with records going into d, accepting only
// token and secret.
func StartDomeneshop(t testing.TB, d *DNS, zone, token, secret string) *Domeneshop {
	t.Helper()
	f := &Domeneshop{records: map[int]record{}, nextID: 1, dns: d, zone: zone}
	const domainID = 1

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v0/domains", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"domain": zone, "id": domainID, "services": map[string]any{"dns": true}},
		})
	})
	mux.HandleFunc("GET /v0/domains/1/dns", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		list := []record{}
		for _, rec := range f.records {
			list = append(list, rec)
		}
		_ = json.NewEncoder(w).Encode(list)
	})
	mux.HandleFunc("POST /v0/domains/1/dns", func(w http.ResponseWriter, r *http.Request) {
		var rec record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil || rec.Type != "TXT" {
			http.Error(w, "bad record", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		rec.ID = f.nextID
		f.nextID++
		f.records[rec.ID] = rec
		f.mu.Unlock()
		d.SetTXT(rec.Host+"."+zone, rec.Data)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]int{"id": rec.ID})
	})
	mux.HandleFunc("DELETE /v0/domains/1/dns/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		f.mu.Lock()
		rec, ok := f.records[id]
		delete(f.records, id)
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		d.DeleteTXT(rec.Host+"."+zone, rec.Data)
		w.WriteHeader(http.StatusNoContent)
	})

	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != token || pass != secret {
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		f.Requests++
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// Client returns an HTTP client that sends requests for api.domeneshop.no
// to the fake, and fails any other request.
func (f *Domeneshop) Client() *http.Client {
	return redirectClient("api.domeneshop.no", f.srv.URL)
}

// Add stores a TXT record that someone else made, as host=data relative to
// the zone.
func (f *Domeneshop) Add(host, data string) {
	f.mu.Lock()
	rec := record{ID: f.nextID, Host: host, Type: "TXT", Data: data}
	f.nextID++
	f.records[rec.ID] = rec
	f.mu.Unlock()
	f.dns.SetTXT(host+"."+f.zone, data)
}

// Records returns the TXT records the fake holds, as host=data.
func (f *Domeneshop) Records() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, rec := range f.records {
		out = append(out, rec.Host+"="+rec.Data)
	}
	return out
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// redirectClient sends requests for host to the server at serverURL, and
// fails any other request.
func redirectClient(host, serverURL string) *http.Client {
	target, _ := url.Parse(serverURL)
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != host {
			return nil, &url.Error{Op: r.Method, URL: r.URL.String(), Err: fmt.Errorf("request to a host other than %s", host)}
		}
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		r.Host = target.Host
		return http.DefaultTransport.RoundTrip(r)
	})}
}
