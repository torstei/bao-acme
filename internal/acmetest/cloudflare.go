// SPDX-License-Identifier: MPL-2.0

package acmetest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// Cloudflare fakes the parts of the Cloudflare API that lego and the engine
// use, publishing records into a test DNS server.
type Cloudflare struct {
	mu      sync.Mutex
	srv     *httptest.Server
	dns     *DNS
	records map[string]cloudflareRecord
	nextID  int
}

type cloudflareRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
}

// StartCloudflare serves zone, with records going into d, accepting only
// the API token.
func StartCloudflare(t testing.TB, d *DNS, zone, token string) *Cloudflare {
	t.Helper()
	f := &Cloudflare{dns: d, records: map[string]cloudflareRecord{}, nextID: 1}
	const zoneID = "zone1"
	reply := func(w http.ResponseWriter, result any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/v4/zones", func(w http.ResponseWriter, r *http.Request) {
		zones := []map[string]string{}
		if dns.Fqdn(r.URL.Query().Get("name")) == dns.Fqdn(zone) {
			zones = append(zones, map[string]string{"id": zoneID, "name": zone})
		}
		reply(w, zones)
	})
	mux.HandleFunc("GET /client/v4/zones/"+zoneID+"/dns_records", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		defer f.mu.Unlock()
		list := []cloudflareRecord{}
		for _, rec := range f.records {
			if (q.Get("type") == "" || q.Get("type") == rec.Type) && (q.Get("name") == "" || q.Get("name") == rec.Name) {
				list = append(list, rec)
			}
		}
		reply(w, list)
	})
	mux.HandleFunc("POST /client/v4/zones/"+zoneID+"/dns_records", func(w http.ResponseWriter, r *http.Request) {
		var rec cloudflareRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil || rec.Type != "TXT" {
			http.Error(w, "bad record", http.StatusBadRequest)
			return
		}
		reply(w, f.add(rec))
	})
	mux.HandleFunc("DELETE /client/v4/zones/"+zoneID+"/dns_records/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		rec, ok := f.records[r.PathValue("id")]
		delete(f.records, rec.ID)
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		d.DeleteTXT(rec.Name, unquote(rec.Content))
		reply(w, map[string]string{"id": rec.ID})
	})

	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`, http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *Cloudflare) add(rec cloudflareRecord) cloudflareRecord {
	f.mu.Lock()
	rec.ID = "rec" + strconv.Itoa(f.nextID)
	f.nextID++
	f.records[rec.ID] = rec
	f.mu.Unlock()
	f.dns.SetTXT(rec.Name, unquote(rec.Content))
	return rec
}

// Add stores a TXT record that someone else made, its content quoted the
// way Cloudflare shows it.
func (f *Cloudflare) Add(name, value string) {
	f.add(cloudflareRecord{Type: "TXT", Name: name, Content: strconv.Quote(value)})
}

// Client returns an HTTP client that sends requests for api.cloudflare.com
// to the fake, and fails any other request.
func (f *Cloudflare) Client() *http.Client {
	return redirectClient("api.cloudflare.com", f.srv.URL)
}

// Records returns the TXT records the fake holds, as name=content.
func (f *Cloudflare) Records() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, rec := range f.records {
		out = append(out, rec.Name+"="+rec.Content)
	}
	return out
}

func unquote(s string) string {
	if u, err := strconv.Unquote(s); err == nil {
		return u
	}
	return s
}
