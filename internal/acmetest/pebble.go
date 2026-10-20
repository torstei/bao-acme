// SPDX-License-Identifier: MPL-2.0

// Package acmetest runs Pebble, Let's Encrypt's test ACME server, inside the
// test process.
package acmetest

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
)

// Options configure the server. The zero value needs no EAB.
type Options struct {
	RequireEAB bool
	// EABKeys maps key IDs to base64url HMAC keys the server accepts.
	EABKeys map[string]string
	// Log, when set, receives Pebble's log.
	Log io.Writer
	// Resolver, as host:port, is where Pebble looks up DNS-01 records.
	Resolver string
	// KeepNoContact leaves the contact out of account responses, as Let's
	// Encrypt does.
	KeepNoContact bool
	// RefuseReplaces, when set, answers every new order that names a
	// certificate it replaces with a problem of this type, such as
	// "urn:ietf:params:acme:error:serverInternal".
	RefuseReplaces string
}

// Pebble is a running server.
type Pebble struct {
	// DirectoryURL is the ACME directory.
	DirectoryURL string
	// CA is the server's TLS certificate, to be trusted by clients.
	CA *x509.Certificate
	// CAPEM is CA as PEM.
	CAPEM string

	contactUpdates  atomic.Int32
	refusedReplaces atomic.Int32
	ordersPlaced    atomic.Int32
}

// RefusedReplaces counts new orders refused for naming a certificate they
// replace.
func (p *Pebble) RefusedReplaces() int {
	return int(p.refusedReplaces.Load())
}

// OrdersPlaced counts new orders the server accepted.
func (p *Pebble) OrdersPlaced() int {
	return int(p.ordersPlaced.Load())
}

// ContactUpdates counts requests that changed an existing account's
// contact.
func (p *Pebble) ContactUpdates() int {
	return int(p.contactUpdates.Load())
}

// Start runs Pebble until the test ends.
func Start(t testing.TB, opts Options) *Pebble {
	t.Helper()
	// Pebble rejects a share of nonces by default to exercise client retries,
	// and waits before each validation.
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")

	out := opts.Log
	if out == nil {
		out = io.Discard
	}
	logger := log.New(out, "pebble ", log.LstdFlags)

	store := db.NewMemoryStore()
	authority := ca.New(logger, store, "", "ecdsa", 0, 1, map[string]ca.Profile{
		"default": {Description: "default"},
	})
	validator := va.New(logger, 0, 0, false, opts.Resolver, store)
	for id, key := range opts.EABKeys {
		if err := store.AddExternalAccountKeyByID(id, key); err != nil {
			t.Fatal(err)
		}
	}
	front := wfe.New(logger, store, validator, authority, []string{"pebble.letsencrypt.org"}, false, opts.RequireEAB, 0, 0)

	p := &Pebble{}
	handler := front.Handler()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/order-plz" {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			if opts.RefuseReplaces != "" && jwsHas(body, "replaces") {
				p.refusedReplaces.Add(1)
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"type": opts.RefuseReplaces, "detail": "refused by the test", "status": http.StatusInternalServerError})
				return
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)
			if rec.Code == http.StatusCreated {
				p.ordersPlaced.Add(1)
			}
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/my-account/") && r.URL.Path != "/sign-me-up" {
			handler.ServeHTTP(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if strings.HasPrefix(r.URL.Path, "/my-account/") && jwsHas(body, "contact") {
			p.contactUpdates.Add(1)
		}
		if !opts.KeepNoContact {
			handler.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		out := rec.Body.Bytes()
		var account map[string]any
		if json.Unmarshal(out, &account) == nil {
			delete(account, "contact")
			out, _ = json.Marshal(account)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(out)))
		w.WriteHeader(rec.Code)
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)

	c := srv.Certificate()
	p.DirectoryURL = srv.URL + "/dir"
	p.CA = c
	p.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	return p
}

// jwsHas reports whether a JWS request's payload has field.
func jwsHas(body []byte, field string) bool {
	var jws struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(body, &jws) != nil {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return false
	}
	var fields map[string]any
	if json.Unmarshal(payload, &fields) != nil {
		return false
	}
	_, ok := fields[field]
	return ok
}
