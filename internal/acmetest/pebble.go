// SPDX-License-Identifier: MPL-2.0

// Package acmetest runs Pebble, Let's Encrypt's test ACME server, inside the
// test process.
package acmetest

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net/http/httptest"
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
}

// Pebble is a running server.
type Pebble struct {
	// DirectoryURL is the ACME directory.
	DirectoryURL string
	// CA is the server's TLS certificate, to be trusted by clients.
	CA *x509.Certificate
	// CAPEM is CA as PEM.
	CAPEM string
}

// Start runs Pebble until the test ends.
func Start(t testing.TB, opts Options) *Pebble {
	t.Helper()
	// Pebble rejects a share of nonces by default to exercise client retries.
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0")

	out := opts.Log
	if out == nil {
		out = io.Discard
	}
	logger := log.New(out, "pebble ", log.LstdFlags)

	store := db.NewMemoryStore()
	authority := ca.New(logger, store, "", "ecdsa", 0, 1, map[string]ca.Profile{
		"default": {Description: "default"},
	})
	validator := va.New(logger, 0, 0, false, "", store)
	for id, key := range opts.EABKeys {
		if err := store.AddExternalAccountKeyByID(id, key); err != nil {
			t.Fatal(err)
		}
	}
	front := wfe.New(logger, store, validator, authority, []string{"pebble.letsencrypt.org"}, false, opts.RequireEAB, 0, 0)

	srv := httptest.NewTLSServer(front.Handler())
	t.Cleanup(srv.Close)

	c := srv.Certificate()
	return &Pebble{
		DirectoryURL: srv.URL + "/dir",
		CA:           c,
		CAPEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
	}
}
