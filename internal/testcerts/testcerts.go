// SPDX-License-Identifier: MPL-2.0

// Package testcerts generates throwaway certificate chains for tests.
package testcerts

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// Options describe the leaf certificate. Zero values give a P-256 leaf for
// "example.com" valid from an hour ago for 90 days.
type Options struct {
	Names     []string
	NotBefore time.Time
	NotAfter  time.Time
	RSABits   int
	// Key, when set, is reused instead of generating one.
	Key crypto.Signer
}

// Chain is a leaf, an intermediate and a root, each signed by the next.
type Chain struct {
	Fullchain string
	Privkey   string
	Root      *x509.Certificate
	Key       crypto.Signer
}

// New returns a fresh chain. Each call creates a new root and intermediate.
func New(t testing.TB, opts Options) Chain {
	t.Helper()
	if len(opts.Names) == 0 {
		opts.Names = []string{"example.com"}
	}
	if opts.NotBefore.IsZero() {
		opts.NotBefore = time.Now().Add(-time.Hour)
	}
	if opts.NotAfter.IsZero() {
		opts.NotAfter = opts.NotBefore.Add(90 * 24 * time.Hour)
	}

	rootKey := ecKey(t)
	root := sign(t, &x509.Certificate{
		Subject:               pkix.Name{Organization: []string{"Test CA"}, CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, rootKey, rootKey)

	intKey := ecKey(t)
	intermediate := sign(t, &x509.Certificate{
		Subject:               pkix.Name{Organization: []string{"Test CA"}, CommonName: "T1"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, root, intKey, rootKey)

	leafKey := opts.Key
	if leafKey == nil {
		if opts.RSABits > 0 {
			k, err := rsa.GenerateKey(rand.Reader, opts.RSABits)
			if err != nil {
				t.Fatal(err)
			}
			leafKey = k
		} else {
			leafKey = ecKey(t)
		}
	}
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: strings.TrimPrefix(opts.Names[0], "*.")},
		NotBefore:   opts.NotBefore,
		NotAfter:    opts.NotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range opts.Names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	leaf := sign(t, tmpl, intermediate, leafKey, intKey)

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return Chain{
		Fullchain: encode(leaf) + encode(intermediate),
		Privkey:   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		Root:      root,
		Key:       leafKey,
	}
}

func ecKey(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t testing.TB, tmpl, parent *x509.Certificate, key, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = serial
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func encode(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}
