// SPDX-License-Identifier: MPL-2.0

// Package cert parses, validates and describes PEM certificate chains and
// their private keys.
package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Bundle is a validated certificate chain with its private key.
type Bundle struct {
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
	Key           crypto.Signer

	// Re-encoded from the parsed values, so stored PEM does not depend on the
	// writer's formatting and keys are always PKCS #8.
	CertPEM  string
	ChainPEM string
	KeyPEM   string
}

// Description is what the engine says about a certificate. It is derived
// from the certificate alone, never supplied by the writer.
type Description struct {
	Names      []string  `json:"names"`
	CommonName string    `json:"common_name"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Serial     string    `json:"serial"`
	Issuer     string    `json:"issuer"`
	SHA256     string    `json:"sha256"`
	SPKISHA256 string    `json:"spki_sha256"`
	KeyType    string    `json:"key_type"`
}

// Parse decodes a fullchain (leaf first) and a private key, and checks that
// they belong together, that each certificate is signed by the next, and
// that the leaf is valid at now.
func Parse(fullchain, privkey string, now time.Time) (*Bundle, error) {
	certs, err := parseCertificates(fullchain)
	if err != nil {
		return nil, fmt.Errorf("fullchain: %w", err)
	}
	key, err := parsePrivateKey(privkey)
	if err != nil {
		return nil, err
	}

	leaf := certs[0]
	if !publicKeysEqual(leaf.PublicKey, key.Public()) {
		return nil, errors.New("private key does not match the certificate")
	}
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("certificate %d in fullchain is not signed by certificate %d: %w", i, i+1, err)
		}
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}

	keyPEM, err := EncodeKey(key)
	if err != nil {
		return nil, err
	}

	return &Bundle{
		Leaf:          leaf,
		Intermediates: certs[1:],
		Key:           key,
		CertPEM:       encodeCertificates(certs[:1]),
		ChainPEM:      encodeCertificates(certs[1:]),
		KeyPEM:        keyPEM,
	}, nil
}

// Describe extracts the description of the bundle's leaf certificate.
func (b *Bundle) Describe() Description {
	leaf := b.Leaf
	certSum := sha256.Sum256(leaf.Raw)
	spkiSum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return Description{
		Names:      Names(leaf),
		CommonName: leaf.Subject.CommonName,
		NotBefore:  leaf.NotBefore.UTC(),
		NotAfter:   leaf.NotAfter.UTC(),
		Serial:     hex.EncodeToString(leaf.SerialNumber.Bytes()),
		Issuer:     readableIssuer(leaf),
		SHA256:     hex.EncodeToString(certSum[:]),
		SPKISHA256: hex.EncodeToString(spkiSum[:]),
		KeyType:    KeyType(leaf.PublicKey),
	}
}

// Names returns the certificate's subjectAltName DNS names, lowercased and
// sorted, followed by its IP addresses.
func Names(c *x509.Certificate) []string {
	dns := make([]string, 0, len(c.DNSNames))
	for _, n := range c.DNSNames {
		dns = append(dns, strings.ToLower(n))
	}
	sort.Strings(dns)
	for _, ip := range c.IPAddresses {
		dns = append(dns, ip.String())
	}
	return dns
}

// KeyType names a public key the way the engine's key_type fields do, for
// example "ecdsa-p256" or "rsa-2048".
func KeyType(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ecdsa-" + strings.ToLower(strings.ReplaceAll(k.Curve.Params().Name, "-", ""))
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa-%d", k.N.BitLen())
	case ed25519.PublicKey:
		return "ed25519"
	default:
		return "unknown"
	}
}

func readableIssuer(c *x509.Certificate) string {
	org := ""
	if len(c.Issuer.Organization) > 0 {
		org = c.Issuer.Organization[0]
	}
	cn := c.Issuer.CommonName
	switch {
	case org != "" && cn != "" && !strings.Contains(cn, org):
		return org + " " + cn
	case cn != "":
		return cn
	default:
		return c.Issuer.String()
	}
}

func parseCertificates(fullchain string) ([]*x509.Certificate, error) {
	rest := []byte(fullchain)
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("contains a %q block; only CERTIFICATE blocks are allowed", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d: %w", len(certs), err)
		}
		certs = append(certs, c)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("contains data that is not PEM")
	}
	if len(certs) == 0 {
		return nil, errors.New("contains no certificate")
	}
	return certs, nil
}

func parsePrivateKey(privkey string) (crypto.Signer, error) {
	block, rest := pem.Decode([]byte(privkey))
	if block == nil {
		return nil, errors.New("privkey is not PEM")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("privkey must contain exactly one PEM block")
	}

	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("privkey has unsupported PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing privkey: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("privkey is not a signing key")
	}
	return signer, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}

func encodeCertificates(certs []*x509.Certificate) string {
	var buf bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return buf.String()
}
