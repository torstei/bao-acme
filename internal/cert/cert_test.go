// SPDX-License-Identifier: MPL-2.0

package cert_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/torstei/bao-acme/internal/cert"
	"github.com/torstei/bao-acme/internal/testcerts"
)

func TestParseAndDescribe(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	chain := testcerts.New(t, testcerts.Options{
		Names:     []string{"www.Example.com", "*.example.com", "192.0.2.1"},
		NotBefore: notBefore,
	})

	b, err := cert.Parse(chain.Fullchain, chain.Privkey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d := b.Describe()

	if got, want := strings.Join(d.Names, ","), "*.example.com,www.example.com,192.0.2.1"; got != want {
		t.Errorf("names = %q, want %q", got, want)
	}
	if d.CommonName != "www.Example.com" {
		t.Errorf("common_name = %q", d.CommonName)
	}
	if d.Issuer != "Test CA T1" {
		t.Errorf("issuer = %q", d.Issuer)
	}
	if d.KeyType != "ecdsa-p256" {
		t.Errorf("key_type = %q", d.KeyType)
	}
	if !d.NotBefore.Equal(notBefore) || d.NotBefore.Location() != time.UTC {
		t.Errorf("not_before = %v, want %v in UTC", d.NotBefore, notBefore)
	}
	if len(d.SHA256) != 64 || len(d.SPKISHA256) != 64 || d.SHA256 == d.SPKISHA256 {
		t.Errorf("fingerprints look wrong: %q %q", d.SHA256, d.SPKISHA256)
	}
	if strings.Count(b.ChainPEM, "BEGIN CERTIFICATE") != 1 || b.CertPEM+b.ChainPEM != chain.Fullchain {
		t.Errorf("chain split wrong")
	}
}

func TestRSAKeyType(t *testing.T) {
	chain := testcerts.New(t, testcerts.Options{RSABits: 2048})
	b, err := cert.Parse(chain.Fullchain, chain.Privkey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Describe().KeyType; got != "rsa-2048" {
		t.Errorf("key_type = %q", got)
	}
}

func TestSPKIStableAcrossReuseOfKey(t *testing.T) {
	first := testcerts.New(t, testcerts.Options{})
	second := testcerts.New(t, testcerts.Options{Key: first.Key})
	a := mustDescribe(t, first)
	b := mustDescribe(t, second)
	if a.SPKISHA256 != b.SPKISHA256 {
		t.Error("spki_sha256 changed although the key was reused")
	}
	if a.SHA256 == b.SHA256 {
		t.Error("sha256 equal for different certificates")
	}
}

func TestAcceptsSEC1AndStoresPKCS8(t *testing.T) {
	chain := testcerts.New(t, testcerts.Options{})
	sec1, err := x509.MarshalECPrivateKey(chain.Key.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	legacy := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))

	b, err := cert.Parse(chain.Fullchain, legacy, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if b.KeyPEM != chain.Privkey {
		t.Error("key was not re-encoded as PKCS #8")
	}
}

func mustDescribe(t *testing.T, c testcerts.Chain) cert.Description {
	t.Helper()
	b, err := cert.Parse(c.Fullchain, c.Privkey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return b.Describe()
}

func TestParseRejects(t *testing.T) {
	good := testcerts.New(t, testcerts.Options{})
	other := testcerts.New(t, testcerts.Options{})
	expired := testcerts.New(t, testcerts.Options{
		NotBefore: time.Now().Add(-100 * 24 * time.Hour),
		NotAfter:  time.Now().Add(-time.Hour),
	})
	leafOnly, _ := pem.Decode([]byte(good.Fullchain))
	otherBlocks := strings.SplitAfter(other.Fullchain, "-----END CERTIFICATE-----\n")
	wrongOrder := otherBlocks[1] + otherBlocks[0]

	cases := map[string]struct {
		fullchain, privkey, wantErr string
	}{
		"key mismatch": {good.Fullchain, other.Privkey, "does not match"},
		"expired":      {expired.Fullchain, expired.Privkey, "expired"},
		"wrong order":  {wrongOrder, other.Privkey, "does not match"},
		"broken chain": {string(pem.EncodeToMemory(leafOnly)) + otherBlocks[1], good.Privkey, "not signed by"},
		"empty":        {"", good.Privkey, "no certificate"},
		"key in chain": {good.Fullchain + good.Privkey, good.Privkey, "only CERTIFICATE"},
		"junk":         {good.Fullchain + "junk", good.Privkey, "not PEM"},
		"no key":       {good.Fullchain, "", "not PEM"},
		"two keys":     {good.Fullchain, good.Privkey + other.Privkey, "exactly one"},
		"cert as key":  {good.Fullchain, good.Fullchain, "exactly one"},
		"unsupported":  {good.Fullchain, strings.ReplaceAll(good.Privkey, "PRIVATE KEY", "DSA PRIVATE KEY"), "unsupported"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := cert.Parse(c.fullchain, c.privkey, time.Now())
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, c.wantErr)
			}
		})
	}
}
