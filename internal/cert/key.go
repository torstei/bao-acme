// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// KeyTypes are the key types the engine generates, in KeyType's naming.
var KeyTypes = []string{"ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"}

// GenerateKey creates a private key of one of KeyTypes.
func GenerateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("unsupported key type %q; use one of %s", keyType, strings.Join(KeyTypes, ", "))
	}
}

// EncodeKey returns key as a PKCS #8 PEM block.
func EncodeKey(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("encoding private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ParseKey decodes a single PEM private key (PKCS #8, PKCS #1 or SEC 1).
func ParseKey(privkey string) (crypto.Signer, error) {
	return parsePrivateKey(privkey)
}

// ParseCertificates decodes PEM certificates, requiring at least one and
// nothing but CERTIFICATE blocks.
func ParseCertificates(pemData string) ([]*x509.Certificate, error) {
	return parseCertificates(pemData)
}
