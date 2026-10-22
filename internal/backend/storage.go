// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"crypto/x509"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/cert"
)

const defaultMaxVersions = 3

// certMeta is the per-certificate entry. It is written after the version it
// points to, so it never references a version that is not fully stored.
type certMeta struct {
	// Account owns the certificate; see owner for entries without one.
	Account        string `json:"account,omitempty"`
	CurrentVersion int    `json:"current_version"`
	LatestVersion  int    `json:"latest_version"`
	MaxVersions    int    `json:"max_versions"`

	// Managed is set for a certificate the engine obtains itself.
	Managed  *managedSpec   `json:"managed,omitempty"`
	Issuance *issuanceState `json:"issuance,omitempty"`
	// Renewal is when to renew the current version of a managed certificate.
	Renewal *renewalSchedule `json:"renewal,omitempty"`
}

type identity struct {
	EntityID    string `json:"entity_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

// certVersion holds everything about one version in a single storage entry,
// so writing a version is one atomic Put.
type certVersion struct {
	Version     int              `json:"version"`
	CreatedTime time.Time        `json:"created_time"`
	Source      string           `json:"source"`
	ImportedBy  *identity        `json:"imported_by,omitempty"`
	Description cert.Description `json:"description"`

	Certificate string `json:"certificate"`
	Chain       string `json:"chain"`
	Privkey     string `json:"privkey,omitempty"`

	DestroyedTime *time.Time `json:"destroyed_time,omitempty"`
}

func (v *certVersion) destroyed() bool {
	return v.DestroyedTime != nil
}

func (v *certVersion) leaf() (*x509.Certificate, error) {
	certs, err := cert.ParseCertificates(v.Certificate)
	if err != nil {
		return nil, fmt.Errorf("version %d: %w", v.Version, err)
	}
	return certs[0], nil
}

// certPrefix is where a certificate's entries are stored; id is
// <account>/<name>, as certID makes it.
func certPrefix(id string) string {
	account, name := splitCertID(id)
	return "accounts/" + account + "/certs/" + name + "/"
}

func metaKey(id string) string {
	return certPrefix(id) + "meta"
}

func versionsPrefix(id string) string {
	return certPrefix(id) + "versions/"
}

func versionKey(name string, n int) string {
	return versionsPrefix(name) + strconv.Itoa(n)
}

func getJSON(ctx context.Context, s logical.Storage, key string, out any) (bool, error) {
	entry, err := s.Get(ctx, key)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", key, err)
	}
	if entry == nil {
		return false, nil
	}
	if err := entry.DecodeJSON(out); err != nil {
		return false, fmt.Errorf("decoding %s: %w", key, err)
	}
	return true, nil
}

func putJSON(ctx context.Context, s logical.Storage, key string, v any) error {
	entry, err := logical.StorageEntryJSON(key, v)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func loadMeta(ctx context.Context, s logical.Storage, name string) (*certMeta, error) {
	var m certMeta
	ok, err := getJSON(ctx, s, metaKey(name), &m)
	if err != nil || !ok {
		return nil, err
	}
	return &m, nil
}

func loadVersion(ctx context.Context, s logical.Storage, name string, n int) (*certVersion, error) {
	var v certVersion
	ok, err := getJSON(ctx, s, versionKey(name, n), &v)
	if err != nil || !ok {
		return nil, err
	}
	return &v, nil
}

func listVersions(ctx context.Context, s logical.Storage, name string) ([]int, error) {
	keys, err := s.List(ctx, versionsPrefix(name))
	if err != nil {
		return nil, err
	}
	versions := make([]int, 0, len(keys))
	for _, k := range keys {
		n, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		versions = append(versions, n)
	}
	sort.Ints(versions)
	return versions, nil
}

// listCertIDs lists the certificates of account, or of every account when
// account is empty, as ids.
func listCertIDs(ctx context.Context, s logical.Storage, account string) ([]string, error) {
	accounts := []string{account}
	if account == "" {
		keys, err := s.List(ctx, "accounts/")
		if err != nil {
			return nil, err
		}
		accounts = accounts[:0]
		for _, k := range keys {
			accounts = append(accounts, strings.TrimSuffix(k, "/"))
		}
	}
	var ids []string
	for _, a := range accounts {
		keys, err := s.List(ctx, "accounts/"+a+"/certs/")
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			ids = append(ids, certID(a, strings.TrimSuffix(k, "/")))
		}
	}
	return ids, nil
}

// prune deletes versions beyond the newest max, but never the current one.
func prune(ctx context.Context, s logical.Storage, name string, m *certMeta) error {
	versions, err := listVersions(ctx, s, name)
	if err != nil {
		return err
	}
	for i, n := range versions {
		if len(versions)-i <= m.MaxVersions {
			break
		}
		if n == m.CurrentVersion {
			continue
		}
		if err := s.Delete(ctx, versionKey(name, n)); err != nil {
			return err
		}
	}
	return nil
}

func deleteCert(ctx context.Context, s logical.Storage, name string) error {
	versions, err := listVersions(ctx, s, name)
	if err != nil {
		return err
	}
	if err := s.Delete(ctx, metaKey(name)); err != nil {
		return err
	}
	if err := s.Delete(ctx, inflightKey(name)); err != nil {
		return err
	}
	for _, n := range versions {
		if err := s.Delete(ctx, versionKey(name, n)); err != nil {
			return err
		}
	}
	return nil
}

// writeVersion stores bundle as the next version and makes it current. The
// caller holds the certificate's lock and passes its meta, which is updated.
func writeVersion(ctx context.Context, s logical.Storage, name string, m *certMeta, bundle *cert.Bundle, source string, by *identity, now time.Time) (*certVersion, error) {
	v := &certVersion{
		Version:     m.LatestVersion + 1,
		CreatedTime: now,
		Source:      source,
		ImportedBy:  by,
		Description: bundle.Describe(),
		Certificate: bundle.CertPEM,
		Chain:       bundle.ChainPEM,
		Privkey:     bundle.KeyPEM,
	}
	if err := putJSON(ctx, s, versionKey(name, v.Version), v); err != nil {
		return nil, err
	}
	m.LatestVersion = v.Version
	m.CurrentVersion = v.Version
	if err := putJSON(ctx, s, metaKey(name), m); err != nil {
		return nil, err
	}
	if err := prune(ctx, s, name, m); err != nil {
		return nil, err
	}
	return v, nil
}
