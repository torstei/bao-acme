// SPDX-License-Identifier: MPL-2.0

// Package backend is the bao-acme secrets engine.
package backend

import (
	"context"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmeclient"
)

const operationPrefix = "bao-acme"

// Version is set at build time with -ldflags.
var Version = "v0.0.0-dev"

// Factory creates the backend; it is what the plugin serves.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := New()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	acmeclient.SetLogger(b.Logger())
	return b, nil
}

type backend struct {
	*framework.Backend

	locks []*locksutil.LockEntry
	now   func() time.Time

	// storage outlives requests, for work in the background.
	storage logical.Storage
	issuer  *issuer
}

// New returns an unconfigured backend.
func New() *backend {
	b := &backend{
		locks:  locksutil.CreateLocks(),
		now:    time.Now,
		issuer: newIssuer(),
	}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"certs/", "config/"},
		},
		Paths: []*framework.Path{
			pathCertsList(b),
			pathCertImport(b),
			pathCertInfo(b),
			pathCertVersion(b),
			pathCertRollback(b),
			pathCertDestroy(b),
			pathCertUnmanage(b),
			pathCert(b),
			pathAccountsList(b),
			pathAccountRegister(b),
			pathAccount(b),
			pathNetwork(b),
			pathDNSList(b),
			pathDNS(b),
		},
		RunningVersion: Version,
		PeriodicFunc:   b.periodic,
		Clean:          func(context.Context) { b.issuer.stop() },
	}
	return b
}

// Setup keeps the storage view for background work.
func (b *backend) Setup(ctx context.Context, conf *logical.BackendConfig) error {
	b.storage = conf.StorageView
	return b.Backend.Setup(ctx, conf)
}

func (b *backend) lock(name string) *locksutil.LockEntry {
	return locksutil.LockForKey(b.locks, name)
}

const backendHelp = `
The bao-acme secrets engine stores TLS certificates with their private keys,
versioned, together with a description it extracts from each certificate.

Write a certificate to certs/<name>/import, or write names, account and
dns_provider to certs/<name> to have the engine obtain it over ACME. Read it,
key included, from certs/<name>, and its description alone from
certs/<name>/info.

Configure ACME accounts at config/accounts/<name> and register them with
config/accounts/<name>/register. config/network sets an optional forward
proxy for all outgoing HTTP, and the DNS settings for DNS-01. Configure DNS
providers at config/dns/<name>.
`
