// SPDX-License-Identifier: MPL-2.0

// Package backend is the bao-acme secrets engine.
package backend

import (
	"context"
	"strings"
	"sync/atomic"
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
	// clockOffset moves now() for tests, safely while work runs.
	clockOffset atomic.Int64

	// storage outlives requests, for work in the background.
	storage logical.Storage
	issuer  *issuer
}

// New returns an unconfigured backend.
func New() *backend {
	b := &backend{
		locks:  locksutil.CreateLocks(),
		issuer: newIssuer(),
	}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"accounts/", "config/"},
		},
		Paths: []*framework.Path{
			pathCertsList(b),
			pathCertImport(b),
			pathCertInfo(b),
			pathCertVersion(b),
			pathCertRollback(b),
			pathCertDestroy(b),
			pathCertUnmanage(b),
			pathCertRenew(b),
			pathCertStatus(b),
			pathCert(b),
			pathAccountsList(b),
			pathAccountRegister(b),
			pathAccount(b),
			pathNetwork(b),
			pathStatus(b),
			pathAccountStatus(b),
			pathDNSList(b),
			pathDNS(b),
		},
		RunningVersion: Version,
		PeriodicFunc:   b.periodic,
		InitializeFunc: b.initialize,
		Clean:          func(context.Context) { b.issuer.stop() },
	}
	return b
}

// Setup keeps the storage view for background work.
func (b *backend) Setup(ctx context.Context, conf *logical.BackendConfig) error {
	b.storage = conf.StorageView
	return b.Backend.Setup(ctx, conf)
}

// initialize warns about data in the layout used before v0.5.0, which is
// no longer read, and gives accounts stored before v0.5.0 an id.
func (b *backend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	if !b.standby() {
		if err := b.assignAccountIDs(ctx, req.Storage); err != nil {
			return err
		}
	}
	for _, prefix := range []string{"certs/", "config/dns/"} {
		keys, err := req.Storage.List(ctx, prefix)
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			b.Logger().Warn("found entries stored before v0.5.0, which are no longer read; create the DNS providers and certificates again under accounts/<account>/", "prefix", prefix, "entries", len(keys))
		}
	}
	return nil
}

func (b *backend) now() time.Time {
	return time.Now().Add(time.Duration(b.clockOffset.Load()))
}

func (b *backend) lock(name string) *locksutil.LockEntry {
	return locksutil.LockForKey(b.locks, name)
}

const backendHelp = `
The bao-acme secrets engine stores TLS certificates with their private keys,
versioned, together with a description it extracts from each certificate, and
can obtain and renew them over ACME with DNS-01.

Everything is done with an account. Its settings are at config/accounts/<account>;
its DNS providers at accounts/<account>/dns/<name>; its certificates at
accounts/<account>/certs/<name>. Import a certificate at .../certs/<name>/import,
or write names and dns to .../certs/<name> to have the engine obtain it.
Read it, key included, from .../certs/<name>, and its description alone from
.../certs/<name>/info.

config/network sets an optional forward proxy for all outgoing HTTP, and the DNS
settings for DNS-01. status gives every certificate's state.
`
