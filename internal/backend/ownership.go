// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Everything done with an account is under accounts/<account>/; its
// settings are at config/accounts/<account>. Names stay unique per mount,
// and each certificate and DNS provider records the account that owns it.

func accountField() *framework.FieldSchema {
	return &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Name of the account (config/accounts/<account>).",
		Required:    true,
	}
}

func accountPrefix() string {
	return "accounts/" + framework.GenericNameRegex("account")
}

func certPath(suffix string) string {
	return accountPrefix() + "/certs/" + framework.GenericNameRegex("name") + suffix
}

func dnsPath() string {
	return accountPrefix() + "/dns/" + framework.GenericNameRegex("name")
}

// owner is the account a certificate belongs to. Entries from before
// v0.4.0 have no account field, and a managed one is then its definition's
// account; an imported one belongs to no account.
func (m *certMeta) owner() string {
	if m.Account != "" {
		return m.Account
	}
	if m.Managed != nil {
		return m.Managed.Account
	}
	return ""
}

// ownedMeta loads a certificate's meta for account. It returns nil if there
// is none, or if another account owns it, which foreign reports.
func ownedMeta(ctx context.Context, s logical.Storage, account, name string) (m *certMeta, foreign bool, err error) {
	m, err = loadMeta(ctx, s, name)
	if err != nil || m == nil {
		return nil, false, err
	}
	if m.owner() != account {
		return nil, true, nil
	}
	return m, false, nil
}

// newOwnedMeta returns the meta for a certificate account is about to
// create, or an error response if the name or the account forbids it.
func newOwnedMeta(ctx context.Context, s logical.Storage, account, name string) (*certMeta, *logical.Response, error) {
	m, foreign, err := ownedMeta(ctx, s, account, name)
	switch {
	case err != nil:
		return nil, nil, err
	case foreign:
		return nil, foreignName("certificate", name), nil
	case m != nil:
		return m, nil, nil
	}
	if resp, err := requireAccount(ctx, s, account); resp != nil || err != nil {
		return nil, resp, err
	}
	return &certMeta{Account: account, MaxVersions: defaultMaxVersions}, nil, nil
}

func requireAccount(ctx context.Context, s logical.Storage, account string) (*logical.Response, error) {
	a, err := loadAccount(ctx, s, account)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("no account named %q; create it at config/accounts/%s", account, account), nil
	}
	return nil, nil
}

func foreignName(kind, name string) *logical.Response {
	return logical.ErrorResponse(fmt.Sprintf("the %s name %q is used by another account; names are unique per mount", kind, name))
}

// ownedDNS loads a DNS provider for account, as ownedMeta does.
func ownedDNS(ctx context.Context, s logical.Storage, account, name string) (e *dnsEntry, foreign bool, err error) {
	e, err = loadDNS(ctx, s, name)
	if err != nil || e == nil {
		return nil, false, err
	}
	if e.Account != account {
		return nil, true, nil
	}
	return e, false, nil
}

// accountInUse names what an account still owns, for refusing its delete.
func accountInUse(ctx context.Context, s logical.Storage, account string) ([]string, error) {
	var owned []string
	names, err := listNames(ctx, s)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		m, err := loadMeta(ctx, s, name)
		if err != nil {
			return nil, err
		}
		if m != nil && m.owner() == account {
			owned = append(owned, "certificate "+name)
		}
	}
	providers, err := s.List(ctx, "config/dns/")
	if err != nil {
		return nil, err
	}
	for _, p := range providers {
		e, err := loadDNS(ctx, s, p)
		if err != nil {
			return nil, err
		}
		if e != nil && e.Account == account {
			owned = append(owned, "DNS provider "+p)
		}
	}
	return owned, nil
}

// dnsInUse names the certificates that need a DNS provider: for issuing,
// or to remove records an interrupted attempt left.
func dnsInUse(ctx context.Context, s logical.Storage, provider string) ([]string, error) {
	var users []string
	names, err := listNames(ctx, s)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		m, err := loadMeta(ctx, s, name)
		if err != nil {
			return nil, err
		}
		if m != nil && m.Managed != nil && m.Managed.DNSProvider == provider {
			users = append(users, name)
			continue
		}
		i, err := loadInflight(ctx, s, name)
		if err != nil {
			return nil, err
		}
		if i != nil && i.DNSProvider == provider && len(i.Published) > 0 {
			users = append(users, name+" (leftover challenge records)")
		}
	}
	return users, nil
}
