// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Everything done with an account is under accounts/<account>/, in the API
// and in storage; its settings are at config/accounts/<account>. Names are
// unique per account.

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

// certID identifies a certificate across accounts, as <account>/<name>.
// Account names cannot contain a slash.
func certID(account, name string) string {
	return account + "/" + name
}

func splitCertID(id string) (account, name string) {
	account, name, _ = strings.Cut(id, "/")
	return account, name
}

// pathCertID is the id of the certificate a request's path names.
func pathCertID(d *framework.FieldData) (account, id string) {
	account = d.Get("account").(string)
	return account, certID(account, d.Get("name").(string))
}

// newMeta returns the meta for a certificate about to be written: the
// stored one, or a new one if the account exists.
func newMeta(ctx context.Context, s logical.Storage, account, id string) (*certMeta, *logical.Response, error) {
	m, err := loadMeta(ctx, s, id)
	if err != nil || m != nil {
		return m, nil, err
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

// accountInUse names what an account still owns, for refusing its delete.
func accountInUse(ctx context.Context, s logical.Storage, account string) ([]string, error) {
	var owned []string
	ids, err := listCertIDs(ctx, s, account)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		_, name := splitCertID(id)
		owned = append(owned, "certificate "+name)
	}
	providers, err := s.List(ctx, dnsPrefix(account))
	if err != nil {
		return nil, err
	}
	for _, p := range providers {
		owned = append(owned, "DNS provider "+p)
	}
	return owned, nil
}

// dnsInUse names the account's certificates that need a DNS provider: for
// issuing, or to remove records an interrupted attempt left.
func dnsInUse(ctx context.Context, s logical.Storage, account, provider string) ([]string, error) {
	var users []string
	ids, err := listCertIDs(ctx, s, account)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		_, name := splitCertID(id)
		m, err := loadMeta(ctx, s, id)
		if err != nil {
			return nil, err
		}
		if m != nil && m.Managed != nil && m.Managed.DNS == provider {
			users = append(users, name)
			continue
		}
		i, err := loadInflight(ctx, s, id)
		if err != nil {
			return nil, err
		}
		if i != nil && i.DNS == provider && len(i.Published) > 0 {
			users = append(users, name+" (leftover challenge records)")
		}
	}
	return users, nil
}
