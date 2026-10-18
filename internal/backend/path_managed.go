// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/cert"
)

func (b *backend) certExists(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	m, err := loadMeta(ctx, req.Storage, d.Get("name").(string))
	return m != nil, err
}

func (b *backend) handleDefine(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	resp, start, err := b.define(ctx, req.Storage, name, d)
	if err == nil && start {
		resp.Data["issuing"] = b.startIssuance(name)
	}
	return resp, err
}

func (b *backend) define(ctx context.Context, s logical.Storage, name string, d *framework.FieldData) (*logical.Response, bool, error) {
	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	m, err := loadMeta(ctx, s, name)
	if err != nil {
		return nil, false, err
	}
	if m == nil {
		m = &certMeta{MaxVersions: defaultMaxVersions}
	}
	spec := managedSpec{KeyType: defaultCertKeyType}
	if m.Managed != nil {
		spec = *m.Managed
	}

	if raw, ok := d.GetOk("names"); ok {
		names, err := cert.NormaliseNames(raw.([]string))
		if err != nil {
			return logical.ErrorResponse("names: " + err.Error()), false, logical.ErrInvalidRequest
		}
		spec.Names = names
	}
	if len(spec.Names) == 0 {
		return logical.ErrorResponse("names is required to manage a certificate"), false, logical.ErrInvalidRequest
	}
	if raw, ok := d.GetOk("key_type"); ok {
		if !slices.Contains(cert.KeyTypes, raw.(string)) {
			return logical.ErrorResponse("unsupported key_type %q", raw), false, logical.ErrInvalidRequest
		}
		spec.KeyType = raw.(string)
	}
	if raw, ok := d.GetOk("account"); ok {
		spec.Account = raw.(string)
	}
	if raw, ok := d.GetOk("dns_provider"); ok {
		spec.DNSProvider = raw.(string)
	}
	if spec.Account == "" || spec.DNSProvider == "" {
		return logical.ErrorResponse("account and dns_provider are required to manage a certificate"), false, logical.ErrInvalidRequest
	}
	if a, err := loadAccount(ctx, s, spec.Account); err != nil {
		return nil, false, err
	} else if a == nil {
		return logical.ErrorResponse("no account named %q", spec.Account), false, logical.ErrInvalidRequest
	}
	if e, err := loadDNS(ctx, s, spec.DNSProvider); err != nil {
		return nil, false, err
	} else if e == nil {
		return logical.ErrorResponse("no DNS provider named %q", spec.DNSProvider), false, logical.ErrInvalidRequest
	}
	if raw, ok := d.GetOk("max_versions"); ok {
		if raw.(int) < 1 {
			return logical.ErrorResponse("max_versions must be at least 1"), false, logical.ErrInvalidRequest
		}
		m.MaxVersions = raw.(int)
	}

	if m.Managed == nil || !sameDefinition(m.Managed, &spec) {
		spec.DefinedTime = b.now().UTC()
		m.Issuance = nil
	}
	m.Managed = &spec
	if err := putJSON(ctx, s, metaKey(name), m); err != nil {
		return nil, false, err
	}
	if err := prune(ctx, s, name, m); err != nil {
		return nil, false, err
	}

	current, err := loadVersion(ctx, s, name, m.CurrentVersion)
	if err != nil {
		return nil, false, err
	}
	resp := &logical.Response{Data: map[string]any{
		"definition": definitionData(m.Managed),
		"issuance":   issuanceData(m, current, b.now()),
	}}
	return resp, needsIssuance(m, current, b.now()) != "", nil
}

func sameDefinition(a, b *managedSpec) bool {
	return slices.Equal(a.Names, b.Names) && a.KeyType == b.KeyType && a.Account == b.Account && a.DNSProvider == b.DNSProvider
}

func (b *backend) handleUnmanage(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	m, err := loadMeta(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if m == nil || m.Managed == nil {
		return logical.ErrorResponse("certificate %q is not managed", name), logical.ErrInvalidRequest
	}
	m.Managed = nil
	m.Issuance = nil
	if err := putJSON(ctx, req.Storage, metaKey(name), m); err != nil {
		return nil, err
	}
	if m.CurrentVersion == 0 {
		if err := deleteCert(ctx, req.Storage, name); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func pathCertRenew(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "certs/" + framework.GenericNameRegex("name") + "/renew",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "renew",
			OperationSuffix: "certificate",
		},
		Fields: map[string]*framework.FieldSchema{"name": nameField()},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleRenew},
		},
		HelpSynopsis: "Renew a managed certificate now, ignoring its schedule and any backoff after failures.",
	}
}

func (b *backend) handleRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := b.requestRenewal(ctx, req.Storage, name); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	return &logical.Response{Data: map[string]any{"issuing": b.startIssuance(name)}}, nil
}

func (b *backend) requestRenewal(ctx context.Context, s logical.Storage, name string) error {
	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	m, err := loadMeta(ctx, s, name)
	if err != nil {
		return err
	}
	if m == nil || m.Managed == nil {
		return fmt.Errorf("certificate %q is not managed", name)
	}
	if m.Issuance == nil {
		m.Issuance = &issuanceState{}
	}
	m.Issuance.RenewRequested = true
	m.Issuance.NextAttemptTime = time.Time{}
	return putJSON(ctx, s, metaKey(name), m)
}
