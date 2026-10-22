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
	_, id := pathCertID(d)
	m, err := loadMeta(ctx, req.Storage, id)
	return m != nil, err
}

func (b *backend) handleDefine(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	account, name := pathCertID(d)
	resp, start, err := b.define(ctx, req.Storage, account, name, d)
	if err == nil && start {
		resp.Data["issuing"] = b.startIssuance(name)
	}
	return resp, err
}

func (b *backend) define(ctx context.Context, s logical.Storage, account, name string, d *framework.FieldData) (*logical.Response, bool, error) {
	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	m, resp, err := newMeta(ctx, s, account, name)
	if err != nil {
		return nil, false, err
	}
	if resp != nil {
		return resp, false, logical.ErrInvalidRequest
	}
	m.Account = account
	spec := managedSpec{KeyType: defaultCertKeyType}
	if m.Managed != nil {
		spec = *m.Managed
	}
	spec.Account = account

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
	if raw, ok := d.GetOk("dns"); ok {
		spec.DNS = raw.(string)
	}
	if raw, ok := d.GetOk("reuse_key"); ok {
		spec.ReuseKey = raw.(bool)
	}
	if spec.DNS == "" {
		return logical.ErrorResponse("dns is required to manage a certificate"), false, logical.ErrInvalidRequest
	}
	if a, err := loadAccount(ctx, s, account); err != nil {
		return nil, false, err
	} else if a.DirectoryURL == "" {
		return logical.ErrorResponse("account %q has no directory_url, so it can hold only imported certificates", account), false, logical.ErrInvalidRequest
	}
	if e, err := loadDNS(ctx, s, account, spec.DNS); err != nil {
		return nil, false, err
	} else if e == nil {
		return logical.ErrorResponse("account %q has no DNS provider named %q", account, spec.DNS), false, logical.ErrInvalidRequest
	}
	if raw, ok := d.GetOk("max_versions"); ok {
		if raw.(int) < 1 {
			return logical.ErrorResponse("max_versions must be at least 1"), false, logical.ErrInvalidRequest
		}
		m.MaxVersions = raw.(int)
	}

	if m.Managed == nil || !sameDefinition(m.Managed, &spec) {
		spec.DefinedTime = b.now().UTC()
		var history []attemptRecord
		if m.Issuance != nil {
			history = m.Issuance.Attempts
		}
		m.Issuance = nil
		if len(history) > 0 {
			m.Issuance = &issuanceState{Attempts: history}
		}
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
	resp = &logical.Response{Data: map[string]any{
		"definition": definitionData(m.Managed),
		"issuance":   issuanceData(m, current, b.now()),
	}}
	return resp, needsIssuance(m, current, b.now()) != "", nil
}

func sameDefinition(a, b *managedSpec) bool {
	return slices.Equal(a.Names, b.Names) && a.KeyType == b.KeyType && a.Account == b.Account && a.DNS == b.DNS
}

func (b *backend) handleUnmanage(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	account, name := pathCertID(d)
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
	m.Account = account
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
		Pattern: certPath("/renew"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "renew",
			OperationSuffix: "certificate",
		},
		Fields: map[string]*framework.FieldSchema{
			"account": accountField(),
			"name":    nameField(),
			"rotate_key": {
				Type:        framework.TypeBool,
				Description: "Use a new key for this renewal, even if the definition reuses keys. Later renewals reuse the new one.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleRenew},
		},
		HelpSynopsis: "Renew a managed certificate now, ignoring its schedule and any backoff after failures.",
	}
}

func (b *backend) handleRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, name := pathCertID(d)
	if err := b.requestRenewal(ctx, req.Storage, name, d.Get("rotate_key").(bool)); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	return &logical.Response{Data: map[string]any{"issuing": b.startIssuance(name)}}, nil
}

func (b *backend) requestRenewal(ctx context.Context, s logical.Storage, name string, rotateKey bool) error {
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
	m.Issuance.RotateKey = m.Issuance.RotateKey || rotateKey
	m.Issuance.NextAttemptTime = time.Time{}
	return putJSON(ctx, s, metaKey(name), m)
}
