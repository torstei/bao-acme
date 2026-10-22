// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmeclient"
	"github.com/torstei/bao-acme/internal/cert"
)

const (
	defaultAccountKeyType = "ecdsa-p256"
	acmeTimeout           = time.Minute
)

// accountEntry is stored at config/accounts/<name>.
type accountEntry struct {
	// ID tells this account apart from an earlier one of the same name.
	ID                   string    `json:"id"`
	DirectoryURL         string    `json:"directory_url"`
	Email                string    `json:"email,omitempty"`
	KeyType              string    `json:"key_type"`
	PrivateKey           string    `json:"private_key"`
	EABKeyID             string    `json:"eab_kid,omitempty"`
	EABHMACKey           string    `json:"eab_hmac_key,omitempty"`
	CABundle             string    `json:"ca_bundle,omitempty"`
	TermsOfServiceAgreed bool      `json:"terms_of_service_agreed"`
	CreatedTime          time.Time `json:"created_time"`

	Registration *accountRegistration `json:"registration,omitempty"`
}

type accountRegistration struct {
	AccountURL     string    `json:"account_url"`
	Status         string    `json:"status"`
	Contact        []string  `json:"contact,omitempty"`
	ContactSent    string    `json:"contact_sent,omitempty"`
	TermsOfService string    `json:"terms_of_service,omitempty"`
	CAAIdentities  []string  `json:"caa_identities,omitempty"`
	RegisteredTime time.Time `json:"registered_time"`
	CheckedTime    time.Time `json:"checked_time"`
}

// caaRecords are the CAA property values (RFC 8659, with RFC 8657's
// accounturi and validationmethods) that restrict issuance to this account
// and to DNS-01, one issue and one issuewild per CA identity.
func (r *accountRegistration) caaRecords() []string {
	var out []string
	for _, id := range r.CAAIdentities {
		value := fmt.Sprintf("%s; accounturi=%s; validationmethods=dns-01", id, r.AccountURL)
		out = append(out, fmt.Sprintf("0 issue %q", value), fmt.Sprintf("0 issuewild %q", value))
	}
	return out
}

const caaNote = "Publish these as CAA records on each name, or on a parent domain, to allow only this account to issue, and only through DNS-01. " +
	"Any other ACME account is then refused, certbot's included: while it is still a fallback, also publish an issue record with its account URL (the \"uri\" in its regr.json)."

func accountKey(name string) string {
	return "config/accounts/" + name
}

func accountLockName(name string) string {
	return "account/" + name
}

func loadAccount(ctx context.Context, s logical.Storage, name string) (*accountEntry, error) {
	var a accountEntry
	ok, err := getJSON(ctx, s, accountKey(name), &a)
	if err != nil || !ok {
		return nil, err
	}
	return &a, nil
}

func (a *accountEntry) client() (*acmeclient.Account, error) {
	key, err := cert.ParseKey(a.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("stored account key: %w", err)
	}
	c := &acmeclient.Account{
		DirectoryURL: a.DirectoryURL,
		Email:        a.Email,
		Key:          key,
		EABKeyID:     a.EABKeyID,
		EABHMACKey:   a.EABHMACKey,
	}
	if a.CABundle != "" {
		if c.CABundle, err = cert.ParseCertificates(a.CABundle); err != nil {
			return nil, fmt.Errorf("stored ca_bundle: %w", err)
		}
	}
	if a.Registration != nil {
		c.AccountURL = a.Registration.AccountURL
		c.ContactSent = a.Registration.ContactSent
	}
	return c, nil
}

func pathAccountsList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/accounts/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "accounts",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.handleAccountsList},
		},
		HelpSynopsis: "List ACME accounts.",
	}
}

func pathAccount(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/accounts/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "account",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the account.",
				Required:    true,
			},
			"directory_url": {
				Type:        framework.TypeString,
				Description: `ACME directory: an https URL, or a CA name known to lego such as "letsencrypt" or "letsencrypt-staging". Needed to register and issue; without it the account holds only imported certificates. Fixed once registered.`,
			},
			"email": {
				Type:        framework.TypeString,
				Description: "Contact address given to the CA. Optional; an empty value removes it.",
			},
			"key_type": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf("Account key type: %s. Defaults to %s; fixed once created.", strings.Join(cert.KeyTypes, ", "), defaultAccountKeyType),
			},
			"eab_kid": {
				Type:        framework.TypeString,
				Description: "External account binding key ID, from the CA. Fixed once registered.",
			},
			"eab_hmac_key": {
				Type:        framework.TypeString,
				Description: "External account binding HMAC key, base64url as the CA gives it. Write-only. Fixed once registered.",
			},
			"ca_bundle": {
				Type:        framework.TypeString,
				Description: "PEM certificates to trust for the ACME server's TLS, in addition to the system roots. For a private ACME server.",
			},
			"terms_of_service_agreed": {
				Type:        framework.TypeBool,
				Description: "Agree to the CA's terms of service. Registration is refused until this is true.",
			},
		},
		ExistenceCheck: b.accountExists,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.handleAccountWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleAccountWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleAccountRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.handleAccountDelete},
		},
		HelpSynopsis: "Configure an ACME account. The account key is generated by the engine and never returned.",
	}
}

func pathAccountRegister(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/accounts/" + framework.GenericNameRegex("name") + "/register",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "register",
			OperationSuffix: "account",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the account.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleAccountRegister},
		},
		HelpSynopsis: "Register the account with the CA, or, once registered, update its contact and refresh its status.",
	}
}

func (b *backend) accountExists(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	a, err := loadAccount(ctx, req.Storage, d.Get("name").(string))
	return a != nil, err
}

func (b *backend) handleAccountsList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, "config/accounts/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *backend) handleAccountRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	l := b.lock(accountLockName(name))
	l.RLock()
	defer l.RUnlock()

	a, err := loadAccount(ctx, req.Storage, name)
	if err != nil || a == nil {
		return nil, err
	}
	return &logical.Response{Data: accountData(a)}, nil
}

// assignAccountIDs gives an id to each account stored without one. The
// account then keeps it, so it is set once, on the active node.
func (b *backend) assignAccountIDs(ctx context.Context, s logical.Storage) error {
	names, err := s.List(ctx, "config/accounts/")
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := b.assignAccountID(ctx, s, name); err != nil {
			return err
		}
	}
	return nil
}

func (b *backend) assignAccountID(ctx context.Context, s logical.Storage, name string) error {
	l := b.lock(accountLockName(name))
	l.Lock()
	defer l.Unlock()
	a, err := loadAccount(ctx, s, name)
	if err != nil || a == nil || a.ID != "" {
		return err
	}
	if a.ID, err = uuid.GenerateUUID(); err != nil {
		return err
	}
	return putJSON(ctx, s, accountKey(name), a)
}

func accountData(a *accountEntry) map[string]any {
	data := map[string]any{
		"id":                      a.ID,
		"directory_url":           a.DirectoryURL,
		"email":                   a.Email,
		"key_type":                a.KeyType,
		"eab_kid":                 a.EABKeyID,
		"eab_hmac_key_set":        a.EABHMACKey != "",
		"ca_bundle":               a.CABundle,
		"terms_of_service_agreed": a.TermsOfServiceAgreed,
		"created_time":            a.CreatedTime,
		"registered":              a.Registration != nil,
	}
	if r := a.Registration; r != nil {
		data["account_url"] = r.AccountURL
		data["status"] = r.Status
		data["registered_contact"] = r.Contact
		data["terms_of_service"] = r.TermsOfService
		data["registered_time"] = r.RegisteredTime
		data["checked_time"] = r.CheckedTime
		data["caa_records"] = r.caaRecords()
		if len(r.CAAIdentities) > 0 {
			data["caa_note"] = caaNote
		} else {
			data["caa_note"] = "The CA's directory names no CAA identities, so no CAA records can be given for it."
		}
	}
	return data
}

func (b *backend) handleAccountWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	l := b.lock(accountLockName(name))
	l.Lock()
	defer l.Unlock()

	a, err := loadAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	creating := a == nil
	if creating {
		uid, err := uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}
		a = &accountEntry{ID: uid, KeyType: defaultAccountKeyType, CreatedTime: b.now().UTC()}
	}
	registered := a.Registration != nil

	if raw, ok := d.GetOk("directory_url"); ok {
		u, err := acmeclient.ResolveDirectoryURL(raw.(string))
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		if registered && u != a.DirectoryURL {
			return logical.ErrorResponse("directory_url cannot change once the account is registered; create a new account instead"), logical.ErrInvalidRequest
		}
		a.DirectoryURL = u
	}

	if raw, ok := d.GetOk("key_type"); ok {
		if !creating && raw.(string) != a.KeyType {
			return logical.ErrorResponse("key_type cannot change once the account exists"), logical.ErrInvalidRequest
		}
		a.KeyType = raw.(string)
	}

	if raw, ok := d.GetOk("email"); ok {
		email := strings.TrimSpace(strings.TrimPrefix(raw.(string), "mailto:"))
		if email != "" && (!strings.Contains(email, "@") || strings.ContainsAny(email, " ,")) {
			return logical.ErrorResponse("email must be a single address"), logical.ErrInvalidRequest
		}
		a.Email = email
	}

	kid, kidSet := d.GetOk("eab_kid")
	hmac, hmacSet := d.GetOk("eab_hmac_key")
	if kidSet || hmacSet {
		if registered {
			return logical.ErrorResponse("external account binding is only used at registration, and the account is already registered"), logical.ErrInvalidRequest
		}
		if kidSet {
			a.EABKeyID = kid.(string)
		}
		if hmacSet {
			if err := validateHMACKey(hmac.(string)); err != nil {
				return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
			}
			a.EABHMACKey = hmac.(string)
		}
		if (a.EABKeyID == "") != (a.EABHMACKey == "") {
			return logical.ErrorResponse("eab_kid and eab_hmac_key must be set together"), logical.ErrInvalidRequest
		}
	}

	if raw, ok := d.GetOk("ca_bundle"); ok {
		bundle := raw.(string)
		if strings.TrimSpace(bundle) != "" {
			if _, err := cert.ParseCertificates(bundle); err != nil {
				return logical.ErrorResponse("ca_bundle " + err.Error()), logical.ErrInvalidRequest
			}
		}
		a.CABundle = bundle
	}

	if raw, ok := d.GetOk("terms_of_service_agreed"); ok {
		a.TermsOfServiceAgreed = raw.(bool)
	}

	if creating {
		key, err := cert.GenerateKey(a.KeyType)
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		if a.PrivateKey, err = cert.EncodeKey(key); err != nil {
			return nil, err
		}
	}

	if err := putJSON(ctx, req.Storage, accountKey(name), a); err != nil {
		return nil, err
	}
	resp := &logical.Response{Data: accountData(a)}
	if registered && a.Registration != nil && !acmeclient.ContactCurrent(a.Registration.Contact, a.Email, a.Registration.ContactSent) {
		resp.AddWarning("the contact differs from the CA's; write to register to update it there")
	}
	return resp, nil
}

func validateHMACKey(s string) error {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return nil
		}
	}
	return errors.New("eab_hmac_key must be base64url, as the CA gives it")
}

func (b *backend) handleAccountRegister(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	l := b.lock(accountLockName(name))
	l.Lock()
	defer l.Unlock()

	a, err := loadAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return logical.ErrorResponse("no account named %q", name), logical.ErrInvalidRequest
	}
	if a.DirectoryURL == "" {
		return logical.ErrorResponse("account %q has no directory_url to register with", name), logical.ErrInvalidRequest
	}
	client, err := a.client()
	if err != nil {
		return nil, err
	}
	n, err := loadNetwork(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if client.Network, err = n.network(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, acmeTimeout)
	defer cancel()

	var reg *acmeclient.Registration
	var dir *acmeclient.Directory
	now := b.now().UTC()
	if a.Registration == nil {
		reg, dir, err = acmeclient.Register(ctx, client, a.TermsOfServiceAgreed)
	} else {
		reg, dir, err = acmeclient.Refresh(ctx, client)
	}
	switch {
	case errors.Is(err, acmeclient.ErrTermsNotAgreed):
		return logical.ErrorResponse("read the CA's terms of service at %s, then set terms_of_service_agreed=true", dir.TermsOfService), logical.ErrInvalidRequest
	case errors.Is(err, acmeclient.ErrEABRequired):
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	case err != nil:
		return logical.ErrorResponse("%s: %v", a.DirectoryURL, err), nil
	}

	if a.Registration == nil {
		a.Registration = &accountRegistration{RegisteredTime: now}
	}
	a.Registration.AccountURL = reg.AccountURL
	a.Registration.Status = reg.Status
	a.Registration.Contact = reg.Contact
	a.Registration.ContactSent = reg.ContactSent
	a.Registration.TermsOfService = reg.TermsOfService
	a.Registration.CAAIdentities = reg.CAAIdentities
	a.Registration.CheckedTime = now
	if err := putJSON(ctx, req.Storage, accountKey(name), a); err != nil {
		return nil, err
	}
	return &logical.Response{Data: accountData(a)}, nil
}

func (b *backend) handleAccountDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	l := b.lock(accountLockName(name))
	l.Lock()
	defer l.Unlock()

	a, err := loadAccount(ctx, req.Storage, name)
	if err != nil || a == nil {
		return nil, err
	}
	owned, err := accountInUse(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if len(owned) > 0 {
		return logical.ErrorResponse("account %q still owns %s; delete those first", name, strings.Join(owned, ", ")), logical.ErrInvalidRequest
	}
	if err := req.Storage.Delete(ctx, accountKey(name)); err != nil {
		return nil, err
	}
	if a.Registration != nil {
		resp := &logical.Response{}
		resp.AddWarning("the account was deleted here but not deactivated at the CA, and its key is gone")
		return resp, nil
	}
	return nil, nil
}
