// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/dnsprovider"
)

// dnsEntry is stored at accounts/<account>/dns/<name>.
type dnsEntry struct {
	// ID tells this provider apart from an earlier one of the same name.
	ID string `json:"id"`
	// Account owns the provider; only its certificates may use it.
	Account                   string            `json:"account"`
	Type                      string            `json:"type"`
	Settings                  map[string]string `json:"settings"`
	TTL                       int               `json:"ttl,omitempty"`
	PropagationTimeoutSeconds int               `json:"propagation_timeout_seconds,omitempty"`
	PollingIntervalSeconds    int               `json:"polling_interval_seconds,omitempty"`
	CreatedTime               time.Time         `json:"created_time"`
}

func dnsPrefix(account string) string {
	return "accounts/" + account + "/dns/"
}

func dnsKey(account, name string) string {
	return dnsPrefix(account) + name
}

func loadDNS(ctx context.Context, s logical.Storage, account, name string) (*dnsEntry, error) {
	var e dnsEntry
	ok, err := getJSON(ctx, s, dnsKey(account, name), &e)
	if err != nil || !ok {
		return nil, err
	}
	return &e, nil
}

func (e *dnsEntry) common() dnsprovider.Common {
	return dnsprovider.Common{
		TTL:                e.TTL,
		PropagationTimeout: time.Duration(e.PropagationTimeoutSeconds) * time.Second,
		PollingInterval:    time.Duration(e.PollingIntervalSeconds) * time.Second,
	}
}

// provider builds the lego provider, its HTTP going the way n says.
func (e *dnsEntry) provider(n *networkEntry) (challenge.Provider, error) {
	spec, ok := dnsprovider.Lookup(e.Type)
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider %q", e.Type)
	}
	network, err := n.network()
	if err != nil {
		return nil, err
	}
	return spec.Build(e.Settings, e.common(), network.HTTPClient(nil))
}

func pathDNSList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: accountPrefix() + "/dns/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "dns-providers",
		},
		Fields: map[string]*framework.FieldSchema{"account": accountField()},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.handleDNSList},
		},
		HelpSynopsis: "List the account's DNS providers.",
	}
}

func pathDNS(b *backend) *framework.Path {
	fields := map[string]*framework.FieldSchema{
		"account": accountField(),
		"name": {
			Type:        framework.TypeString,
			Description: "Name of this DNS provider configuration.",
			Required:    true,
		},
		"type": {
			Type:          framework.TypeString,
			Description:   "Provider type: " + strings.Join(dnsprovider.Names(), ", ") + ". Fixed once created.",
			AllowedValues: toAny(dnsprovider.Names()),
		},
		"ttl": {
			Type:        framework.TypeInt,
			Description: "TTL of the challenge records, in seconds. Default: the provider's.",
		},
		"propagation_timeout": {
			Type:        framework.TypeDurationSecond,
			Description: "How long to wait for a challenge record to propagate. Default: the provider's.",
		},
		"polling_interval": {
			Type:        framework.TypeDurationSecond,
			Description: "How often to check propagation. Default: the provider's.",
		},
	}
	for name, f := range dnsprovider.AllFields() {
		desc := f.Description
		if f.Secret {
			desc += " Write-only."
		}
		fields[name] = &framework.FieldSchema{Type: framework.TypeString, Description: desc}
	}

	return &framework.Path{
		Pattern: dnsPath(),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "dns-provider",
		},
		Fields:         fields,
		ExistenceCheck: b.dnsExists,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.handleDNSWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleDNSWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleDNSRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.handleDNSDelete},
		},
		HelpSynopsis:    "Configure a DNS provider for this account's DNS-01 challenges. Credentials are write-only.",
		HelpDescription: dnsHelp(),
	}
}

func dnsHelp() string {
	var sb strings.Builder
	sb.WriteString("Each provider takes its own settings; an empty value removes one.\n")
	for _, name := range dnsprovider.Names() {
		spec, _ := dnsprovider.Lookup(name)
		fmt.Fprintf(&sb, "\n%s: %s\n  Egress: %s\n", name, spec.Description, spec.Egress)
		for _, f := range spec.Fields {
			flags := ""
			if f.Required {
				flags += " (required)"
			}
			if f.Secret {
				flags += " (write-only)"
			}
			fmt.Fprintf(&sb, "  %s%s: %s\n", f.Name, flags, f.Description)
		}
	}
	return sb.String()
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func (b *backend) dnsExists(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	e, err := loadDNS(ctx, req.Storage, d.Get("account").(string), d.Get("name").(string))
	return e != nil, err
}

func (b *backend) handleDNSList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, dnsPrefix(d.Get("account").(string)))
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *backend) handleDNSRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	account, name := d.Get("account").(string), d.Get("name").(string)
	l := b.lock(dnsLockName(account, name))
	l.RLock()
	defer l.RUnlock()

	e, err := loadDNS(ctx, req.Storage, account, name)
	if err != nil || e == nil {
		return nil, err
	}
	return &logical.Response{Data: dnsData(e)}, nil
}

func dnsLockName(account, name string) string {
	return "dns/" + account + "/" + name
}

func dnsData(e *dnsEntry) map[string]any {
	data := map[string]any{
		"id":                  e.ID,
		"account":             e.Account,
		"type":                e.Type,
		"ttl":                 e.TTL,
		"propagation_timeout": e.PropagationTimeoutSeconds,
		"polling_interval":    e.PollingIntervalSeconds,
		"created_time":        e.CreatedTime,
	}
	spec, ok := dnsprovider.Lookup(e.Type)
	if !ok {
		return data
	}
	data["egress"] = spec.Egress
	for _, f := range spec.Fields {
		if f.Secret {
			data[f.Name+"_set"] = e.Settings[f.Name] != ""
		} else {
			data[f.Name] = e.Settings[f.Name]
		}
	}
	return data
}

func (b *backend) handleDNSWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	account, name := d.Get("account").(string), d.Get("name").(string)
	l := b.lock(dnsLockName(account, name))
	l.Lock()
	defer l.Unlock()

	e, err := loadDNS(ctx, req.Storage, account, name)
	if err != nil {
		return nil, err
	}
	creating := e == nil
	if creating {
		if resp, err := requireAccount(ctx, req.Storage, account); resp != nil || err != nil {
			return resp, err
		}
		uid, err := uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}
		e = &dnsEntry{ID: uid, Account: account, Settings: map[string]string{}, CreatedTime: b.now().UTC()}
	}

	if raw, ok := d.GetOk("type"); ok {
		if !creating && raw.(string) != e.Type {
			return logical.ErrorResponse("type cannot change; create a new DNS provider configuration instead"), logical.ErrInvalidRequest
		}
		e.Type = raw.(string)
	}
	if e.Type == "" {
		return logical.ErrorResponse("type is required: one of %s", strings.Join(dnsprovider.Names(), ", ")), logical.ErrInvalidRequest
	}
	spec, ok := dnsprovider.Lookup(e.Type)
	if !ok {
		return logical.ErrorResponse("unknown type %q; use one of %s", e.Type, strings.Join(dnsprovider.Names(), ", ")), logical.ErrInvalidRequest
	}

	settings := maps.Clone(e.Settings)
	for field := range dnsprovider.AllFields() {
		raw, ok := d.GetOk(field)
		if !ok {
			continue
		}
		if _, belongs := spec.Field(field); !belongs {
			return logical.ErrorResponse("%s has no setting %q", e.Type, field), logical.ErrInvalidRequest
		}
		if v := strings.TrimSpace(raw.(string)); v == "" {
			delete(settings, field)
		} else {
			settings[field] = v
		}
	}
	if raw, ok := d.GetOk("ttl"); ok {
		e.TTL = raw.(int)
	}
	if raw, ok := d.GetOk("propagation_timeout"); ok {
		e.PropagationTimeoutSeconds = raw.(int)
	}
	if raw, ok := d.GetOk("polling_interval"); ok {
		e.PollingIntervalSeconds = raw.(int)
	}

	if _, err := spec.Build(settings, e.common(), nil); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	e.Settings = settings
	if err := putJSON(ctx, req.Storage, dnsKey(account, name), e); err != nil {
		return nil, err
	}

	resp := &logical.Response{Data: dnsData(e)}
	if !spec.HTTP {
		if n, err := loadNetwork(ctx, req.Storage); err == nil && n.ProxyURL != "" {
			resp.AddWarning(fmt.Sprintf("%s does not use HTTP, so its traffic does not go through the proxy: %s", e.Type, spec.Egress))
		}
	}
	return resp, nil
}

func (b *backend) handleDNSDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	account, name := d.Get("account").(string), d.Get("name").(string)
	l := b.lock(dnsLockName(account, name))
	l.Lock()
	defer l.Unlock()

	if e, err := loadDNS(ctx, req.Storage, account, name); err != nil || e == nil {
		return nil, err
	}
	users, err := dnsInUse(ctx, req.Storage, account, name)
	if err != nil {
		return nil, err
	}
	if len(users) > 0 {
		return logical.ErrorResponse("DNS provider %q is in use by %s", name, strings.Join(users, ", ")), logical.ErrInvalidRequest
	}
	return nil, req.Storage.Delete(ctx, dnsKey(account, name))
}
