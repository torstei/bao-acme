// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/acmeclient"
	"github.com/torstei/bao-acme/internal/cert"
)

const networkKey = "config/network"

// networkEntry is stored at config/network. An absent entry means direct
// connections and the default DNS settings.
type networkEntry struct {
	// ProxyURL includes any credentials, which are never returned.
	ProxyURL      string `json:"proxy_url,omitempty"`
	ProxyCABundle string `json:"proxy_ca_bundle,omitempty"`

	DNSResolvers []string `json:"dns_resolvers,omitempty"`
	// DNSPropagationCheck is empty for the default, authoritative.
	DNSPropagationCheck string `json:"dns_propagation_check,omitempty"`
	DNSPropagationDelay int    `json:"dns_propagation_delay_seconds,omitempty"`
	DNSTCPOnly          bool   `json:"dns_tcp_only,omitempty"`
}

func loadNetwork(ctx context.Context, s logical.Storage) (*networkEntry, error) {
	var n networkEntry
	if _, err := getJSON(ctx, s, networkKey, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

func (n *networkEntry) dns() acmeclient.DNSSettings {
	check := n.DNSPropagationCheck
	if check == "" {
		check = acmeclient.PropagationAuthoritative
	}
	return acmeclient.DNSSettings{
		Resolvers:        n.DNSResolvers,
		PropagationCheck: check,
		PropagationDelay: time.Duration(n.DNSPropagationDelay) * time.Second,
		TCPOnly:          n.DNSTCPOnly,
	}
}

func (n *networkEntry) network() (*acmeclient.Network, error) {
	out := &acmeclient.Network{DNS: n.dns()}
	if n.ProxyURL != "" {
		u, err := acmeclient.ParseProxyURL(n.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("stored %w", err)
		}
		out.Proxy = u
	}
	if n.ProxyCABundle != "" {
		certs, err := cert.ParseCertificates(n.ProxyCABundle)
		if err != nil {
			return nil, fmt.Errorf("stored proxy_ca_bundle: %w", err)
		}
		out.ProxyCA = certs
	}
	return out, nil
}

func pathNetwork(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/network",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "network",
		},
		Fields: map[string]*framework.FieldSchema{
			"proxy_url": {
				Type:        framework.TypeString,
				Description: "Forward proxy for all HTTP egress, as http://[user:password@]host:port or https://…. Credentials are write-only; write the whole URL to change them. Empty removes the proxy.",
			},
			"proxy_ca_bundle": {
				Type:        framework.TypeString,
				Description: "PEM certificates to trust for an https proxy, or for a proxy that inspects TLS.",
			},
			"dns_resolvers": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Recursive resolvers for DNS-01 discovery lookups, as host or host:port. Default: the OpenBao host's /etc/resolv.conf.",
			},
			"dns_propagation_check": {
				Type:          framework.TypeString,
				Description:   "Where to check that a challenge record has propagated: authoritative (the zone's servers, the default), resolvers, or none.",
				AllowedValues: []any{acmeclient.PropagationAuthoritative, acmeclient.PropagationResolvers, acmeclient.PropagationNone},
			},
			"dns_propagation_delay": {
				Type:        framework.TypeDurationSecond,
				Description: "Fixed wait before asking the CA to validate. Required with dns_propagation_check=none.",
			},
			"dns_tcp_only": {
				Type:        framework.TypeBool,
				Description: "Send all DNS queries over TCP.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleNetworkRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleNetworkWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.handleNetworkDelete},
		},
		HelpSynopsis: "How the engine reaches the outside: an optional forward proxy for all HTTP, and DNS settings for DNS-01.",
	}
}

func (b *backend) handleNetworkRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	n, err := loadNetwork(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: networkData(n)}, nil
}

func networkData(n *networkEntry) map[string]any {
	dns := n.dns()
	data := map[string]any{
		"proxy_url":               "",
		"proxy_credentials_set":   false,
		"proxy_ca_bundle":         n.ProxyCABundle,
		"dns_resolvers":           n.DNSResolvers,
		"effective_dns_resolvers": dns.EffectiveResolvers(),
		"dns_propagation_check":   dns.PropagationCheck,
		"dns_propagation_delay":   n.DNSPropagationDelay,
		"dns_tcp_only":            n.DNSTCPOnly,
	}
	if n.ProxyURL != "" {
		if u, err := acmeclient.ParseProxyURL(n.ProxyURL); err == nil {
			data["proxy_credentials_set"] = u.User != nil
			u.User = nil
			data["proxy_url"] = u.String()
		}
	}
	return data
}

func (b *backend) handleNetworkWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	l := b.lock(networkKey)
	l.Lock()
	defer l.Unlock()

	n, err := loadNetwork(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if raw, ok := d.GetOk("proxy_url"); ok {
		s := strings.TrimSpace(raw.(string))
		if s != "" {
			if _, err := acmeclient.ParseProxyURL(s); err != nil {
				return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
			}
		}
		n.ProxyURL = s
	}
	if raw, ok := d.GetOk("proxy_ca_bundle"); ok {
		bundle := raw.(string)
		if strings.TrimSpace(bundle) != "" {
			if _, err := cert.ParseCertificates(bundle); err != nil {
				return logical.ErrorResponse("proxy_ca_bundle " + err.Error()), logical.ErrInvalidRequest
			}
		}
		n.ProxyCABundle = bundle
	}
	if raw, ok := d.GetOk("dns_resolvers"); ok {
		resolvers := []string{}
		for _, r := range raw.([]string) {
			if strings.TrimSpace(r) == "" {
				continue
			}
			addr, err := acmeclient.NormaliseResolver(r)
			if err != nil {
				return logical.ErrorResponse("dns_resolvers: " + err.Error()), logical.ErrInvalidRequest
			}
			resolvers = append(resolvers, addr)
		}
		n.DNSResolvers = resolvers
	}
	if raw, ok := d.GetOk("dns_propagation_check"); ok {
		n.DNSPropagationCheck = raw.(string)
		if n.DNSPropagationCheck == acmeclient.PropagationAuthoritative {
			n.DNSPropagationCheck = ""
		}
	}
	if raw, ok := d.GetOk("dns_propagation_delay"); ok {
		n.DNSPropagationDelay = raw.(int)
	}
	if raw, ok := d.GetOk("dns_tcp_only"); ok {
		n.DNSTCPOnly = raw.(bool)
	}

	if err := n.dns().Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if err := putJSON(ctx, req.Storage, networkKey, n); err != nil {
		return nil, err
	}

	resp := &logical.Response{Data: networkData(n)}
	if len(n.dns().EffectiveResolvers()) == 0 {
		resp.AddWarning("no DNS resolvers are configured and none were found in /etc/resolv.conf on this node; DNS-01 issuance will be refused")
	}
	return resp, nil
}

func (b *backend) handleNetworkDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	l := b.lock(networkKey)
	l.Lock()
	defer l.Unlock()
	return nil, req.Storage.Delete(ctx, networkKey)
}
