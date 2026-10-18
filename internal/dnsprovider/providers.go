// SPDX-License-Identifier: MPL-2.0

package dnsprovider

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/providers/dns/dnsupdate"
	"github.com/go-acme/lego/v5/providers/dns/domeneshop"
	"github.com/miekg/dns"
)

func init() {
	register(&Spec{
		Name:        "domeneshop",
		Description: "Domeneshop (domene.shop), through its API.",
		Egress:      "HTTPS to api.domeneshop.no",
		HTTP:        true,
		Fields: []Field{
			{Name: "api_token", Description: "API token, from domene.shop/admin?view=api.", Secret: true, Required: true},
			{Name: "api_secret", Description: "API secret belonging to the token.", Secret: true, Required: true},
		},
		build: func(s Settings, c Common, hc *http.Client) (challenge.Provider, error) {
			return domeneshop.NewDNSProviderConfig(&domeneshop.Config{
				APIToken:           s["api_token"],
				APISecret:          s["api_secret"],
				PropagationTimeout: orDefault(c.PropagationTimeout, 5*time.Minute),
				PollingInterval:    orDefault(c.PollingInterval, 20*time.Second),
				HTTPClient:         hc,
			})
		},
	})

	register(&Spec{
		Name:        "cloudflare",
		Description: "Cloudflare DNS, through its API. Prefer an API token with Zone:Read and DNS:Edit over the global API key.",
		Egress:      "HTTPS to api.cloudflare.com",
		HTTP:        true,
		Fields: []Field{
			{Name: "api_token", Description: "API token with DNS:Edit (and Zone:Read unless zone_api_token is set).", Secret: true},
			{Name: "zone_api_token", Description: "Optional separate API token with Zone:Read.", Secret: true},
			{Name: "email", Description: "Account email, with api_key; only when not using api_token."},
			{Name: "api_key", Description: "Global API key, with email; only when not using api_token.", Secret: true},
		},
		check: func(s Settings) error {
			token := s["api_token"] != ""
			key := s["email"] != "" || s["api_key"] != ""
			switch {
			case token && key:
				return errors.New("use either api_token or email and api_key, not both")
			case key && (s["email"] == "" || s["api_key"] == ""):
				return errors.New("email and api_key must be set together")
			case !token && !key:
				return errors.New("needs api_token, or email and api_key")
			case !token && s["zone_api_token"] != "":
				return errors.New("zone_api_token needs api_token")
			}
			return nil
		},
		build: func(s Settings, c Common, hc *http.Client) (challenge.Provider, error) {
			return cloudflare.NewDNSProviderConfig(&cloudflare.Config{
				AuthToken:          s["api_token"],
				ZoneToken:          s["zone_api_token"],
				AuthEmail:          s["email"],
				AuthKey:            s["api_key"],
				TTL:                orDefault(c.TTL, 120),
				PropagationTimeout: orDefault(c.PropagationTimeout, 2*time.Minute),
				PollingInterval:    orDefault(c.PollingInterval, dns01.DefaultPollingInterval),
				HTTPClient:         hc,
			})
		},
	})

	register(&Spec{
		Name:        "dnsupdate",
		Description: "RFC 2136 dynamic updates to a name server, such as BIND, Knot or PowerDNS, signed with TSIG.",
		Egress:      "DNS UPDATE on port 53 (UDP and TCP) to the nameserver; not through the proxy",
		Fields: []Field{
			{Name: "nameserver", Description: "Server accepting updates, as host or host:port.", Required: true},
			{Name: "tsig_key", Description: "TSIG key name, as configured on the server."},
			{Name: "tsig_secret", Description: "TSIG key secret, base64.", Secret: true},
			{Name: "tsig_algorithm", Description: "TSIG algorithm: hmac-sha256 (default), hmac-sha384, hmac-sha512 or hmac-sha1."},
			{Name: "zones", Description: "Optional comma-separated zones to update, when not discoverable from the names."},
		},
		check: func(s Settings) error {
			if (s["tsig_key"] == "") != (s["tsig_secret"] == "") {
				return errors.New("tsig_key and tsig_secret must be set together")
			}
			if _, err := tsigAlgorithm(s["tsig_algorithm"]); err != nil {
				return err
			}
			return nil
		},
		build: func(s Settings, c Common, _ *http.Client) (challenge.Provider, error) {
			alg, _ := tsigAlgorithm(s["tsig_algorithm"])
			var zones []string
			for _, z := range strings.Split(s["zones"], ",") {
				if z = strings.TrimSpace(z); z != "" {
					zones = append(zones, z)
				}
			}
			return dnsupdate.NewDNSProviderConfig(&dnsupdate.Config{
				Nameserver:         s["nameserver"],
				DNSTimeout:         10 * time.Second,
				Zones:              zones,
				TSIGKey:            s["tsig_key"],
				TSIGSecret:         s["tsig_secret"],
				TSIGAlgorithm:      alg,
				TTL:                orDefault(c.TTL, dns01.DefaultTTL),
				PropagationTimeout: orDefault(c.PropagationTimeout, dns01.DefaultPropagationTimeout),
				PollingInterval:    orDefault(c.PollingInterval, dns01.DefaultPollingInterval),
				SequenceInterval:   dns01.DefaultPropagationTimeout,
			})
		},
	})
}

func tsigAlgorithm(name string) (string, error) {
	switch strings.TrimSuffix(strings.ToLower(name), ".") {
	case "", "hmac-sha256":
		return dns.HmacSHA256, nil
	case "hmac-sha384":
		return dns.HmacSHA384, nil
	case "hmac-sha512":
		return dns.HmacSHA512, nil
	case "hmac-sha1":
		return dns.HmacSHA1, nil
	default:
		return "", errors.New("tsig_algorithm must be hmac-sha256, hmac-sha384, hmac-sha512 or hmac-sha1")
	}
}
