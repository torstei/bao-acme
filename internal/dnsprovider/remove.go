// SPDX-License-Identifier: MPL-2.0

package dnsprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/miekg/dns"
)

// challengeRecord is the TXT record lego publishes for a challenge.
type challengeRecord struct {
	Domain, Token, KeyAuth string
	// FQDN has no trailing dot.
	FQDN, Value string
}

// zone finds the zone rec belongs to, as lego's providers do, without the
// trailing dot.
func (rec challengeRecord) zone(ctx context.Context) (string, error) {
	zone, err := dns01.DefaultClient().FindZoneByFqdn(ctx, dns.Fqdn(rec.FQDN))
	if err != nil {
		return "", fmt.Errorf("finding the zone of %s: %w", rec.FQDN, err)
	}
	return dns01.UnFqdn(zone), nil
}

// Remove removes the challenge record lego published for domain, token and
// keyAuth, if the provider still holds a record with exactly that name and
// value, and reports whether it was there. Records with other values at the
// same name are never touched. An error means the record may still be
// there. Like lego's providers, it uses lego's process-wide DNS client to
// find the zone.
func (s *Spec) Remove(ctx context.Context, settings Settings, common Common, httpClient *http.Client, domain, token, keyAuth string) (bool, error) {
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	rec := challengeRecord{
		Domain: domain, Token: token, KeyAuth: keyAuth,
		FQDN: dns01.UnFqdn(info.EffectiveFQDN), Value: info.Value,
	}
	found, err := s.remove(ctx, settings, common, httpClient, rec)
	if err != nil {
		return found, fmt.Errorf("%s: %w", s.Name, err)
	}
	return found, nil
}

const domeneshopAPI = "https://api.domeneshop.no/v0"

func removeDomeneshop(ctx context.Context, s Settings, _ Common, hc *http.Client, rec challengeRecord) (bool, error) {
	api := apiClient{hc: hc, auth: func(r *http.Request) { r.SetBasicAuth(s["api_token"], s["api_secret"]) }}
	zone, err := rec.zone(ctx)
	if err != nil {
		return false, err
	}
	host, err := dns01.ExtractSubDomain(dns.Fqdn(rec.FQDN), dns.Fqdn(zone))
	if err != nil {
		return false, err
	}

	var domains []struct {
		ID       int    `json:"id"`
		Domain   string `json:"domain"`
		Services struct {
			DNS bool `json:"dns"`
		} `json:"services"`
	}
	if err := api.do(ctx, http.MethodGet, domeneshopAPI+"/domains", &domains); err != nil {
		return false, err
	}
	domainID := 0
	for _, d := range domains {
		if d.Domain == zone && d.Services.DNS {
			domainID = d.ID
		}
	}
	if domainID == 0 {
		return false, fmt.Errorf("no domain %s with DNS service", zone)
	}

	recordsURL := domeneshopAPI + "/domains/" + strconv.Itoa(domainID) + "/dns"
	var records []struct {
		ID   int    `json:"id"`
		Host string `json:"host"`
		Type string `json:"type"`
		Data string `json:"data"`
	}
	if err := api.do(ctx, http.MethodGet, recordsURL, &records); err != nil {
		return false, err
	}
	for _, r := range records {
		if r.Type == "TXT" && r.Host == host && r.Data == rec.Value {
			return true, api.do(ctx, http.MethodDelete, recordsURL+"/"+strconv.Itoa(r.ID), nil)
		}
	}
	return false, nil
}

const cloudflareAPI = "https://api.cloudflare.com/client/v4"

func removeCloudflare(ctx context.Context, s Settings, _ Common, hc *http.Client, rec challengeRecord) (bool, error) {
	auth := func(token string) func(*http.Request) {
		return func(r *http.Request) {
			if token != "" {
				r.Header.Set("Authorization", "Bearer "+token)
			} else {
				r.Header.Set("X-Auth-Email", s["email"])
				r.Header.Set("X-Auth-Key", s["api_key"])
			}
		}
	}
	zone, err := rec.zone(ctx)
	if err != nil {
		return false, err
	}
	zoneToken := s["zone_api_token"]
	if zoneToken == "" {
		zoneToken = s["api_token"]
	}
	zoneAPI := apiClient{hc: hc, auth: auth(zoneToken)}
	recordAPI := apiClient{hc: hc, auth: auth(s["api_token"])}

	var zones struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := zoneAPI.do(ctx, http.MethodGet, cloudflareAPI+"/zones?"+url.Values{"name": {zone}}.Encode(), &zones); err != nil {
		return false, err
	}
	if len(zones.Result) == 0 {
		return false, fmt.Errorf("no zone %s", zone)
	}

	recordsURL := cloudflareAPI + "/zones/" + url.PathEscape(zones.Result[0].ID) + "/dns_records"
	query := url.Values{"type": {"TXT"}, "name": {rec.FQDN}, "per_page": {"100"}}
	var records struct {
		Result []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"result"`
	}
	if err := recordAPI.do(ctx, http.MethodGet, recordsURL+"?"+query.Encode(), &records); err != nil {
		return false, err
	}
	for _, r := range records.Result {
		if r.Name == rec.FQDN && (r.Content == rec.Value || r.Content == strconv.Quote(rec.Value)) {
			return true, recordAPI.do(ctx, http.MethodDelete, recordsURL+"/"+url.PathEscape(r.ID), nil)
		}
	}
	return false, nil
}

// removeDNSUpdate asks the name server that takes the updates, and leaves
// the removal to lego, whose update deletes only the record with this value.
func removeDNSUpdate(ctx context.Context, s Settings, c Common, hc *http.Client, rec challengeRecord) (bool, error) {
	nameserver := s["nameserver"]
	if _, _, err := net.SplitHostPort(nameserver); err != nil {
		nameserver = net.JoinHostPort(nameserver, "53")
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(rec.FQDN), dns.TypeTXT)
	q.RecursionDesired = false
	client := &dns.Client{Timeout: 10 * time.Second}
	reply, _, err := client.ExchangeContext(ctx, q, nameserver)
	if err == nil && reply.Truncated {
		client.Net = "tcp"
		reply, _, err = client.ExchangeContext(ctx, q, nameserver)
	}
	if err != nil {
		return false, fmt.Errorf("asking %s for %s: %w", nameserver, rec.FQDN, err)
	}
	if reply.Rcode != dns.RcodeSuccess && reply.Rcode != dns.RcodeNameError {
		return false, fmt.Errorf("%s answered %s for %s", nameserver, dns.RcodeToString[reply.Rcode], rec.FQDN)
	}
	found := false
	for _, rr := range reply.Answer {
		if txt, ok := rr.(*dns.TXT); ok && dns.Fqdn(rec.FQDN) == dns.Fqdn(txt.Hdr.Name) && strings.Join(txt.Txt, "") == rec.Value {
			found = true
		}
	}
	if !found {
		return false, nil
	}
	p, err := specs["dnsupdate"].build(s, c, hc)
	if err != nil {
		return true, err
	}
	return true, p.CleanUp(ctx, rec.Domain, rec.Token, rec.KeyAuth)
}

type apiClient struct {
	hc   *http.Client
	auth func(*http.Request)
}

func (a apiClient) do(ctx context.Context, method, url string, result any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	a.auth(req)
	resp, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, req.URL.Path, err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s", method, req.URL.Path, resp.Status)
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("%s %s: %w", method, req.URL.Path, err)
	}
	return nil
}
