// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Certificate states, for monitoring. A certificate is in exactly one.
const (
	stateValid      = "valid"
	stateRenewalDue = "renewal_due"
	stateRenewing   = "renewing"
	stateIssuing    = "issuing"
	statePending    = "pending"
	stateFailing    = "failing"
	stateExpired    = "expired"
)

var allStates = []string{stateValid, stateRenewalDue, stateRenewing, stateIssuing, statePending, stateFailing, stateExpired}

// certState sums up a certificate: the worst condition that applies.
func certState(m *certMeta, current *certVersion, running *job, now time.Time) string {
	managed := m.Managed != nil
	failing := m.Issuance != nil && m.Issuance.Failures > 0
	switch {
	case current == nil && running != nil:
		return stateIssuing
	case current == nil && failing:
		return stateFailing
	case current == nil:
		return statePending
	case !now.Before(current.Description.NotAfter):
		return stateExpired
	case running != nil && running.Reason != "":
		return stateRenewing
	case failing:
		return stateFailing
	case managed && needsIssuance(&certMeta{Managed: m.Managed, Renewal: m.Renewal}, current, now) != "":
		return stateRenewalDue
	}
	return stateValid
}

func pathCertStatus(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "certs/" + framework.GenericNameRegex("name") + "/status",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "certificate-status",
		},
		Fields: map[string]*framework.FieldSchema{"name": nameField()},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.handleCertStatus},
		},
		HelpSynopsis: "The certificate's state for monitoring, what the engine is doing with it now, and its recent attempts.",
	}
}

func pathStatus(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "status",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "status",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.handleStatus},
		},
		HelpSynopsis: "Every certificate's state and expiry, and how many are in each state, in one read.",
	}
}

func (b *backend) handleCertStatus(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	m, current, err := b.loadCurrent(ctx, req.Storage, name)
	if err != nil || m == nil {
		return nil, err
	}
	now := b.now()
	running := b.issuer.job(name)

	data := summary(m, current, running, now)
	if running != nil {
		data["running_since"] = running.Since
		data["running_reason"] = running.Reason
	}
	if m.Managed != nil {
		issuance := issuanceData(m, current, now)
		for _, k := range []string{"needed", "last_attempt_time", "last_success_time", "last_error", "next_attempt_time", "renew_requested", "renewal"} {
			if v, ok := issuance[k]; ok {
				data[k] = v
			}
		}
	}
	attempts := []map[string]any{}
	if m.Issuance != nil {
		for _, a := range m.Issuance.Attempts {
			attempts = append(attempts, map[string]any{
				"start_time":       a.StartTime,
				"duration_seconds": a.DurationSeconds,
				"reason":           a.Reason,
				"outcome":          a.Outcome,
				"error":            a.Error,
				"version":          a.Version,
			})
		}
	}
	data["attempts"] = attempts
	return &logical.Response{Data: data}, nil
}

// summary is what both status paths say about a certificate.
func summary(m *certMeta, current *certVersion, running *job, now time.Time) map[string]any {
	data := map[string]any{
		"state":    certState(m, current, running, now),
		"managed":  m.Managed != nil,
		"running":  running != nil,
		"failures": 0,
	}
	if m.Issuance != nil {
		data["failures"] = m.Issuance.Failures
	}
	if current != nil {
		data["version"] = current.Version
		data["not_after"] = current.Description.NotAfter
		data["expires_in"] = int64(current.Description.NotAfter.Sub(now).Seconds())
	}
	if m.Renewal != nil && current != nil && m.Renewal.ForSHA256 == current.Description.SHA256 {
		data["renew_at"] = m.Renewal.RenewAt
	}
	return data
}

func (b *backend) handleStatus(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	names, err := listNames(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	now := b.now()
	counts := map[string]int{}
	for _, s := range allStates {
		counts[s] = 0
	}
	certs := map[string]any{}
	for _, name := range names {
		m, current, err := b.loadCurrent(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
		if m == nil {
			continue
		}
		s := summary(m, current, b.issuer.job(name), now)
		certs[name] = s
		counts[s["state"].(string)]++
	}
	return &logical.Response{Data: map[string]any{
		"certificates": certs,
		"counts":       counts,
		"total":        len(certs),
	}}, nil
}
