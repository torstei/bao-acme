// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/cert"
)

const sourceImport = "import"

func nameField() *framework.FieldSchema {
	return &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Name of the certificate.",
		Required:    true,
	}
}

func pathCertsList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: accountPrefix() + "/certs/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "certificates",
		},
		Fields: map[string]*framework.FieldSchema{
			"account": accountField(),
			"covers": {
				Type:        framework.TypeString,
				Description: "Only list certificates whose current version covers this host name or IP address.",
				Query:       true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.handleList},
		},
		HelpSynopsis: "List certificates.",
	}
}

func pathCert(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: certPath(""),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "certificate",
		},
		Fields: map[string]*framework.FieldSchema{
			"account": accountField(),
			"name":    nameField(),
			"names": {
				Type:        framework.TypeCommaStringSlice,
				Description: "DNS names for a managed certificate; wildcards allowed as the leftmost label.",
			},
			"key_type": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf("Key type for a managed certificate: %s. Default %s.", strings.Join(cert.KeyTypes, ", "), defaultCertKeyType),
			},
			"dns": {
				Type:        framework.TypeString,
				Description: "DNS provider for a managed certificate's DNS-01 challenges: the name of one of this account's, at accounts/<account>/dns/<name>.",
			},
			"reuse_key": {
				Type:        framework.TypeBool,
				Description: "Renew a managed certificate with its current key, so its public key stays the same. A destroyed key is never reused. Default false.",
			},
			"max_versions": {
				Type:        framework.TypeInt,
				Description: fmt.Sprintf("Number of versions to keep. Defaults to %d for a new certificate; unchanged if omitted.", defaultMaxVersions),
			},
		},
		ExistenceCheck: b.certExists,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.handleDefine},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleDefine},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.handleDelete},
		},
		HelpSynopsis: "Read the current version of a certificate, private key included; write to define a managed certificate that the engine obtains over ACME; or delete the certificate and all its versions.",
	}
}

func pathCertUnmanage(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: certPath("/unmanage"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "unmanage",
			OperationSuffix: "certificate",
		},
		Fields: map[string]*framework.FieldSchema{"account": accountField(), "name": nameField()},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleUnmanage},
		},
		HelpSynopsis: "Stop obtaining the certificate over ACME. Its versions stay, and it can be imported into again.",
	}
}

func pathCertVersion(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: certPath("/versions/(?P<version>[1-9][0-9]*)"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "certificate-version",
		},
		Fields: map[string]*framework.FieldSchema{
			"account": accountField(),
			"name":    nameField(),
			"version": {
				Type:        framework.TypeInt,
				Description: "Version number.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.handleReadVersion},
		},
		HelpSynopsis: "Read an earlier version of a certificate, private key included.",
	}
}

func pathCertInfo(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: certPath("/info"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationSuffix: "certificate-info",
		},
		Fields: map[string]*framework.FieldSchema{"account": accountField(), "name": nameField()},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.handleInfo},
		},
		HelpSynopsis: "Read the description and version state of a certificate, without its key.",
	}
}

func pathCertImport(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: certPath("/import"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "import",
			OperationSuffix: "certificate",
		},
		Fields: map[string]*framework.FieldSchema{
			"account": accountField(),
			"name":    nameField(),
			"fullchain": {
				Type:        framework.TypeString,
				Description: "PEM certificates, leaf first, each followed by the one that signed it.",
				Required:    true,
			},
			"privkey": {
				Type:        framework.TypeString,
				Description: "PEM private key of the leaf certificate (PKCS #8, PKCS #1 or SEC 1).",
				Required:    true,
			},
			"max_versions": {
				Type:        framework.TypeInt,
				Description: fmt.Sprintf("Number of versions to keep. Defaults to %d for a new certificate; unchanged if omitted.", defaultMaxVersions),
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleImport},
		},
		HelpSynopsis: "Write a new version of an imported certificate. An import identical to the current version writes nothing.",
	}
}

func pathCertRollback(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: certPath("/rollback"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "rollback",
			OperationSuffix: "certificate",
		},
		Fields: map[string]*framework.FieldSchema{
			"account": accountField(),
			"name":    nameField(),
			"version": {
				Type:        framework.TypeInt,
				Description: "Version to make current.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleRollback},
		},
		HelpSynopsis: "Make an earlier version current again.",
	}
}

func pathCertDestroy(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: certPath("/destroy"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "destroy",
			OperationSuffix: "certificate-versions",
		},
		Fields: map[string]*framework.FieldSchema{
			"account": accountField(),
			"name":    nameField(),
			"versions": {
				Type:        framework.TypeCommaIntSlice,
				Description: "Versions whose private keys to destroy.",
			},
			"spki_sha256": {
				Type:        framework.TypeString,
				Description: "Destroy the key with this public key fingerprint (info's spki_sha256) in every version that holds it, for a compromised key.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleDestroy},
		},
		HelpSynopsis: "Destroy the private keys of the given versions, or of every version holding one key. Their descriptions remain.",
	}
}

func (b *backend) handleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ids, err := listCertIDs(ctx, req.Storage, d.Get("account").(string))
	if err != nil {
		return nil, err
	}
	host := d.Get("covers").(string)

	matching := []string{}
	for _, id := range ids {
		_, name := splitCertID(id)
		m, err := loadMeta(ctx, req.Storage, id)
		if err != nil {
			return nil, err
		}
		if m == nil {
			continue
		}
		if host == "" {
			matching = append(matching, name)
			continue
		}
		v, err := loadVersion(ctx, req.Storage, id, m.CurrentVersion)
		if err != nil {
			return nil, err
		}
		if v != nil && cert.Covers(v.Description.Names, host) {
			matching = append(matching, name)
		}
	}
	return logical.ListResponse(matching), nil
}

func (b *backend) handleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, name := pathCertID(d)
	l := b.lock(name)
	l.RLock()
	defer l.RUnlock()

	m, err := loadMeta(ctx, req.Storage, name)
	if err != nil || m == nil {
		return nil, err
	}
	return b.versionResponse(ctx, req.Storage, m, name, m.CurrentVersion)
}

func (b *backend) handleReadVersion(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, name := pathCertID(d)
	n := d.Get("version").(int)
	l := b.lock(name)
	l.RLock()
	defer l.RUnlock()

	m, err := loadMeta(ctx, req.Storage, name)
	if err != nil || m == nil {
		return nil, err
	}
	return b.versionResponse(ctx, req.Storage, m, name, n)
}

func (b *backend) versionResponse(ctx context.Context, s logical.Storage, m *certMeta, name string, n int) (*logical.Response, error) {
	v, err := loadVersion(ctx, s, name, n)
	if err != nil || v == nil {
		return nil, err
	}
	if v.destroyed() {
		return logical.ErrorResponse("the private key of version %d was destroyed at %s", n, v.DestroyedTime.Format(time.RFC3339)), nil
	}
	data := versionData(v)
	data["id"] = m.ID
	data["fullchain"] = v.Certificate + v.Chain
	data["certificate"] = v.Certificate
	data["chain"] = v.Chain
	data["privkey"] = v.Privkey
	return &logical.Response{Data: data}, nil
}

func (b *backend) handleInfo(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, name := pathCertID(d)
	l := b.lock(name)
	l.RLock()
	defer l.RUnlock()

	m, err := loadMeta(ctx, req.Storage, name)
	if err != nil || m == nil {
		return nil, err
	}
	return b.infoResponse(ctx, req.Storage, name, m)
}

func (b *backend) infoResponse(ctx context.Context, s logical.Storage, name string, m *certMeta) (*logical.Response, error) {
	current, err := loadVersion(ctx, s, name, m.CurrentVersion)
	if err != nil {
		return nil, err
	}
	if current == nil && m.CurrentVersion != 0 {
		return nil, fmt.Errorf("certificate %q: current version %d is missing", name, m.CurrentVersion)
	}

	ns, err := listVersions(ctx, s, name)
	if err != nil {
		return nil, err
	}
	versions := make(map[string]any, len(ns))
	for _, n := range ns {
		v, err := loadVersion(ctx, s, name, n)
		if err != nil {
			return nil, err
		}
		if v == nil {
			continue
		}
		entry := map[string]any{
			"created_time": v.CreatedTime,
			"sha256":       v.Description.SHA256,
			"not_after":    v.Description.NotAfter,
			"destroyed":    v.destroyed(),
		}
		versions[strconv.Itoa(n)] = entry
	}

	data := map[string]any{}
	if current != nil {
		data = versionData(current)
		data["destroyed"] = current.destroyed()
	}
	data["id"] = m.ID
	data["account"] = m.Account
	data["certificate_created_time"] = m.CreatedTime
	data["current_version"] = m.CurrentVersion
	data["latest_version"] = m.LatestVersion
	data["max_versions"] = m.MaxVersions
	data["versions"] = versions
	data["managed"] = m.Managed != nil
	if m.Managed != nil {
		data["definition"] = definitionData(m.Managed)
		data["issuance"] = issuanceData(m, current, b.now())
	}
	return &logical.Response{Data: data}, nil
}

func definitionData(s *managedSpec) map[string]any {
	return map[string]any{
		"names":        s.Names,
		"key_type":     s.KeyType,
		"account":      s.Account,
		"dns":          s.DNS,
		"reuse_key":    s.ReuseKey,
		"defined_time": s.DefinedTime,
	}
}

func issuanceData(m *certMeta, current *certVersion, now time.Time) map[string]any {
	data := map[string]any{"needed": needsIssuance(&certMeta{Managed: m.Managed}, current, now)}
	if st := m.Issuance; st != nil {
		data["last_attempt_time"] = st.LastAttemptTime
		data["last_success_time"] = st.LastSuccessTime
		data["last_error"] = st.LastError
		data["failures"] = st.Failures
		if !st.FailingSince.IsZero() {
			data["failing_since"] = st.FailingSince
		}
		data["next_attempt_time"] = st.NextAttemptTime
		data["renew_requested"] = st.RenewRequested
		data["rotate_key_requested"] = st.RotateKey
	}
	if r := m.Renewal; r != nil && current != nil && r.ForSHA256 == current.Description.SHA256 {
		data["renewal"] = map[string]any{
			"renew_at":        r.RenewAt,
			"source":          r.Source,
			"window_start":    r.WindowStart,
			"window_end":      r.WindowEnd,
			"explanation_url": r.ExplanationURL,
			"ari_error":       r.ARIError,
			"checked_time":    r.CheckedTime,
			"next_check_time": r.NextCheckTime,
		}
	}
	return data
}

func versionData(v *certVersion) map[string]any {
	d := v.Description
	data := map[string]any{
		"version":      v.Version,
		"created_time": v.CreatedTime,
		"source":       v.Source,
		"account_id":   v.AccountID,
		"names":        d.Names,
		"common_name":  d.CommonName,
		"not_before":   d.NotBefore,
		"not_after":    d.NotAfter,
		"serial":       d.Serial,
		"issuer":       d.Issuer,
		"sha256":       d.SHA256,
		"spki_sha256":  d.SPKISHA256,
		"key_type":     d.KeyType,
	}
	if v.ImportedBy != nil {
		data["imported_by"] = map[string]any{
			"entity_id":    v.ImportedBy.EntityID,
			"display_name": v.ImportedBy.DisplayName,
		}
	}
	return data
}

func (b *backend) handleImport(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	account, name := pathCertID(d)
	now := b.now().UTC()

	bundle, err := cert.Parse(d.Get("fullchain").(string), d.Get("privkey").(string), now)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	desc := bundle.Describe()

	maxVersions := 0
	if raw, ok := d.GetOk("max_versions"); ok {
		maxVersions = raw.(int)
		if maxVersions < 1 {
			return logical.ErrorResponse("max_versions must be at least 1"), logical.ErrInvalidRequest
		}
	}

	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	m, resp, err := newMeta(ctx, req.Storage, account, name, b.now().UTC())
	if resp != nil || err != nil {
		return resp, err
	}
	m.Account = account
	if m.LatestVersion > 0 {
		current, err := loadVersion(ctx, req.Storage, name, m.CurrentVersion)
		if err != nil {
			return nil, err
		}
		if current != nil && !current.destroyed() && current.Description.SHA256 == desc.SHA256 {
			if maxVersions > 0 && maxVersions != m.MaxVersions {
				m.MaxVersions = maxVersions
				if err := putJSON(ctx, req.Storage, metaKey(name), m); err != nil {
					return nil, err
				}
				if err := prune(ctx, req.Storage, name, m); err != nil {
					return nil, err
				}
			}
			return importResponse(current, false), nil
		}
	}
	if maxVersions > 0 {
		m.MaxVersions = maxVersions
	}

	var by *identity
	if req.EntityID != "" || req.DisplayName != "" {
		by = &identity{EntityID: req.EntityID, DisplayName: req.DisplayName}
	}
	v, err := writeVersion(ctx, req.Storage, name, m, bundle, sourceImport, by, now)
	if err != nil {
		return nil, err
	}
	return importResponse(v, true), nil
}

func importResponse(v *certVersion, written bool) *logical.Response {
	return &logical.Response{Data: map[string]any{
		"version":   v.Version,
		"written":   written,
		"sha256":    v.Description.SHA256,
		"names":     v.Description.Names,
		"not_after": v.Description.NotAfter,
	}}
}

func (b *backend) handleRollback(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, name := pathCertID(d)
	n := d.Get("version").(int)

	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	m, err := loadMeta(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return logical.ErrorResponse("no certificate named %q", name), logical.ErrInvalidRequest
	}
	v, err := loadVersion(ctx, req.Storage, name, n)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return logical.ErrorResponse("certificate %q has no version %d", name, n), logical.ErrInvalidRequest
	}
	if v.destroyed() {
		return logical.ErrorResponse("version %d has been destroyed", n), logical.ErrInvalidRequest
	}
	if !b.now().Before(v.Description.NotAfter) {
		return logical.ErrorResponse("version %d expired at %s", n, v.Description.NotAfter.Format(time.RFC3339)), logical.ErrInvalidRequest
	}
	if m.Managed != nil && !m.Managed.matches(v) {
		return logical.ErrorResponse("version %d does not match the managed definition, so the engine would replace it at once; unmanage the certificate first", n), logical.ErrInvalidRequest
	}

	m.CurrentVersion = n
	if err := putJSON(ctx, req.Storage, metaKey(name), m); err != nil {
		return nil, err
	}
	return b.infoResponse(ctx, req.Storage, name, m)
}

func (b *backend) handleDestroy(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, name := pathCertID(d)
	ns := d.Get("versions").([]int)
	spki := strings.ToLower(strings.TrimSpace(d.Get("spki_sha256").(string)))
	if (len(ns) == 0) == (spki == "") {
		return logical.ErrorResponse("give either versions or spki_sha256"), logical.ErrInvalidRequest
	}

	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	m, err := loadMeta(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return logical.ErrorResponse("no certificate named %q", name), logical.ErrInvalidRequest
	}
	all, err := listVersions(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	versions := map[int]*certVersion{}
	for _, n := range all {
		v, err := loadVersion(ctx, req.Storage, name, n)
		if err != nil {
			return nil, err
		}
		if v != nil {
			versions[n] = v
		}
	}

	targets := map[int]bool{}
	destroyedKeys := map[string]bool{}
	if spki != "" {
		for n, v := range versions {
			if v.Description.SPKISHA256 == spki {
				targets[n] = true
			}
		}
		if len(targets) == 0 {
			return logical.ErrorResponse("no version holds a key with spki_sha256 %s", spki), logical.ErrInvalidRequest
		}
	}
	for _, n := range ns {
		targets[n] = true
	}

	now := b.now().UTC()
	for n := range targets {
		v := versions[n]
		if v == nil {
			continue
		}
		destroyedKeys[v.Description.SPKISHA256] = true
		if v.destroyed() {
			continue
		}
		v.Privkey = ""
		v.DestroyedTime = &now
		if err := putJSON(ctx, req.Storage, versionKey(name, n), v); err != nil {
			return nil, err
		}
	}
	if err := clearInflightKey(ctx, req.Storage, name, destroyedKeys); err != nil {
		return nil, err
	}

	resp, err := b.infoResponse(ctx, req.Storage, name, m)
	if err != nil || resp == nil {
		return resp, err
	}
	for k := range destroyedKeys {
		var holders []string
		for _, n := range all {
			if v := versions[n]; v != nil && !v.destroyed() && v.Description.SPKISHA256 == k {
				holders = append(holders, strconv.Itoa(n))
			}
		}
		if len(holders) > 0 {
			resp.AddWarning(fmt.Sprintf("version(s) %s still hold the same key (spki_sha256 %s); destroy with spki_sha256 to remove it everywhere. It will not be reused.", strings.Join(holders, ", "), k))
		}
	}
	return resp, nil
}

func (b *backend) handleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, name := pathCertID(d)
	l := b.lock(name)
	l.Lock()
	defer l.Unlock()

	if m, err := loadMeta(ctx, req.Storage, name); err != nil || m == nil {
		return nil, err
	}
	return nil, deleteCert(ctx, req.Storage, name)
}
