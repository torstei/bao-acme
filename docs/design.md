# bao-acme: design

An external OpenBao secrets engine that stores TLS certificates with their keys, describes them
itself, and can obtain and renew them over ACME. Published independently as `bao-acme`
(`github.com/torstei/bao-acme`), under MPL-2.0.

**Status:** phase 1 (§9.4.1, imported certificates) is implemented. Where the implementation
settled a detail this sketch left open, the section says so, marked *Phase 1*.

## 1. The gap

1.1. OpenBao has no engine for certificates it did not issue itself. Its PKI engine is a CA (and an
ACME *server*). It cannot hold a certificate from Let's Encrypt or another public CA as a
certificate. It can only hold one as an opaque KV secret.

1.2. KV version 2 works, but leaves every user to rebuild the same things:

1.2.1. Data and `custom_metadata` are written in separate calls, with no transaction across them.

1.2.2. `custom_metadata` is kept per secret, not per version, so a rollback leaves it describing
another certificate.

1.2.3. Nothing describes the certificate (names, validity, fingerprints) unless the writer extracts
and stores it.

1.2.4. A policy cannot let a role see a certificate's description without also letting it see the
key, except through the metadata copy.

1.3. Obtaining and renewing happen outside OpenBao, typically certbot plus a deploy hook writing to
KV, with the ACME account and the DNS credentials on whatever host runs certbot.

1.4. There is demand. OpenBao issue #1983, "OpenBao as ACME Client or Proxy", is open. Its thread
covers why the existing community plugin (`remilapeyre/vault-acme`) does not fill it:

1.4.1. It has been unmaintained for about three years.

1.4.2. It does not support External Account Binding.

1.4.3. Its `lego` version is outdated, which breaks some DNS providers.

1.4.4. Its DNS credentials come from environment variables, not from OpenBao.

1.5. HashiCorp Vault 2.0 has a "PKI External CA" engine for this, but only in Vault Enterprise, and it
does not import certificates issued elsewhere.

## 2. Goals and non-goals

### Goals

2.1. Store certificates with their keys, versioned, with the description extracted by the engine
and kept atomically with each version.

2.2. Two kinds of certificate in one mount:

2.2.1. **Imported:** something else issues the certificate (certbot today, a manual purchase) and
writes it in.

2.2.2. **Managed:** the engine itself obtains and renews it over ACME.

2.3. Keep everything ACME needs in OpenBao: the account key, EAB credentials, DNS provider
credentials, and each certificate's definition. None of it is readable back.

2.4. Let policies separate reading the key from reading the description.

2.5. Renew on the CA's schedule where offered (ACME Renewal Information, RFC 9773), and on a sane
default otherwise.

### Non-goals

2.6. Being a CA. That is the PKI engine's job.

2.7. Distributing certificates to hosts. That is the consumers' job, for example an agent on each
host that fetches a certificate and hands it to a service through systemd's `LoadCredential=`.

2.8. HTTP-01 and TLS-ALPN-01 challenges. OpenBao cannot answer on the domains' ports 80 or 443, and
wildcards need DNS-01 anyway.

## 3. Shape

An external plugin (Go, OpenBao SDK), mounted like any engine:

```sh
bao plugin register -sha256=<sha256 of the binary> secret bao-acme
bao secrets enable -path=certificates bao-acme
```

The name keeps ACME in it and stays out of the `openbao-plugin-secrets-*` pattern, so it does not
read as a first-party OpenBao plugin.

Released first as a binary with its SHA-256 on GitHub releases. Later also as an OCI image, so it
can be installed through the declarative `plugin` block in the server configuration, pinned by
digest.

## 4. API

Paths are relative to the mount. "Write-only" fields are accepted on write and never returned:
reads show only whether they are set.

*v0.4.0 moves every path under an account (§4.5).* §4.1 and §4.2 describe what each path does,
and still apply; §4.5 says where the paths are now.

### 4.1. Configuration (operators)

| Path | Holds |
|---|---|
| `config/accounts/<account>` | ACME directory URL, contact address, EAB key id and HMAC key (write-only). The account key is generated inside the engine on first use and is never readable. Registering happens on first use, or explicitly with `config/accounts/<account>/register`. |
| `config/dns/<provider>` | A DNS provider by `lego` name (`rfc2136`, `cloudflare`, `route53`, ...) and its settings. Credentials are write-only. |

*Phase 2, accounts:*

4.1.1. An account's fields are:

4.1.1.1. `directory_url`: an https URL, or a CA name that lego knows, such as `letsencrypt` or
`letsencrypt-staging`.

4.1.1.2. `email`: optional, since Let's Encrypt no longer sends mail.

4.1.1.3. `key_type`: default `ecdsa-p256`.

4.1.1.4. `eab_kid` and `eab_hmac_key`.

4.1.1.5. `ca_bundle`: PEM certificates to trust for the ACME server's TLS, in addition to the
system roots, for a private ACME server such as step-ca or OpenBao's own PKI engine.

4.1.1.6. `terms_of_service_agreed`.

4.1.2. The account key is generated when the account is created, not on first use, so a stored
account always has one.

4.1.3. `register` makes the CA match the configuration. An account that is not yet registered is
registered, with EAB when it is configured. A registered one has its contact updated if `email`
changed, and its status refreshed. Registration is refused until `terms_of_service_agreed` is true,
and the refusal names the CA's terms of service URL. Registering on first use comes with issuance
(phase 3).

4.1.4. `directory_url`, `key_type` and EAB cannot change once they are bound: `key_type` from
creation, the others from registration. Changing them means a new account.

4.1.5. Reads show `eab_hmac_key_set`, never the key. A registered account's read also shows
`caa_records` and `caa_note` (§7.3.1).

4.1.6. Deleting an account removes it from the engine only. It is not deactivated at the CA, and
the response warns that its key is gone.

4.1.7. lego is given the HTTP client, account key and EAB values directly; nothing passes through
environment variables. Its log goes to OpenBao's log, at debug level, because it logs every request
together with the contact address.

*Phase 2, DNS providers:*

4.1.8. `config/dns/<name>` takes `provider` plus that provider's own settings as top-level fields,
and `ttl`, `propagation_timeout` and `polling_interval`. `<name>` is the operator's label. The
provider cannot change once created. A field that the provider does not take is refused, and an
empty value removes a setting.

4.1.9. Reads show non-secret settings, `<field>_set` for secret ones, and `egress`: where the
provider connects, for allow-listing. `bao path-help` lists every provider's fields and egress.

4.1.10. The first providers are:

| Provider | Settings | Egress |
|---|---|---|
| `domeneshop` | `api_token`, `api_secret` | HTTPS to `api.domeneshop.no` |
| `cloudflare` | `api_token` (and optionally `zone_api_token`), or `email` and `api_key` | HTTPS to `api.cloudflare.com` |
| `dnsupdate` (RFC 2136) | `nameserver`, `tsig_key`, `tsig_secret`, `tsig_algorithm` (default `hmac-sha256`), `zones` | DNS UPDATE on port 53 to `nameserver`, not through the proxy |

4.1.11. Each provider is built from lego's typed config, never from `NewDNSProvider()`, which reads
environment variables. Every field is also filled in by the engine, because lego's
`NewDefaultConfig()` reads environment variables for its defaults too. HTTP providers get the
engine's HTTP client, so they use the proxy of §7.1.1. `dnsupdate` takes its TSIG key inline: no
key files and no GSS-TSIG. Its default algorithm is HMAC-SHA256, not lego's HMAC-SHA1.

4.1.12. Route 53 is left out for now. Without explicit keys, lego falls back to the AWS default
credential chain (environment variables, `~/.aws`, the EC2 instance metadata service), which is
implicit credentials and implicit egress. It also adds several megabytes of AWS SDK. It can be
added with static credentials and the engine's HTTP client only, when someone needs it.

### 4.2. Certificates

| Path | Method | What |
|---|---|---|
| `certs/<name>` | write | Defines a **managed** certificate: `names`, `key_type` (`ecdsa-p256`, `rsa-2048`, ...), `account`, `dns_provider` (optionally per name or zone), `reuse_key`, and the renewal settings (§6.4). Issues the first certificate asynchronously. |
| `certs/<name>/import` | write | Writes a new version of an **imported** certificate: `fullchain` and `privkey` as PEM, optionally `max_versions`. The engine validates and describes it (§5.2). An unchanged certificate is not written again. The response gives `version` and `written`, so an importer on a timer can tell whether anything changed. |
| `certs/<name>` | read | The current version: `fullchain`, `certificate` (the leaf alone), `chain` (the intermediates), `privkey`, the description, and `version`. |
| `certs/<name>` | delete | Deletes the certificate and all its versions. |
| `certs/<name>/versions/<n>` | read | An earlier version, the same way. |
| `certs/<name>/info` | read | The description and version state, **no key**. This is the path for monitoring, inventories and "has it changed" checks. |
| `certs/<name>/status` | read | For managed certificates: the next planned renewal and why (ARI window or default), the last attempt and its error, and the order in progress. |
| `certs/<name>/renew` | write | Renew now, ignoring the schedule. |
| `certs/<name>/rollback` | write | Make version `n` current again. Its description comes with it. |
| `certs/<name>/destroy` | write | Destroy the key material of given versions, or with `spki_sha256` of every version holding that key, for a compromised key. |
| `certs/` | list | Names. With a `covers=<host>` filter, only certificates whose names cover that host, applying the one-level wildcard rule. |

*Phase 1:* `info` also returns `current_version`, `latest_version`, `max_versions`, `destroyed`,
and `versions`, which maps each kept version to its `created_time`, `sha256`, `not_after` and
`destroyed`. Certificate names follow OpenBao's usual name rule (letters, digits, `-`, `.`, `_`),
so a wildcard is named, for example, `wildcard.example.com`. The `covers` filter is a query
parameter on `LIST`. With no match, the list is empty and the HTTP status is 404, as for any
empty list in OpenBao.

*Phase 3, managed certificates:*

4.2.1. Writing `names`, `account` and `dns_provider` (and optionally `key_type`, default
`ecdsa-p256`) to `certs/<name>` defines a managed certificate. Names are lowercased, sorted and
deduplicated. A wildcard is allowed only as the whole leftmost label, IP addresses are refused
(DNS-01 cannot validate them), and international names must be in their A-label (`xn--`) form. The
account and the DNS provider must exist. The write returns at once, with `issuing: true` when it
started an issuance, because an order with DNS propagation can outlast OpenBao's request timeout.

4.2.2. A certificate needs issuing when its current version is missing, destroyed, expired, or
does not match the definition (names and key type). That makes an imported certificate with the
same names and key type count as satisfying the definition: the engine leaves it alone until
renewal (phase 4). One with other names is replaced, and its versions are kept, so the imported
version is served until the first issuance succeeds.

4.2.3. Changing the definition (names, key type, account or DNS provider) clears the backoff and
issues again. Writing the same definition again changes nothing.

4.2.4. `info` adds `managed`, `definition`, and `issuance`: `needed` (why an issuance is due, or
empty), `last_attempt_time`, `last_success_time`, `last_error`, `failures` and
`next_attempt_time`. Before the first certificate exists, `info` shows only these, and reading
`certs/<name>` returns not found.

4.2.5. `certs/<name>/unmanage` returns a certificate to import-only, keeping its versions. A
managed certificate that never got a version is removed entirely. Importing into a managed
certificate is allowed, so certbot can stay a fallback (§8.3). Rolling a managed certificate back
to a version that does not match its definition is refused, because the engine would replace it at
once.

4.2.6. An account that is not yet registered is registered at the first issuance, if its terms of
service are agreed to.

4.2.7. *Phase 4:* `certs/<name>/renew` renews a managed certificate now, ignoring its schedule and
clearing any backoff. `info.issuance` adds `renew_requested`, and `renewal` for the current version:
`renew_at`, `source` (`ari` or `default`), `window_start`, `window_end`, `explanation_url`,
`ari_error`, `checked_time` and `next_check_time`.

4.2.8. *v0.3.0, status:* `certs/<name>/status` sums a certificate up for monitoring, for imported
and managed certificates alike:

4.2.8.1. `state`, exactly one of `valid`, `renewal_due`, `renewing`, `issuing` (the first
certificate is being obtained), `pending` (no certificate yet, nothing running), `failing` and
`expired`. When several apply, the first of `expired`, `renewing`, `failing`, `renewal_due` wins.
A renewal that is running after earlier failures is therefore `renewing`.

4.2.8.2. `expires_in` in seconds, `not_after`, `version`, `renew_at`, `failures`.

4.2.8.3. `running`, and while a job runs on this node, `running_since` and `running_reason`. A
job that only checks the renewal schedule does not count as `renewing`. Which step of an order is
running needs the persisted state machine (#9).

4.2.8.4. The issuance fields of `info`, and `attempts`: the last ten attempts, newest first, with
`start_time`, `duration_seconds`, `reason`, `outcome` (`issued` or `failed`), `error` and
`version`. The history survives a change of definition.

4.2.8.5. `inflight`, while an attempt runs or after one was interrupted: `start_time`, `reason`,
`order_url`, `published` (each record's `domain`, `published_time` and `cleanup_error`) and
`next_cleanup_time` (§6.2.2).

4.2.9. `status`, at the mount, gives every certificate's summary (`state`, `expires_in`,
`not_after`, `renew_at`, `failures`, `running`) and `counts` per state, so one read answers "is
anything failing or about to expire". It is a separate path from `certs/`, so a monitoring policy
can grant it alone.

4.2.10. *v0.3.0, reusing keys:* with `reuse_key=true` in the definition, an issuance uses the
current version's key, so the public key stays the same for consumers that pin it (DANE `3 1 1`,
mTLS allow-lists). An imported certificate's key is reused too, so a certbot key survives the
migration (§8). A new key is made when there is no usable current key, when the key type changes,
and once after `certs/<name>/renew` with `rotate_key=true`; later renewals reuse that one.

4.2.10.1. Each version holds its own copy of the key, so `destroy` takes either `versions` or
`spki_sha256`. The latter destroys the key in every version holding it. Destroying by version warns
when other versions still hold the same key.

4.2.10.2. A key that any destroyed version held is never reused. Destroying a key also clears it from
an attempt in flight, and an attempt that obtained a certificate for a key destroyed meanwhile does
not store it: it fails and retries at once with a new key.

4.2.10.3. A CA may refuse a key, for example one it has seen revoked for key compromise. Such a
failure shows in `status`, and `renew rotate_key=true` moves on.

Because the key and the description are on different paths, policies get the split that KV cannot
give:

```hcl
path "certificates/certs/example.com"     { capabilities = ["read"] }   # a consumer
path "certificates/certs/+/info"          { capabilities = ["read"] }   # monitoring
path "certificates/certs/+/import"        { capabilities = ["update"] } # an importer
```

The action paths (`import`, `rollback`, `destroy`, `renew`) have no existence check, so a write to
them is always an `update`, never a `create`.

### 4.3. The description

Extracted by the engine from the certificate, never supplied by the writer:

| Field | |
|---|---|
| `names` | subjectAltName DNS names, lowercased and sorted, wildcards as written, followed by IP addresses, if present. |
| `common_name` | for display only. Clients check `names`. |
| `not_before`, `not_after` | RFC 3339, UTC. |
| `serial`, `issuer` | `issuer` in readable form, e.g. `Let's Encrypt YR2`. |
| `sha256`, `spki_sha256` | fingerprints of the certificate and of its public key. |
| `key_type` | e.g. `ecdsa-p256`. |
| `source` | `acme:<account>` or `import`. An import also records `imported_by`: the token's `entity_id` and `display_name`. |
| `created_time`, `version` | per version. |
| `renewal_window` | managed certificates only: ARI's suggested window, if the CA gave one. |

### 4.4. Compatibility with KV version 2 (optional)

A read-only `data/<name>` path answering in KV version 2's shape (`data.fullchain`, `data.privkey`
and so on) would let consumers written against a KV layout switch mounts without changing. Cheap to add, and worth it only if such consumers exist.

### 4.5. Everything under an account (v0.4.0)

4.5.1. **Why.** OpenBao authorizes by path. Up to v0.3.0, a definition at `certs/<name>` chose its
`account` and `dns_provider` in its fields, so whoever could write any certificate path could
obtain a certificate, key included, for every name any configured DNS provider could prove. From
v0.4.0 the ACME account is the unit of authority, and every use of an account names it in its
path. A policy on `accounts/<account>/*` is then the whole authorization for one team, or one
purpose.

4.5.2. The account is also a boundary at the CA. With CAA `accounturi` (§7.3), a zone can be
pinned to one account, and the CA refuses every other account for it, whatever DNS records it can
publish. The engine's boundary and the CA's are the same.

4.5.3. **Settings and use have separate prefixes,** as is usual in OpenBao (the PKI engine has
`roles/<role>` and `issue/<role>`). An account's settings stay at `config/accounts/<account>`;
everything done with the account is under `accounts/<account>/`. No path differs from another only
by a trailing slash, so a policy cannot grant one where the other was meant, and
`accounts/<account>` itself has no operations.

4.5.4. Paths, relative to the mount:

| Path | Method | What |
|---|---|---|
| `config/accounts/` | list | Account names. |
| `config/accounts/<account>` | write, read, delete | The account, as before (§4.1). `directory_url` is needed only to register and issue, so an account may hold just imported certificates. Delete is refused while the account owns certificates or DNS providers. |
| `config/accounts/<account>/register` | write | As before. |
| `accounts/<account>/dns/` | list | The account's DNS providers. |
| `accounts/<account>/dns/<provider>` | write, read, delete | A DNS provider, as `config/dns/<name>` was. Usable only by this account's certificates. Delete is refused while a certificate uses it, or an in-flight entry still needs it to remove records. |
| `accounts/<account>/certs/` | list | The account's certificates, with `covers` as before. Found by reading each certificate's owner, which is fine for hundreds of certificates. |
| `accounts/<account>/certs/<cert>` | write, read, delete | As `certs/<name>` was. A definition takes `names`, `dns_provider` (one of this account's), `key_type` and `reuse_key`; no `account`, since the path gives it. |
| `accounts/<account>/certs/<cert>/…` | | `import`, `info`, `status`, `versions/<n>`, `rollback`, `destroy`, `renew`, `unmanage`, as before. |
| `accounts/<account>/status` | read | The account's certificates, as the mount's `status`. |
| `config/network` | write, read, delete | Unchanged: mount-wide, for the operator. |
| `status` | read | Unchanged: every account's certificates. |

4.5.5. Certificate and DNS provider names are unique per mount, not per account: two teams sharing
a mount cannot both have a certificate called `www`, and use a naming convention such as
`team-a-www` instead. Writing a name another account owns is refused. A DNS key that two accounts
both need is entered twice, under two names. That is duplication, but it makes explicit who can use
which credentials.

4.5.6. `config/dns/` and `certs/` are removed. Nothing has been deployed against them, so there is
no transition period.

4.5.7. Example policies:

```hcl
# a team: everything done with its own account
path "acme/accounts/team-a/*" { capabilities = ["create", "read", "update", "delete", "list"] }

# a team that may also see its account's settings, such as the CAA records to publish
path "acme/config/accounts/team-a" { capabilities = ["read"] }

# a team whose DNS credentials the operator manages: certificates only
path "acme/accounts/team-a/certs/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "acme/accounts/team-a/status"  { capabilities = ["read"] }

# a consumer: one certificate, key included
path "acme/accounts/team-a/certs/www" { capabilities = ["read"] }

# monitoring: every state, no keys
path "acme/status" { capabilities = ["read"] }

# the operator: network settings and accounts
path "acme/config/network"    { capabilities = ["create", "read", "update", "delete"] }
path "acme/config/accounts/*" { capabilities = ["create", "read", "update", "delete", "list"] }
```

Write `accounts/team-a/*`, with the slash. `accounts/team-a*` also matches `accounts/team-ab/…`.

4.5.8. When one DNS key covers more names than an account should have, for example one Domeneshop
login holding every team's zones, the credentials do not limit the account. An optional
`allowed_domains` on the account, set by the operator and checked when a definition is written,
would. It is left for when someone needs it (#30). Until then, give each account credentials that
cover only its own names, or CAA-pin the other names to their accounts.

4.5.9. Separate mounts per team remain possible, for anyone who wants each team's accounts,
network settings and monitoring fully apart.

4.5.10. The storage stays format 1. Certificates and DNS providers gain an `account` field naming
their owner (§5.7).

## 5. Storage

5.1. **One transaction per version.** Writing a version means writing the certificate, key,
description and the "current" pointer together:

5.1.1. External plugins get OpenBao's transactional storage over gRPC
(`GRPCTransactionalStorageClient` in `sdk/plugin/grpc_storage.go`) when the storage backend supports
it, as Raft does.

5.1.2. On a backend without transactions, write the version entry first and move the "current"
pointer last. A crash then leaves an unreferenced version, never a current one that is incomplete.

5.1.3. *Phase 1:* no transactions are needed. Each version is one storage entry
(`certs/<name>/versions/<n>`) holding the certificate, key and description together, so writing
it is a single atomic `Put`. The per-certificate entry `certs/<name>/meta` (current and latest
version, `max_versions`) is written after it, as in §5.1.2. An orphaned version left by a crash
is overwritten by the next import. Writes to one certificate are serialised by a per-name lock,
and `certs/` is seal-wrapped.

5.2. **Validation on write**, for imports and for issued certificates alike:

5.2.1. The chain parses. It holds only `CERTIFICATE` blocks, leaf first, and each certificate is
signed by the next one.

5.2.2. The key matches the certificate. PKCS #8, PKCS #1 and SEC 1 keys are accepted and stored
re-encoded as PKCS #8. Certificates are re-encoded too, so stored PEM does not depend on the
writer's formatting.

5.2.3. The certificate is within its validity period.

5.2.4. Optionally, the chain must lead to a configured set of roots, which refuses a staging
certificate in production. *Not in phase 1.*

5.3. **Unchanged imports are not written.** An import whose `sha256` equals the current version's
returns the current version, so an importer can run on a timer without creating versions.

5.4. **History:** `max_versions` per certificate (default 3). Older versions are deleted with their
key material. `destroy` removes key material but keeps the description, so it remains visible what
was there.

5.5. *Phase 1, rollback:* `rollback` moves the "current" pointer back. It does not copy the old
version into a new one, as KV version 2 does. The current version is never pruned, even when it
falls outside `max_versions`. Rolling back to a destroyed or expired version is refused. An
importer on a timer that still holds the newer certificate writes it again on its next run and
so undoes the rollback, so stop the importer before rolling back.

5.6. **Storage compatibility.** OpenBao owns everything below the plugin: the physical backend,
the barrier's encryption, and the mount's storage view (`logical/<mount-uuid>/`). The plugin sees
only `Get`, `Put`, `List` and `Delete` of key → bytes. The key layout and the JSON in those
entries are the engine's own format. Only the engine reads them; the API's responses are built
from them, but are a separate contract (§4). Every release must read what every earlier release
wrote, both on upgrade and when restoring an old Raft snapshot.

5.6.1. Keys, relative to the mount:

| Key | Holds |
|---|---|
| `certs/<name>/meta` | Which version is current, the latest version number, `max_versions`, and for a managed certificate its `managed` definition and `issuance` state. |
| `certs/<name>/versions/<n>` | One version: certificate, chain, key and description, in one entry. |
| `config/accounts/<name>` | An ACME account: its settings, its key (PKCS #8 PEM), and, once registered, a `registration` object with the account URL, status, contact and terms of service URL. |
| `config/network` | The proxy URL, credentials included, `proxy_ca_bundle`, and the DNS settings of §7.1.7. Absent means direct connections and the defaults. |
| `config/dns/<name>` | A DNS provider: `provider`, a `settings` object with its fields, credentials included, and the common timing settings. |
| `certs/<name>/inflight` | While an attempt runs, or after it was interrupted: the attempt's private key, its definition, the order URL, and the challenge records not yet removed (§6.2.2). |

5.6.2. A `meta` entry:

```json
{ "current_version": 2, "latest_version": 2, "max_versions": 3 }
```

5.6.3. A `versions/<n>` entry, about 2 KB for ECDSA P-256, with the PEM shortened here:

```json
{
  "version": 2,
  "created_time": "2026-10-18T13:15:44.106773629Z",
  "source": "import",
  "imported_by": { "entity_id": "…", "display_name": "approle-importer" },
  "description": {
    "names": ["*.example.com", "example.com"],
    "common_name": "example.com",
    "not_before": "2026-10-18T12:15:44Z",
    "not_after": "2027-01-16T12:15:44Z",
    "serial": "9dddfee823ec492d",
    "issuer": "Test CA T1",
    "sha256": "0ea103f6…",
    "spki_sha256": "38d228ee…",
    "key_type": "ecdsa-p256"
  },
  "certificate": "-----BEGIN CERTIFICATE-----\n…",
  "chain": "-----BEGIN CERTIFICATE-----\n…",
  "privkey": "-----BEGIN PRIVATE KEY-----\n…"
}
```

`fullchain` is not stored: reads return `certificate` followed by `chain`. A destroyed version
has no `privkey` and gains `"destroyed_time"`. `imported_by` is absent when the
request carried no identity. The description is kept as it was extracted at write time. A later
release that describes certificates differently does not rewrite old versions.

5.6.4. Rules for changing the format:

5.6.4.1. Adding a field needs nothing. Older releases ignore fields they do not know, and newer
releases read a missing field as its zero value. That zero value must therefore mean what the
older release did.

5.6.4.2. Renaming or moving a field or key needs a migration: either converting entries when they
are read, or a one-off upgrade at mount time (`InitializeFunc`) that records a storage version.
With no storage-version entry, the format is the one described here.

5.6.4.3. Downgrading loses data. An older release that rewrites an entry, for example on
`destroy`, drops the fields it does not know. Release notes must say so for the first release
that adds a field whose loss matters.

5.6.4.4. These rules apply from the first release, `v0.1.0`, regardless of semantic versioning's
pre-1.0 leeway.

5.6.5. Tests enforce this format. `internal/backend/testdata/storage-v1/` holds real entries in
this format, one file per storage key. A file is never regenerated once a release has shipped it.
A new kind of entry adds its file when it is introduced. One test loads them and reads
them through the API. Another checks that a fresh write still produces every field they have, so
a renamed JSON tag fails CI. A new storage format adds a `storage-v2/` beside it, and `storage-v1/`
stays.

5.7. **Owners (v0.4.0).** The account-scoped paths of §4.5 keep storage format 1: the keys stay
where they are, and two entries gain a field.

5.7.1. A certificate's `certs/<cert>/meta` and a DNS provider's `config/dns/<provider>` gain
`account`: the owning account's name, as in `accounts/<account>`.

```json
{ "account": "team-a", "current_version": 2, "latest_version": 2, "max_versions": 3, "managed": { … } }
```

5.7.2. A name is enough because an account cannot be deleted while it owns certificates or DNS
providers (§4.5.4), and accounts cannot be renamed. So no entry can point at an account that is
gone, or at a new account later created under the same name.

5.7.3. A managed certificate's definition already names its account (`managed.account`). The field
stays, so format 1 entries read as before, and new writes set it to the same value as `account`.
When reading, `account` wins, and an entry without one, from v0.3.0 or earlier, belongs to
`managed.account`. An imported certificate from v0.3.0 or earlier has neither, so no account path
reaches it; it is still kept, and still counted in the mount's `status`. Such data is
theoretical: v0.4.0 is the first version meant for use with accounts.

5.7.4. Both fields are additive, so the rules of §5.6.4 hold: the format 1 fixtures stay frozen,
and new ones record the field.

## 6. Issuing and renewing (managed certificates)

6.1. **On the active node only.** The plugin's `PeriodicFunc` (`sdk/framework/backend.go`) picks
certificates that are due and starts their work in the background. It does not block the periodic
call.

6.1.0. OpenBao 2.x also calls it on read-enabled standbys, which set up mounts read-only and mark
themselves `ReplicationPerformanceStandby`. Work started there would act on the DNS provider and
the CA before failing at its first write: in v0.4.0 a standby, taking the active node's attempt
for an interrupted one, removed its challenge record (#37). So both the periodic function and
each job first check `System().ReplicationState()`, and do nothing on a performance standby or a
DR secondary, as OpenBao's PKI engine does.

6.1.1. *Phase 3:* the periodic function runs every minute and starts an issuance for each
certificate that needs one (§4.2.2) and is past its backoff. That is also what resumes work after a
restart or failover: an attempt cut short simply happens again. Each certificate has at most one
job running; work asked for while it runs (a write, `renew`) makes it run once more afterwards,
so the request is never lost. Each certificate has at most one issuance running, and issuances that set lego's process-wide DNS client run one at a time
(§7.1.9). An issuance is given 15 minutes. Background work uses the mount's storage view, not a
request's, and stops when the mount is unmounted or the plugin reloaded.

6.2. **Orders are persisted as a state machine.** The steps: order created, authorizations pending,
DNS records published, challenge answered, finalized, downloaded. A failover or restart resumes the
order instead of starting over. This matters for CA rate limits.

6.2.1. *v0.3.0: recovery, not a full state machine.* Persisting every step would mean replacing
lego's `Obtain()` with the engine's own order flow on lego's lower-level API. A restart in the
middle of an order costs little, though: a new order is well within the CA's limits, and the CA
reuses the authorizations it already validated. Two things are really lost, and those are what
the engine recovers:

6.2.1.1. A certificate the CA issued but the engine never stored, which costs one of the CA's
duplicate certificates (five a week at Let's Encrypt).

6.2.1.2. Challenge records published but never removed.

6.2.2. An attempt writes `certs/<name>/inflight` before anything reaches the CA. It holds the new
private key, the definition it is for, and, as they happen, the order URL and each challenge
record. lego gets the engine's HTTP client, so the order URL is read from the CA's answer to
`newOrder` without changing lego's flow. Each record is written down before it is published, and
dropped once removed. A finished attempt deletes the entry.

6.2.3. When a certificate's background job finds an entry left by an attempt that is no longer
running, it first removes the leftover records through the DNS provider. It then asks the CA for
the order: if the order is valid, the job downloads its certificate, checks it against the stored
key, and stores it as the next version, as an attempt "recovered after an interruption". Otherwise
it drops the entry, and a new order follows if one is due.

6.2.4. A record that cannot be removed is kept, with the error, and retried hourly. `status` shows
it under `inflight`, but never the key. A record whose publishing failed is dropped if removing it
also fails, since it most likely never existed. lego's Cloudflare provider keeps the IDs of
records it created in memory, so after a restart it cannot remove them: those stay visible in
`status` until removed by hand. Domeneshop and `dnsupdate` find records by name and value.

6.3. **DNS-01 via `lego`'s providers.** `lego` is used as a library, pinned, with 200+ DNS providers,
including RFC 2136 dynamic updates for self-hosted name servers.

6.3.1. Publish the TXT records.

6.3.2. Wait for them to propagate to the zone's authoritative servers.

6.3.3. Answer the challenge.

6.3.4. Always remove the records afterwards, including after failures.

6.3.5. **Credentials are never passed through environment variables.** lego's providers read
their settings from the environment, which the whole process shares, so concurrent issuances
could see each other's credentials. Each provider is constructed from its typed config
(`NewDNSProviderConfig`) instead. Typed adapters come first for `domeneshop`, `rfc2136`,
`cloudflare` and `route53`. A generic fallback for the other providers could set the variables
under a mutex just for the constructor call, which is when providers read them. *Decided in
v0.3.0:* no such fallback. It would bring environment variables back (§7.1.2), and a path shared by
providers that each read their settings differently cannot be tested properly. Further providers
are added typed, one at a time, when someone needs one (#3).

6.4. **When to renew:**

6.4.1. If the CA's directory has `renewalInfo` (RFC 9773, which Let's Encrypt supports), fetch the
suggested window and pick a random point in it. ARI also lets the CA ask for an early renewal, for
example after a mass revocation.

6.4.2. Otherwise renew when a third of the lifetime remains, with jitter.

6.4.3. Certificate lifetimes are shrinking, so this must not assume 90 days. The CA/Browser Forum's
ballot SC-081 takes the maximum down to 47 days by 2029.

6.4.4. *Phase 4:* the schedule belongs to one version, identified by its `sha256`, and is worked
out in the background job that also issues. With ARI, `renew_at` is a random time in the CA's
suggested window. Asking again keeps the same time as long as the window still contains it, so
renewals do not move about. ARI is asked again after the CA's `Retry-After`, clamped to between
one and 24 hours, and that is how a request to renew early (a revocation, a mass incident) is
picked up.

6.4.5. Without ARI, `renew_at` is a third of the lifetime before expiry, less up to a thirtieth of
the lifetime as jitter. That covers a CA without ARI (checked again daily), a certificate the CA
does not know, such as an imported one from another CA (also daily), and a failed request
(retried after an hour, with the error in `ari_error`). Imported certificates from the same CA
get ARI like issued ones, because asking needs no account.

6.4.6. A renewal names the certificate it replaces (RFC 9773 `replaces`) only when this account
issued it, because a CA refuses to link certificates across accounts. If the CA answers that the
certificate was already replaced, lego orders again without it.

6.4.7. A CA may reuse an authorization it validated recently for the same account and name. A
renewal soon after issuance then needs no DNS-01 challenge, so it succeeds even when the DNS
provider is misconfigured. Issuing does not prove the DNS provider still works.

6.5. **Failures:** exponential backoff per certificate, within the CA's rate limits. Every failure is
kept in `status` and in the logs. When renewals keep failing, `info` shows how close the current
certificate is to expiry, so monitoring needs no access to the engine's internals.

6.5.1. *Phase 3:* the first retry comes after a minute, and each further one waits twice as long,
up to six hours, with ±10% jitter. A failure is recorded only for the definition it was tried
for: a certificate obtained for a definition that changed in the meantime is discarded.

6.6. **While sealed, nothing renews.** The renewal window has to be long enough to survive an outage
of the cluster. Expiry monitoring through `info` covers that.

## 7. Security

7.1. **Egress.** A managed certificate needs the cluster to reach the ACME CA and the DNS provider's
API. For a cluster that holds every secret, that is a real change. It should be a deliberate network
decision, and imports alone need no egress.

7.1.1. **All HTTP egress can go through one proxy, so it can be reviewed.** `config/network` holds
`proxy_url`, an `http://` or `https://` forward proxy, and `proxy_ca_bundle` for a proxy with its
own TLS certificate or one that inspects TLS. Credentials in the URL are write-only. When a proxy is
set, every request the engine makes goes through it, with no direct fallback: the ACME directory,
orders, ARI, and the DNS providers' APIs. HTTPS uses `CONNECT`, so the proxy sees each host name and
can allow-list it (for example `acme-v02.api.letsencrypt.org` and `api.domeneshop.no`) without
seeing the content.

7.1.2. The proxy is the engine's own configuration, not the environment. OpenBao starts a plugin
with an empty environment plus its own variables, so the server's `HTTPS_PROXY` never reaches the
plugin. The only route is `bao plugin register -env`, which is process-wide and not visible in the
engine's configuration. Go also reads the proxy variables only once per process. The engine
therefore ignores proxy environment variables altogether, even ones given with `-env`, so that
`config/network` is the whole story.

7.1.3. Every DNS provider must therefore take an injected HTTP client. lego providers whose typed
config has no HTTP client field cannot be proxied, and are refused while a proxy is set.

7.1.4. **DNS is not HTTP.** No proxy carries DNS queries. A DNS-01 challenge makes two kinds of
lookups:

7.1.4.1. Discovery, through recursive resolvers: following CNAMEs from `_acme-challenge.<name>`,
then finding the zone (SOA) and its authoritative servers (NS). These records are stable, so
caching does them no harm.

7.1.4.2. The propagation check, against the zone's authoritative servers directly, on port 53
(UDP, falling back to TCP). Asking the authoritative servers is what makes the check reliable: a
recursive resolver may hold a cached answer, including a cached "no such record" from before the
TXT record was published.

7.1.4.3. The propagation check is about timing, not security. It only decides when to ask the CA
to validate. The CA then looks the record up itself, from its own resolvers in several network
locations, and that is the step that matters. A stale or forged answer to the engine's check can
at worst make it ask too early: the validation fails, the order starts over, and the failure counts
against the CA's limit on failed validations. Skipping the check (`none`, below) is safe, at the
cost of always waiting long enough for the slowest propagation. The discovery lookups are needed
either way, because many providers need the zone name before they can call the provider's API.

7.1.5. **The default is to check the authoritative servers only.** lego by default also requires
the record to be visible through the recursive resolvers. The engine turns that off, because it
is the step that negative caching delays.

7.1.6. **The DNS egress is documented as a requirement, not hidden.** It is UDP and TCP port 53 to
the authoritative servers of each zone the engine issues for, plus the recursive resolvers. For
one DNS provider, the authoritative servers are a small fixed set, given by `dig NS <zone>`, so they
can be allow-listed.

7.1.7. `config/network` also takes these DNS settings:

7.1.7.1. `dns_resolvers`: the recursive resolvers to use for discovery, as `host` or
`host:port`. By default, the ones in the OpenBao host's `/etc/resolv.conf`. If there are none, the
engine refuses to issue. lego would instead fall back to public resolvers, which would be egress
nobody chose.

7.1.7.2. `dns_propagation_check`: `authoritative` (the default), `resolvers` (check through
`dns_resolvers` instead, for networks that cannot reach authoritative servers, accepting the
caching delay), or `none`.

7.1.7.3. `dns_propagation_delay`: a fixed wait before the CA is told to validate. With `none` it
replaces the check, and it is required.

7.1.7.4. `dns_tcp_only`: send every DNS query over TCP, for firewalls that allow only that.

7.1.8. With a proxy set and `dns_propagation_check = resolvers`, the engine's whole egress is the
proxy and the resolvers. The CA's own validation queries go to the public DNS, not to the
cluster, and need nothing from it.

7.1.9. lego keeps its DNS settings process-wide. Mounts served by one plugin process that use
different settings therefore have their issuances serialised (§6).

7.2. **DNS credentials can obtain certificates.** Whoever controls the DNS credentials, or the
engine's configuration paths, can get certificates for those names. Policies on `config/` should be
as narrow as those on root-level operations.

7.3. **CAA records with `accounturi` (RFC 8657).** These pin issuance for a domain to the engine's
ACME account and to `dns-01`. Then even someone who can change DNS records elsewhere cannot get a
certificate through another account. The engine can show the exact CAA record to publish for each
account.

7.3.1. *Phase 2:* a registered account's read shows `caa_records`: for each issuer domain name the
CA lists in its directory (`caaIdentities`, for example `letsencrypt.org`), an `issue` and an
`issuewild` value:

```
0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123; validationmethods=dns-01"
0 issuewild "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123; validationmethods=dns-01"
```

The identities are stored at registration. A CA that lists none gets no records, and a note
saying so.

7.3.2. CAA applies to the name and everything below it, unless a subdomain has CAA records of its
own, so one pair on the zone apex usually covers a zone. Publishing it shuts out every other ACME
account, certbot's included. During the migration (§8), add a further `issue` record with
certbot's account URL (the `uri` in its `regr.json`), or publish the pair only after certbot is
retired. With `dns-persist-01` (#20), `validationmethods` would have to name that method too.

7.4. **No key leaves the engine except through `certs/<name>` reads.** Account keys are never
exported. Private keys are generated inside the engine, and `reuse_key` keeps a key across renewals
when a consumer pins it.

7.5. **Audit.** OpenBao's audit log HMACs response fields by default, so certificates and keys do
not appear in clear text there.

## 8. Moving from certbot and a KV mount

8.1. Mount the engine and create the account (§4.5), for now without `directory_url`. Start the
importer writing to `accounts/<account>/certs/<name>/import` instead of KV, or have
the engine import the current certificate once.

8.2. Point consumers at the engine's paths, or use §4.4 so they do not change at all.

8.3. Configure the account and the DNS provider. Change the certificate from imported to managed, so
its next renewal is the engine's own. Keep certbot as a fallback until a renewal has gone through.
With the same names and key type, writing the definition changes nothing at once (§4.2.2); with
other names, the engine issues at once. `accounts/<account>/certs/<name>/unmanage` goes back.

8.4. Retire certbot and the importer.

## 9. Building it

9.1. **Language and code:** Go, against OpenBao's `sdk/framework`, with `lego` as the ACME client.
Licence MPL-2.0, as OpenBao itself.

9.2. **Tests:**

9.2.1. Unit tests for parsing, describing, validating and wildcard matching.

9.2.2. Integration tests against **Pebble** (Let's Encrypt's test ACME server, which supports ARI)
with `pebble-challtestsrv` as the DNS, and a real OpenBao in Docker.

9.2.3. Failover in the middle of an order, against a three-node Raft cluster.

9.3. **Release:** an OCI image with the plugin binary, signed, so it can be pinned by digest in the
`plugin` block.

9.4. **Order of work:**

9.4.1. Imported certificates alone: storage, description, `info`, policies.

9.4.2. ACME accounts and DNS providers.

9.4.3. Issuance.

9.4.4. Renewal with ARI.

9.4.5. The KV compatibility path, if needed.

9.4.6. Step 9.4.1 is already useful by itself. It replaces the KV pattern of keeping the description
twice, in the data and in `custom_metadata` (§1.2).

9.4.7. Status: 9.4.1 is done, with unit tests against in-memory storage and an integration test
(`make integration`) that runs the plugin in OpenBao 2.7.0 in Docker. The integration test covers
importing, the policy split of §4.2, `covers`, a plugin reload, and that the audit log has no key
in clear text (§7.5). The audit device is declared in the server configuration, because OpenBao
2.x does not allow enabling one through the API. Releases are tag-driven: static linux/amd64 and
linux/arm64 binaries with `SHA256SUMS` and build provenance attestations, published only for a
commit whose CI has passed. The signed OCI image of §9.3 comes later.

## 10. Open questions

10.1. Whether to upstream into `openbao/openbao-plugins`, or publish independently first.
*Decided:* publish independently first, and offer it upstream once it has users.

10.2. Whether an ACME *proxy* mode is in scope: the engine as an ACME server for internal clients,
validating against the public CA on their behalf. Suggested in #1983. It is attractive, but a large
step up in scope.

10.3. Notifying consumers when a certificate changes. Polling `info` works. A push mechanism would
depend on what OpenBao offers.

10.4. Per-name DNS providers for certificates that span zones on different providers.

10.5. What `destroy` means once `reuse_key` exists (phase 3). Each version holds its own copy of
the key, so destroying one version of a compromised reused key leaves the same key in the others.
The likely answer is a way to destroy every version with a given `spki_sha256`, which is already
stored per version, so it needs no format change. OpenBao's PKI engine solved a similar problem
differently: CA certificates and keys are separate entries (`config/issuer/`, `config/key/`) linked
by ID, so several issuers can share one key. That suits a CA, but it would split a version across
entries and lose the single atomic write of §5.1.3.
*Decided in v0.3.0:* `destroy` takes `spki_sha256` and destroys the key in every version that holds
it (§4.2.10).

## References

1. OpenBao issue #1983, "OpenBao as ACME Client or Proxy": https://github.com/openbao/openbao/issues/1983
2. HashiCorp Vault PKI External CA (Enterprise): https://developer.hashicorp.com/vault/docs/secrets/pki-external-ca
3. `remilapeyre/vault-acme`: https://github.com/remilapeyre/vault-acme
4. `lego`: https://github.com/go-acme/lego
5. RFC 9773, ACME Renewal Information: https://datatracker.ietf.org/doc/html/rfc9773
6. RFC 8657, CAA `accounturi` and `validationmethods`: https://datatracker.ietf.org/doc/html/rfc8657
7. OpenBao declarative plugins RFC: https://openbao.org/community/rfcs/config-plugins/
8. OpenBao transactional storage RFC: https://openbao.org/community/rfcs/transactions/
9. Pebble: https://github.com/letsencrypt/pebble
