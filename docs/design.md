# bao-acme: design

An external OpenBao secrets engine that stores TLS certificates with their keys, describes them
itself, and can obtain and renew them over ACME. Published independently as `bao-acme`
(`github.com/torstei/bao-acme`), under MPL-2.0.

This document describes the design as it is now, with the reasons for each decision. What changed
in which release is in §11. The README is the user's guide; this is the why.

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

2.2.1. **Imported:** something else issues the certificate (certbot, a manual purchase) and writes
it in.

2.2.2. **Managed:** the engine itself obtains and renews it over ACME.

2.3. Keep everything ACME needs in OpenBao: the account key, EAB credentials, DNS provider
credentials, and each certificate's definition. None of it is readable back.

2.4. Let policies separate reading the key from reading the description.

2.5. Renew on the CA's schedule where offered (ACME Renewal Information, RFC 9773), and on a sane
default otherwise.

### Non-goals

2.6. Being a CA. That is the PKI engine's job.

2.7. Distributing certificates to hosts. That is the consumers' job, for example OpenBao Agent or
another client on each host that fetches a certificate and hands it to a service, such as through
systemd's `LoadCredential=` (§10.3).

2.8. HTTP-01 and TLS-ALPN-01 challenges. OpenBao cannot answer on the domains' ports 80 or 443, and
wildcards need DNS-01 anyway.

## 3. Shape

3.1. An external plugin in Go, against OpenBao's `sdk/framework`, with `lego` as the ACME client
library. It is mounted like any engine, conventionally at `certificates/`.

3.2. The name keeps ACME in it and stays out of the `openbao-plugin-secrets-*` pattern, so it does
not read as a first-party OpenBao plugin.

3.3. Each release is a static binary per platform, with `SHA256SUMS` and build provenance. The
recommended installation is OpenBao's declarative `plugin` block with `sha256sum`, so every node
registers the same binary at startup and on `SIGHUP`, with no API call. Registering through the API
works too. Binaries are named after their version, because replacing the binary of a registration
in place makes the mount fail with `checksums did not match`. The README has the steps.

3.4. `plugin_directory` is read only when OpenBao starts. Where it was not set before, the first
installation needs a restart, and so an unseal, of each node. Upgrades need only `SIGHUP`, a `secrets
tune -plugin-version` and a `plugin reload`.

## 4. API

### 4.1. Principles

4.1.1. **The account is the unit of authority.** OpenBao authorizes by path. Every use of an ACME
account names it in its path, so a policy on `accounts/<account>/*` is the whole authorization for
one team, or one purpose. A certificate can use only its own account's DNS providers.

4.1.2. The account is also a boundary at the CA. With CAA `accounturi` (§7.3), a zone can be
pinned to one account, and the CA refuses every other account for it, whatever DNS records it can
publish. The engine's boundary and the CA's are the same.

4.1.3. **Settings and use have separate prefixes,** as is usual in OpenBao (the PKI engine has
`roles/<role>` and `issue/<role>`). An account's settings are at `config/accounts/<account>`, for
the operator; everything done with the account is under `accounts/<account>/`. No path differs
from another only by a trailing slash, so a policy cannot grant one where the other was meant, and
`accounts/<account>` itself has no operations.

4.1.4. **Names are labels.** Account, DNS provider and certificate names are chosen by the user and
follow OpenBao's usual name rule (letters, digits, `-`, `.`, `_`). The engine reads nothing into
them: a certificate's DNS names are in its `names`, never taken from its name.

4.1.5. Certificate and DNS provider names belong to their account, in the paths and in storage
(§5.4.1). Two teams sharing a mount can both have a certificate called `www`, and neither can see,
change or even detect the other's. A DNS key that two accounts both need is entered twice, once in
each: duplication, but it makes explicit who can use which credentials.

4.1.6. "Write-only" fields are accepted on write and never returned: reads show only whether they
are set. A field that does not apply, such as an unset time or an empty error, is left out of every
response rather than shown empty, because `bao` prints a zero time as year 1.

4.1.7. The action paths (`import`, `rollback`, `destroy`, `renew`, `unmanage`, `register`) have no
existence check, so a write to them is always an `update`, never a `create`.

### 4.2. Paths

Relative to the mount:

| Path | Method | What |
|---|---|---|
| `config/accounts/` | list | Account names. |
| `config/accounts/<account>` | write, read, delete | The account (§4.3). Delete is refused while the account owns certificates or DNS providers. |
| `config/accounts/<account>/register` | write | Register, or update the contact and refresh the status (§4.3.3). |
| `config/network` | write, read, delete | Outgoing traffic: proxy and DNS settings (§7.1). Mount-wide, for the operator. |
| `accounts/<account>/dns/` | list | The account's DNS providers. |
| `accounts/<account>/dns/<name>` | write, read, delete | A DNS provider (§4.4). Delete is refused while a certificate uses it, or an interrupted attempt still needs it to remove records. |
| `accounts/<account>/certs/` | list | The account's certificates. With `covers=<host>`, only those whose names cover the host. |
| `accounts/<account>/certs/<name>` | write, read, delete | Write defines a managed certificate (§4.5.2); read returns the current version, key included; delete removes the certificate and all its versions. |
| `…/certs/<name>/import` | write | A new version of an imported certificate (§4.5.1). |
| `…/certs/<name>/info` | read | The description and version state, **no key** (§4.6). |
| `…/certs/<name>/status` | read | The certificate's state for monitoring (§4.7). |
| `…/certs/<name>/versions/<n>` | read | An earlier version, like the certificate itself. |
| `…/certs/<name>/rollback` | write | Make version `n` current again. |
| `…/certs/<name>/destroy` | write | Destroy key material (§4.5.4). |
| `…/certs/<name>/renew` | write | Renew now, ignoring the schedule and any backoff. |
| `…/certs/<name>/unmanage` | write | Back to import-only, keeping the versions. |
| `accounts/<account>/status` | read | The account's certificates and registration (§4.7). |
| `status` | read | The same for every account. |

### 4.3. Accounts

4.3.1. An account's fields are:

4.3.1.1. `directory_url`: an https URL, or a CA name that lego knows, such as `letsencrypt` or
`letsencrypt-staging`. It is needed only to register and issue, so an account without one can hold
imported certificates, and the engine then never orders anything for it.

4.3.1.2. `email`: optional. Let's Encrypt keeps no contact address (§4.3.4).

4.3.1.3. `key_type`: default `ecdsa-p256`.

4.3.1.4. `eab_kid` and `eab_hmac_key`, for External Account Binding.

4.3.1.5. `ca_bundle`: PEM certificates to trust for the ACME server's TLS, in addition to the
system roots, for a private ACME server such as step-ca or OpenBao's own PKI engine.

4.3.1.6. `terms_of_service_agreed`.

4.3.2. The account key is generated inside the engine when the account is created, so a stored
account always has one. It is never returned. `directory_url`, `key_type` and EAB cannot change
once they are bound: `key_type` from creation, the others from registration. Changing them means a
new account.

4.3.3. `register` makes the CA match the configuration. An account that is not yet registered is
registered, with EAB when it is configured. A registered one has its contact updated if `email`
changed, and its status refreshed. Registration is refused until `terms_of_service_agreed` is true,
and the refusal names the CA's terms of service URL. An account is also registered at its first
issuance, if its terms are agreed to.

4.3.4. A CA may keep no contact. Let's Encrypt has kept none since June 2025: it forwards the
address to ISRG's mailing list and returns accounts without one. The engine records the address it
last gave the CA (`contact_sent`). An empty contact from the CA counts as current if `contact_sent`
is the configured `email`, so the address is neither sent again on every `register` nor reported
as differing. A changed `email` is still sent, once.

4.3.5. Reads show `eab_hmac_key_set`, never the key. A registered account's read also shows
`caa_records` and `caa_note` (§7.3.1).

4.3.6. Deleting an account removes it from the engine only. It is not deactivated at the CA, and
the response warns that its key is gone.

4.3.7. lego is given the HTTP client, account key and EAB values directly; nothing passes through
environment variables. Its log goes to OpenBao's log at debug level, because it logs every request
together with the contact address.

### 4.4. DNS providers

4.4.1. `accounts/<account>/dns/<name>` takes `type`, that type's own settings as top-level fields,
and `ttl`, `propagation_timeout` and `polling_interval`. `<name>` is how certificates refer to it,
in their `dns`. The type cannot change once created. A field that the type does not take is
refused, and an empty value removes a setting.

4.4.2. Reads show non-secret settings, `<field>_set` for secret ones, and `egress`: where the
provider connects, for allow-listing. `bao path-help` lists every type's fields and egress.

4.4.3. The types are:

| Type | Settings | Egress |
|---|---|---|
| `domeneshop` | `api_token`, `api_secret` | HTTPS to `api.domeneshop.no` |
| `cloudflare` | `api_token` (and optionally `zone_api_token`), or `email` and `api_key` | HTTPS to `api.cloudflare.com` |
| `dnsupdate` (RFC 2136) | `nameserver`, `tsig_key`, `tsig_secret`, `tsig_algorithm` (default `hmac-sha256`), `zones` | DNS UPDATE on port 53 to `nameserver`, not through the proxy |

4.4.4. **Credentials are never passed through environment variables.** lego's providers read their
settings from the environment by default, which the whole process shares, so concurrent issuances
could see each other's credentials. Each provider is built from lego's typed config
(`NewDNSProviderConfig`), never from `NewDNSProvider()`, and every field is filled in by the
engine, because lego's `NewDefaultConfig()` reads environment variables for its defaults too.
HTTP providers get the engine's HTTP client, so they use the proxy of §7.1.1. `dnsupdate` takes its
TSIG key inline: no key files and no GSS-TSIG. Its default algorithm is HMAC-SHA256, not lego's
HMAC-SHA1.

4.4.5. There is no generic fallback for lego's other providers. One could set the environment
variables under a mutex for the constructor call, but it would bring environment variables back
(§7.1.2), and a path shared by providers that each read their settings differently cannot be tested
properly. Further types are added typed, one at a time, when someone needs one (#3).

4.4.6. Route 53 is left out for now. Without explicit keys, lego falls back to the AWS default
credential chain (environment variables, `~/.aws`, the EC2 instance metadata service), which is
implicit credentials and implicit egress. It also adds several megabytes of AWS SDK. It can be
added with static credentials and the engine's HTTP client only, when someone needs it.

### 4.5. Certificates

4.5.1. **Imported.** `…/certs/<name>/import` takes `fullchain` and `privkey` as PEM, and optionally
`max_versions`. The engine validates and describes the certificate (§5.2). An import identical to
the current version writes nothing: the response gives `version` and `written`, so an importer on a
timer can tell whether anything changed.

4.5.2. **Managed.** Writing `names` and `dns` (and optionally `key_type`, default `ecdsa-p256`, and
`reuse_key`) to `…/certs/<name>` defines a managed certificate. `dns` names one of the account's DNS
providers; both fields are required.

4.5.2.1. Names are lowercased, sorted and deduplicated. A wildcard is allowed only as the whole
leftmost label, IP addresses are refused (DNS-01 cannot validate them), and international names
must be in their A-label (`xn--`) form.

4.5.2.2. The write returns at once, with `issuing: true` when it started an issuance, because an
order with DNS propagation can outlast OpenBao's request timeout.

4.5.2.3. A certificate needs issuing when its current version is missing, destroyed, expired, or
does not match the definition (names and key type). An imported certificate with the same names
and key type therefore satisfies the definition, and the engine leaves it alone until renewal. One
with other names is replaced, and its versions are kept, so the imported version is served until
the first issuance succeeds.

4.5.2.4. Changing the definition (names, key type or DNS provider) clears the backoff and issues
again. Writing the same definition again changes nothing.

4.5.2.5. Before the first certificate exists, `info` shows the definition and the issuance state,
and reading the certificate returns not found.

4.5.2.6. Importing into a managed certificate is allowed, so certbot can stay a fallback (§8.3).
`unmanage` returns a certificate to import-only, keeping its versions; a managed certificate that
never got a version is removed entirely. Rolling a managed certificate back to a version that does
not match its definition is refused, because the engine would replace it at once.

4.5.3. **Reading.** `…/certs/<name>` returns the current version: `fullchain`, `certificate` (the
leaf alone), `chain` (the intermediates), `privkey`, the description, and `version`.
`versions/<n>` returns an earlier one the same way.

4.5.4. **Reusing and destroying keys.** With `reuse_key=true`, an issuance uses the current
version's key, so the public key stays the same for consumers that pin it (DANE `3 1 1`, mTLS
allow-lists). An imported certificate's key is reused too, so a certbot key survives the migration
(§8). A new key is made when there is no usable current key, when the key type changes, and once
after `renew` with `rotate_key=true`; later renewals reuse that one.

4.5.4.1. Each version holds its own copy of the key, so `destroy` takes either `versions` or
`spki_sha256`. The latter destroys the key in every version holding it, which is what a
compromised key needs. Destroying by version warns when other versions still hold the same key.
The description is kept, so it remains visible what was there.

4.5.4.2. A key that any destroyed version held is never reused. Destroying a key also clears it from
an attempt in flight, and an attempt that obtained a certificate for a key destroyed meanwhile does
not store it: it fails and retries at once with a new key.

4.5.4.3. A CA may refuse a key, for example one it has seen revoked for key compromise. Such a
failure shows in `status`, and `renew rotate_key=true` moves on.

4.5.4.4. OpenBao's PKI engine solves a similar problem differently: CA certificates and keys are
separate entries linked by ID, so several issuers can share one key. That suits a CA, but it would
split a version across entries and lose the single atomic write of §5.1.

4.5.5. **Listing.** `covers=<host>` lists only certificates whose names cover the host, applying
the one-level wildcard rule. It is a query parameter on `LIST`, which the `bao` CLI cannot pass;
the README shows the HTTP call. With no match, the list is empty and the HTTP status is 404, as for
any empty list in OpenBao.

### 4.6. The description

Extracted by the engine from the certificate, never supplied by the writer, and returned by
`info`, which has no key material. `info` is the path for inventories and "has it changed" checks:
a client can poll it and read the key only when `current_version` or `sha256` changes.

| Field | |
|---|---|
| `names` | subjectAltName DNS names, lowercased and sorted, wildcards as written, followed by IP addresses, if present. |
| `common_name` | for display only. Clients check `names`. |
| `not_before`, `not_after` | RFC 3339, UTC. |
| `serial`, `issuer` | `issuer` in readable form, e.g. `Let's Encrypt YR2`. |
| `sha256`, `spki_sha256` | fingerprints of the certificate and of its public key. |
| `key_type` | e.g. `ecdsa-p256`. |

`info` also returns `current_version`, `latest_version`, `max_versions`, `destroyed`, and
`versions`, which maps each kept version to its `created_time`, `sha256`, `not_after` and
`destroyed`; the version's `source` (`acme:<account>` or `import`, with `imported_by`: the token's
`entity_id` and `display_name`); and for a managed certificate `definition` and `issuance`:
`needed` (why an issuance is due), `last_attempt_time`, `last_success_time`, `last_error`,
`failures`, `failing_since`, `next_attempt_time`, `renew_requested`, and `renewal` for the current
version (`renew_at`, `source` (`ari` or `default`), `window_start`, `window_end`,
`explanation_url`, `ari_error`, `checked_time`, `next_check_time`).

### 4.7. Status

4.7.1. `…/certs/<name>/status` sums a certificate up, for imported and managed certificates alike:

4.7.1.1. `state`, exactly one of `valid`, `renewal_due`, `renewing`, `issuing` (the first
certificate is being obtained), `pending` (no certificate yet, nothing running), `failing` and
`expired`. When several apply, the first of `expired`, `renewing`, `failing`, `renewal_due` wins.
A renewal that is running after earlier failures is therefore `renewing`.

4.7.1.2. `expires_in` in seconds, `not_after`, `version`, `renew_at`, `failures`.

4.7.1.3. `running`, and while a job runs on this node, `running_since` and `running_reason`. A
job that only checks the renewal schedule does not count as `renewing`.

4.7.1.4. The issuance fields of `info`, and `attempts`: the last ten attempts, newest first, with
`start_time`, `duration_seconds`, `reason`, `outcome` (`issued` or `failed`), `error` and
`version`. The history survives a change of definition.

4.7.1.5. `inflight`, while an attempt runs or after one was interrupted: `start_time`, `reason`,
`order_url`, `published` (each record's `domain`, `published_time` and `cleanup_error`) and
`next_cleanup_time` (§6.2). Never the attempt's key.

4.7.2. `status` at the mount gives every certificate's summary and `counts` per state, so one read
answers "is anything failing or about to expire". It is a separate path from the certificates, so
a monitoring policy can grant it alone. `accounts/<account>/status` gives the same for one account.

4.7.2.1. It shows facts, with no interpretation of its own. A failing certificate also has
`failing_since`, when its current run of failures began, and `last_error`. A certificate whose
challenge records could not be removed has `leftovers`, each with `domain`, `published_time` and
`cleanup_error`, since those do not affect its state. `accounts` lists every account, including
those without certificates, with `registered`, its `status` at the CA and
`terms_of_service_agreed`.

4.7.2.2. In the mount's `status`, certificates are keyed `<account>/<name>`, since names repeat
across accounts; an account's `status` uses plain names. Its nested values are meant to be read
with `bao read -format=yaml`, or as JSON. Its shape stays as it is until it is known what will
monitor the engine (#45).

### 4.8. Policies

Because the key and the description are on different paths, and everything is under the account,
policies get splits that KV cannot give:

```hcl
# a team: everything done with its own account
path "certificates/accounts/team-a/*" { capabilities = ["create", "read", "update", "delete", "list"] }

# … that may also read its account's settings, such as the CAA records to publish
path "certificates/config/accounts/team-a" { capabilities = ["read"] }

# a team whose DNS credentials the operator manages: certificates only
path "certificates/accounts/team-a/certs/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "certificates/accounts/team-a/status"  { capabilities = ["read"] }

# a consumer: one certificate, key included
path "certificates/accounts/team-a/certs/web" { capabilities = ["read"] }

# an inventory: descriptions, no keys
path "certificates/accounts/team-a/certs/+/info" { capabilities = ["read"] }

# an importer
path "certificates/accounts/team-a/certs/+/import" { capabilities = ["update"] }

# monitoring: every state, no keys
path "certificates/status" { capabilities = ["read"] }

# the operator: network settings and accounts
path "certificates/config/network"    { capabilities = ["create", "read", "update", "delete"] }
path "certificates/config/accounts/*" { capabilities = ["create", "read", "update", "delete", "list"] }
```

Write `accounts/team-a/*`, with the slash. `accounts/team-a*` also matches `accounts/team-ab/…`.

4.8.1. When one DNS key covers more names than an account should have, for example one Domeneshop
login holding every team's zones, the credentials do not limit the account. An optional
`allowed_domains` on the account, set by the operator and checked when a definition is written,
would (#30). Until then, give each account credentials that cover only its own names, or CAA-pin
the other names to their accounts. Separate mounts per team remain possible, for anyone who wants
each team's accounts, network settings and monitoring fully apart.

## 5. Storage

5.1. **One entry per version.** Each version is one storage entry (`…/certs/<name>/versions/<n>`)
holding the certificate, key and description together, so writing it is a single atomic `Put`,
and the description can never belong to another certificate. The per-certificate entry
`…/certs/<name>/meta` (current and latest version, `max_versions`, the definition and the issuance
state) is written after it. A crash in between leaves an unreferenced version, never a current one
that is incomplete, and the next write overwrites it. Writes to one certificate are serialised by
a per-certificate lock. `accounts/` and `config/` are seal-wrapped. No transactions are needed, though
OpenBao offers them to external plugins on Raft.

5.2. **Validation on write**, for imports and for issued certificates alike:

5.2.1. The chain parses. It holds only `CERTIFICATE` blocks, leaf first, and each certificate is
signed by the next one.

5.2.2. The key matches the certificate. PKCS #8, PKCS #1 and SEC 1 keys are accepted and stored
re-encoded as PKCS #8. Certificates are re-encoded too, so stored PEM does not depend on the
writer's formatting.

5.2.3. The certificate is within its validity period.

5.2.4. Not done: optionally requiring the chain to lead to a configured set of roots, which would
refuse a staging certificate in production.

5.3. **History:** `max_versions` per certificate (default 3). Older versions are deleted with their
key material. `rollback` moves the "current" pointer back; it does not copy the old version into a
new one, as KV version 2 does. The current version is never pruned, even when it falls outside
`max_versions`. Rolling back to a destroyed or expired version is refused. An importer on a timer
that still holds the newer certificate writes it again on its next run and so undoes the rollback,
so stop the importer before rolling back.

5.4. **Storage compatibility.** OpenBao owns everything below the plugin: the physical backend, the
barrier's encryption, and the mount's storage view (`logical/<mount-uuid>/`). The plugin sees only
`Get`, `Put`, `List` and `Delete` of key → bytes. The key layout and the JSON in those entries are
the engine's own format. Only the engine reads them; the API's responses are built from them, but
are a separate contract (§4). From 1.0, every release must read what every earlier release wrote,
both on upgrade and when restoring an old Raft snapshot (§5.4.4).

5.4.1. Keys, relative to the mount. Everything an account owns is stored under it, as the paths
are, so names are unique per account by construction. Inside the engine, a certificate is
identified as `<account>/<name>`; account names cannot contain a slash.

| Key | Holds |
|---|---|
| `accounts/<account>/certs/<name>/meta` | The `account`, which version is current, the latest version number, `max_versions`, and for a managed certificate its `managed` definition and `issuance` state (including `failing_since`). |
| `accounts/<account>/certs/<name>/versions/<n>` | One version: certificate, chain, key and description, in one entry. |
| `accounts/<account>/certs/<name>/inflight` | While an attempt runs, or after it was interrupted: the attempt's private key, its definition, the order URL, and the challenge records not yet removed (§6.2). |
| `accounts/<account>/dns/<name>` | A DNS provider: its `account`, `type`, a `settings` object with its fields, credentials included, and the common timing settings. |
| `config/accounts/<name>` | An ACME account: its settings, its key (PKCS #8 PEM), and, once registered, a `registration` object with the account URL, status, contact, the address last sent to the CA (`contact_sent`) and terms of service URL. |
| `config/network` | The proxy URL, credentials included, `proxy_ca_bundle`, and the DNS settings of §7.1.7. Absent means direct connections and the defaults. |

5.4.2. A `meta` entry, and a `versions/<n>` entry (about 2 KB for ECDSA P-256), with the PEM
shortened:

```json
{ "account": "team-a", "current_version": 2, "latest_version": 2, "max_versions": 3, "managed": { … } }
```

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

`fullchain` is not stored: reads return `certificate` followed by `chain`. A destroyed version has
no `privkey` and gains `"destroyed_time"`. `imported_by` is absent when the request carried no
identity. The description is kept as it was extracted at write time; a later release that
describes certificates differently does not rewrite old versions.

5.4.3. **Owners.** The key names the owning account. An account cannot be deleted while it owns
certificates or DNS providers, and accounts cannot be renamed, so no entry can belong to an account
that is gone, or to a new account later created under the same name.

5.4.4. Rules for changing the format:

5.4.4.1. Adding a field needs nothing. Older releases ignore fields they do not know, and newer
releases read a missing field as its zero value. That zero value must therefore mean what the
older release did.

5.4.4.2. Renaming or moving a field or key needs a migration: either converting entries when they
are read, or a one-off upgrade at mount time (`InitializeFunc`) that records a storage version.
From 1.0, renaming an API field therefore does not rename the stored one.

5.4.4.3. Downgrading loses data. An older release that rewrites an entry, for example on
`destroy`, drops the fields it does not know. Release notes must say so for the first release that
adds a field whose loss matters.

5.4.4.4. These rules apply from 1.0. Before 1.0, a release may change the layout without a
migration; its release notes then say what to create again. Otherwise every early layout would
have to be read forever. v0.5.0 did this (§11.5.3).

5.4.5. Tests enforce this format. `internal/backend/testdata/storage/` holds real entries in this
format, one file per storage key. A new kind of entry adds its file when it is introduced. One test
loads them and reads them through the API. Another checks that a fresh write still produces every
field they have, so a renamed JSON tag fails CI. Until 1.0 these files follow the layout; from 1.0
they are frozen, and a new storage format adds a directory beside them.

## 6. Issuing and renewing (managed certificates)

6.1. **Background work, on the active node only.**

6.1.1. The plugin's `PeriodicFunc` runs every minute. It starts a background job for each
certificate that needs issuing (§4.5.2.3) and is past its backoff, whose renewal schedule is due
for a check, or that has an interrupted attempt to recover. It does not block the periodic call.
That is also what resumes work after a restart or failover: an attempt cut short simply happens
again.

6.1.2. Each certificate has at most one job running. Work asked for while it runs (a write,
`renew`) makes it run once more afterwards, so the request is never lost. An issuance is given 15
minutes. Background work uses the mount's storage view, not a request's, and stops when the mount
is unmounted or the plugin reloaded.

6.1.3. lego keeps its DNS settings process-wide (its DNS client). Issuances, and the lookups of
recovery, set it from `config/network` and run one at a time while they do (§7.1.9).

6.1.4. OpenBao 2.x also calls `PeriodicFunc` on read-enabled standbys, which set up mounts
read-only and mark themselves `ReplicationPerformanceStandby`. Work started there would act on the
DNS provider and the CA before failing at its first write; a standby once removed the active
node's challenge record, taking its attempt for an interrupted one (#37). So both the periodic
function and each job first check `System().ReplicationState()`, and do nothing on a performance
standby or a DR secondary, as OpenBao's PKI engine does.

6.2. **Interrupted attempts are recovered, not resumed.** Persisting every step of an order, to
resume it after a failover, would mean replacing lego's `Obtain()` with the engine's own order flow
on lego's lower-level API. A restart in the middle of an order costs little, though: a new order is
well within the CA's limits, and the CA reuses the authorizations it already validated. Two things
are really lost, and those are what the engine recovers:

6.2.1. A certificate the CA issued but the engine never stored, which costs one of the CA's
duplicate certificates (five a week at Let's Encrypt).

6.2.2. Challenge records published but never removed.

6.2.3. An attempt writes its `inflight` entry (§5.4.1) before anything reaches the CA. It holds the new
private key, the definition it is for, and, as they happen, the order URL and each challenge
record. lego gets the engine's HTTP client, so the order URL is read from the CA's answer to
`newOrder` without changing lego's flow. Each record is written down before it is published, and
dropped once removed. A finished attempt deletes the entry.

6.2.4. When a certificate's background job finds an entry left by an attempt that is no longer
running, it first removes the leftover records. It then asks the CA for the order: if the order is
valid, the job downloads its certificate, checks it against the stored key, and stores it as the
next version, as an attempt "recovered after an interruption". Otherwise it drops the entry, and a
new order follows if one is due.

6.2.5. **Leftover records are removed by the engine, not by lego, and checked first:**

6.2.5.1. The engine asks the provider for the TXT records at the challenge name, through its API
(Domeneshop, Cloudflare) or the name server that takes the updates (`dnsupdate`). The zone is found
the way lego finds it, using `config/network`'s resolvers.

6.2.5.2. Only a record with exactly the value the engine published counts. If there is none, the
leftover is done with. If there is, that record is deleted, by the ID the listing gave
(Domeneshop, Cloudflare) or as that exact record (`dnsupdate`). A record with another value at the
same name belongs to someone else and is never touched. Doing this itself also lets the engine
remove Cloudflare leftovers, which lego can remove only by an ID it keeps in memory.

6.2.5.3. If the check or the removal fails, the record is kept, with the error, and tried again:
every five minutes for the first hour after it was published, then hourly. A failed check never
counts as "not there". `status` shows the record.

6.2.5.4. A record whose publishing failed is dropped whatever the outcome, since it most likely
never existed.

6.2.5.5. Removal right after validation, inside lego's flow, stays lego's.

6.3. **DNS-01 through lego's providers.** lego is used as a library, pinned. For each name it
publishes the TXT record, waits for it to propagate (§7.1.4), answers the challenge, and always
removes the record afterwards, including after failures.

6.3.1. lego's `dnsupdate` deletes every TXT record at the name before adding its own, so another
party validating the same name at the same moment loses its record (#39). It takes a coincidence
to matter, costs one failed validation that is retried, and does not affect Domeneshop or
Cloudflare, which only add.

6.3.2. A CA may reuse an authorization it validated recently for the same account and name. A
renewal soon after issuance then needs no DNS-01 challenge, so it succeeds even when the DNS
provider is misconfigured. Issuing does not prove the DNS provider still works.

6.4. **When to renew.** Certificate lifetimes are shrinking (the CA/Browser Forum's ballot SC-081
takes the maximum down to 47 days by 2029), so nothing assumes 90 days.

6.4.1. The schedule belongs to one version, identified by its `sha256`, and is worked out in the
same background job that issues.

6.4.2. If the CA's directory has `renewalInfo` (ARI, RFC 9773, which Let's Encrypt supports),
`renew_at` is a random time in the CA's suggested window. Asking again keeps the same time as long
as the window still contains it, so renewals do not move about. ARI is asked again after the CA's
`Retry-After`, clamped to between one and 24 hours, and that is how a request to renew early (a
revocation, a mass incident) is picked up.

6.4.3. Without ARI, `renew_at` is a third of the lifetime before expiry, less up to a thirtieth of
the lifetime as jitter. That covers a CA without ARI (checked again daily), a certificate the CA
does not know, such as an imported one from another CA (also daily), and a failed request (retried
after an hour, with the error in `ari_error`). Imported certificates from the same CA get ARI like
issued ones, because asking needs no account.

6.4.4. A renewal names the certificate it replaces (`replaces`) only when this account issued it,
because a CA refuses to link certificates across accounts. If the CA answers that the certificate
was already replaced, lego orders again without it.

6.4.5. `replaces` only links the renewal to its predecessor, for the CA's rate limits and renewal
window, so it must never cost the renewal. If the CA refuses to create the order for any other
reason, the engine orders once more without it, and logs a warning. Examples are a definition
whose names no longer overlap the old certificate's, or Pebble missing serials that have the top
bit set. The exception is a rate limit, which `replaces` may be what exempts the order from. A
failure after the order was created, such as a failed validation, is not retried this way.

6.5. **Failures** back off per certificate: the first retry comes after a minute, and each further
one waits twice as long, up to six hours, with ±10% jitter. Every failure is kept in `status` and
in the logs. A failure is recorded only for the definition it was tried for: a certificate obtained
for a definition that changed in the meantime is discarded. When renewals keep failing, `info` and
`status` show how close the current certificate is to expiry, so monitoring needs no access to the
engine's internals.

6.6. **While sealed, nothing renews.** The renewal window has to be long enough to survive an outage
of the cluster. Expiry monitoring through `status` covers that.

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

7.1.3. Every HTTP-based DNS provider must therefore take an injected HTTP client; lego providers
whose typed config has no HTTP client field are not offered. `dnsupdate` does not use HTTP at all:
its updates go straight to its name server on port 53, and writing one while a proxy is set warns
about that.

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

7.1.9. Because lego's DNS client is process-wide, mounts served by one plugin process that use
different settings have their issuances serialised (§6.1.3).

7.2. **DNS credentials can obtain certificates.** Whoever controls the DNS credentials, or the
engine's account and DNS provider paths, can get certificates for those names. Policies on
`config/` and `accounts/<account>/dns/` should be as narrow as those on root-level operations.

7.3. **CAA records with `accounturi` (RFC 8657).** These pin issuance for a domain to the engine's
ACME account and to `dns-01`. Then even someone who can change DNS records elsewhere cannot get a
certificate through another account.

7.3.1. A registered account's read shows `caa_records`: for each issuer domain name the CA lists in
its directory (`caaIdentities`, for example `letsencrypt.org`), an `issue` and an `issuewild`
value:

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

7.4. **No key leaves the engine except through certificate reads** (`…/certs/<name>` and
`versions/<n>`). Account keys are never exported. Private keys are generated inside the engine,
and `reuse_key` keeps a key across renewals when a consumer pins it.

7.5. **Audit.** OpenBao's audit log HMACs response fields by default, so certificates and keys do
not appear in clear text there. The audit log records API requests only: a renewal by the engine's
own background job is not in it, but in OpenBao's server log, and in `info` and `status`.

## 8. Moving from certbot and a KV mount

8.1. Mount the engine and create the account, for now without `directory_url`. Start the importer
writing to `accounts/<account>/certs/<name>/import` instead of KV, or import the current
certificate once.

8.2. Point consumers at the engine's paths.

8.3. Configure the account's `directory_url` and its DNS provider. Change the certificate from
imported to managed, so its next renewal is the engine's own. Keep certbot as a fallback until a
renewal has gone through. With the same names and key type, writing the definition changes nothing
at once (§4.5.2.3); with other names, the engine issues at once. `unmanage` goes back. With
`reuse_key`, certbot's key carries over (§4.5.4).

8.4. Retire certbot and the importer, and publish the CAA records (§7.3.2).

## 9. Building and testing

9.1. Go, against OpenBao's `sdk/framework`, with `lego` as the ACME client. Licence MPL-2.0, as
OpenBao itself.

9.2. **Tests:**

9.2.1. Unit tests for parsing, describing, validating and wildcard matching.

9.2.2. Issuance tests against an in-process **Pebble**, Let's Encrypt's test ACME server, which
supports ARI. Beside it, an in-process authoritative DNS server that accepts RFC 2136 updates with
TSIG, fakes of the Domeneshop and Cloudflare APIs, and a forward proxy that records what it is asked
to reach. The test CA can be made to behave like Let's Encrypt where Pebble does not (keeping no
contact) or to refuse things (`replaces`), so those paths are tested deterministically.

9.2.3. The storage format tests of §5.4.5.

9.2.4. An integration test (`make integration`) that runs the plugin in a real OpenBao in Docker:
importing, the policy split, `covers`, background issuance, a plugin reload, and that the audit log
has no key in clear text. The audit device is declared in the server configuration, because
OpenBao 2.x does not allow enabling one through the API.

9.2.5. Not built: failover in the middle of an order, against a three-node Raft cluster.

9.3. Changes go through pull requests, and `main` accepts one only once the `checks` and
`integration` jobs have passed. Releases are tag-driven, and published only for a commit whose CI
has passed: static linux/amd64 and linux/arm64 binaries with `SHA256SUMS` and build provenance
attestations. Releases are immutable. `CONTRIBUTING.md` has the steps.

## 10. Open questions

10.1. Upstreaming. *Decided:* published independently first, and offered to
`openbao/openbao-plugins` once it has users.

10.2. Whether an ACME *proxy* mode is in scope: the engine as an ACME server for internal clients,
validating against the public CA on their behalf. Suggested in #1983. It is attractive, but a large
step up in scope.

10.3. Notifying consumers when a certificate changes. OpenBao has no event or webhook mechanism: an
experimental events API existed in Vault, and OpenBao removed it (openbao/openbao#553). The audit
log does not see renewals (§7.5). So consumers poll. OpenBao Agent re-reads a certificate, key
included, at a fixed interval (`static_secret_render_interval`, five minutes by default; an hour is
plenty for certificates). A client that polls `info` instead reads the key only when the version
changes. The engine could call a configured webhook when it stores a version, but that is new
egress with its own questions, and not needed while polling works.

10.4. Per-name DNS providers for certificates that span zones on different providers.

10.5. A read-only `data/<name>` path answering in KV version 2's shape (`data.fullchain`,
`data.privkey` and so on), so consumers written against a KV layout could switch mounts without
changing. Worth it only if such consumers exist.

10.6. Releasing an OCI image with the plugin binary, signed, so it can be pinned by digest in the
`plugin` block, in addition to the binaries.

10.7. Searching certificates across accounts (#43), and shaping `status` for whatever will monitor
the engine (#45).

## 11. History

11.1. **v0.1.0: imported certificates.** Import, read, `info`, versions, rollback, destroy,
`covers`. Storage format 1. Paths were `certs/<name>/…`.

11.2. **v0.2.0: obtaining and renewing.** ACME accounts (`config/accounts/<name>`), DNS providers
(`config/dns/<name>`: `domeneshop`, `cloudflare`, `dnsupdate`), managed certificates at
`certs/<name>` with `account` and `dns_provider` in the definition, renewal with ARI, `renew`,
`unmanage`, and `config/network`.

11.3. **v0.3.0: status, recovery and reused keys.** `status` per certificate and at the mount,
recovery of interrupted attempts (§6.2) instead of a persisted order state machine, `reuse_key`
and `destroy` by `spki_sha256`. With Cloudflare, leftover records were listed for removal by hand.

11.4. **v0.4.0: everything under an account.** Paths moved under `accounts/<account>/`, with
settings at `config/accounts/<account>` (§4.1). Owners were added to storage, which stayed format
1. `certs/…` and `config/dns/…` were removed.

11.5. **v0.5.0: from the first production use.**

11.5.1. API changes: a definition's `dns_provider` became `dns`, after the path segment it points
into, and a DNS provider's `provider` became `type`, because the same word had named both an entry
and its kind. Considered and rejected at the same time: defaulting `names` to the certificate's
name, an optional `dns` when the account has one DNS provider (both implicit), and placing
certificates under their DNS provider's path (moving a zone would move the certificate's path).
`status` gained errors, leftovers and accounts.

11.5.2. Fixes: no background work on standbys (§6.1.4); leftover records checked with the
provider before removal, and only the exact value removed (§6.2.5); a CA that keeps no contact
(§4.3.4); `replaces` dropped when the CA refuses it (§6.4.5); empty values left out of responses
(§4.1.6).

11.5.3. Storage moved under the account (§5.4.1). Until then, names were unique per mount, because
the v0.4.0 paths named the account but the storage keys did not; a migration was avoided then, and
the result was confusing. v0.5.0 changes the layout without a migration (§5.4.4.4): DNS providers
and certificates stored by earlier releases are ignored, with a warning at start, and are created
again. Account settings keep their keys. The stored fields `dns_provider` and `provider` took the
API's names, `dns` and `type`.

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
10. OpenBao issue #553, events: https://github.com/openbao/openbao/issues/553
