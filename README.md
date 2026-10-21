# bao-acme

An [OpenBao](https://openbao.org) secrets engine for TLS certificates from Let's Encrypt and other
ACME CAs. It obtains and renews certificates itself, over ACME with DNS-01, or stores ones
something else issued, such as certbot. Each certificate is kept with its private key, versioned,
together with a description the engine extracts from the certificate (names, validity, issuer,
fingerprints), so policies can grant the description without the key.

Everything is done with an **account**: an ACME account, and the unit of authority. A team's
policy on `accounts/<account>/*` is its whole access. See [docs/design.md](docs/design.md) for
the design.

> Status: early, and not yet used in production.

## Build and try it

You need Go 1.27 or later and the `bao` CLI.

```sh
make test
make integration  # needs Docker: runs the plugin in OpenBao (quay.io/openbao/openbao, override with BAO_IMAGE)
make dev          # builds, starts a throwaway OpenBao dev server on 127.0.0.1:18200
```

In another terminal:

```sh
export BAO_ADDR=http://127.0.0.1:18200 BAO_TOKEN=root
bao write -f certificates/config/accounts/demo             # an account, for now just holding imports
bao write certificates/accounts/demo/certs/example.com/import fullchain=@fullchain.pem privkey=@privkey.pem
bao read  certificates/accounts/demo/certs/example.com/info   # description, no key
bao read  certificates/accounts/demo/certs/example.com        # certificate and key
```

## Installing in a real OpenBao

Each [release](https://github.com/torstei/bao-acme/releases) has a static binary for linux/amd64
and linux/arm64, a `SHA256SUMS` file, and build provenance. Fetch and check it on each node, or
wherever your configuration management builds its packages:

```sh
v=v0.4.0
curl -LO https://github.com/torstei/bao-acme/releases/download/$v/bao-acme_linux_amd64
curl -LO https://github.com/torstei/bao-acme/releases/download/$v/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify bao-acme_linux_amd64 --repo torstei/bao-acme

install -m 0755 bao-acme_linux_amd64 /opt/openbao/plugins/bao-acme-$v
```

### Registering it in the server configuration (recommended)

Declare the plugin in OpenBao's configuration, next to `plugin_directory`. OpenBao registers it at
startup and on `SIGHUP` (`plugin_auto_register`, on by default), so there is no API call and no
privileged token, and every node registers the same thing:

```hcl
plugin_directory = "/opt/openbao/plugins"

plugin "secret" "bao-acme" {
  command   = "bao-acme-v0.4.0"
  version   = "v0.4.0"
  sha256sum = "<the bao-acme_linux_amd64 line of SHA256SUMS>"
}
```

`sha256sum` guards against mistakes, not attackers. With it, OpenBao refuses a binary other than
the one you verified: a wrong version, the wrong architecture, a half-copied file. Without it,
OpenBao registers the plugin with no checksum and runs whatever file is at that path. It does
nothing against anyone who can write the configuration or replace OpenBao itself, so the real
protection is that only root can write the plugin directory and the configuration, and that you
verify each release when you install it.

Then, once:

```sh
bao secrets enable -path=certificates -plugin-version=v0.4.0 bao-acme
```

To upgrade, install the new binary next to the old one, and add a second `plugin` block for the
new version. Blocks with the same name and different versions may sit side by side. Send OpenBao
`SIGHUP`, then switch the mount and reload:

```sh
bao secrets tune -plugin-version=v0.5.0 certificates
bao plugin reload -plugin=bao-acme
```

Remove the old block and binary once the mount runs the new version.

### Registering it through the API

Without access to the server configuration, register each version through the API instead:

```sh
bao plugin register -sha256="$(sha256sum bao-acme_linux_amd64 | cut -d' ' -f1)" \
    -command=bao-acme-$v -version=$v secret bao-acme
bao secrets enable -path=certificates -plugin-version=$v bao-acme
```

Upgrades then register the new version the same way, followed by the same `secrets tune` and
`plugin reload`.

Either way, name each binary after its version: replacing the binary of an unversioned
registration in place made the mount's requests fail with `checksums did not match`. Every release
reads what earlier releases stored (see [design §5.6](docs/design.md)).

Or build it yourself with `make build`, which writes `bin/bao-acme`.

## Releasing

Push an annotated tag `vX.Y.Z` on a commit that has passed CI on `main`. The release workflow
refuses a commit without passing `checks` and `integration` runs. The tag's annotation leads the
release notes. Releases from v0.1.1 on are immutable: once published, neither the binaries nor the
tag can change, so a fix is always a new version.

## API

Paths are relative to the mount. An account's **settings** are under `config/accounts/<account>`;
everything **done with** the account is under `accounts/<account>/`. Certificate and DNS provider
names are unique per mount: writing a name another account owns is refused.

A write that takes no fields, such as `register`, `renew` or `unmanage`, needs `bao write -f`;
without it, `bao` stops with "Must supply data or use -force".

A field that does not apply, such as an unset time or an empty error, is left out of a read.

### Accounts (the operator)

| Path | Method | |
|---|---|---|
| `config/accounts/<account>` | write | `directory_url` (URL, or a CA name such as `letsencrypt` or `letsencrypt-staging`), `email`, `key_type`, `eab_kid`, `eab_hmac_key`, `ca_bundle`, `terms_of_service_agreed`. The key is generated by the engine. Without `directory_url` the account can hold only imported certificates. `email` is optional: Let's Encrypt keeps no contact address, and passes one it is given to ISRG's mailing list. |
| `config/accounts/<account>` | read | Settings and registration state, and once registered, `caa_records`: the CAA records that allow only this account to issue, and only through DNS-01. Never the key or the EAB HMAC key. |
| `config/accounts/<account>` | delete | Refused while the account owns certificates or DNS providers. |
| `config/accounts/<account>/register` | write | Register with the CA, or update the contact and refresh the status. Also done at the first issuance. |
| `config/accounts/` | list | Names. |

After registering, publish the CAA records that `bao read -field=caa_records
certificates/config/accounts/<account>` lists, on each zone's apex. Until certbot is retired, also
publish an `issue` record with its account URL, or certbot is refused.

### DNS providers

| Path | Method | |
|---|---|---|
| `accounts/<account>/dns/<name>` | write | `type` (`domeneshop`, `cloudflare` or `dnsupdate` for RFC 2136), then that provider's settings; credentials are write-only. `bao path-help certificates/accounts/x/dns/y` lists them. Only this account's certificates can use it. |
| `accounts/<account>/dns/<name>` | read | Settings, `<secret>_set` flags, and `egress`: where the provider connects. |
| `accounts/<account>/dns/<name>` | delete | Refused while a certificate uses it, or still needs it to remove leftover challenge records. |
| `accounts/<account>/dns/` | list | Names. |

### Certificates

| Path | Method | |
|---|---|---|
| `accounts/<account>/certs/<name>` | write | A managed certificate: `names`, `dns` (one of this account's DNS providers), optionally `key_type` (default `ecdsa-p256`) and `reuse_key` (renew with the same key, for consumers that pin it). Returns at once; the certificate is obtained in the background. An imported certificate under the same name keeps its versions. |
| `accounts/<account>/certs/<name>` | read | Current version: `fullchain`, `certificate`, `chain`, `privkey` and the description. |
| `accounts/<account>/certs/<name>` | delete | The certificate and all its versions. |
| `…/certs/<name>/import` | write | `fullchain`, `privkey` (PEM), optional `max_versions` (default 3). An import identical to the current version writes nothing (`written: false`). |
| `…/certs/<name>/info` | read | Description and version state, no key material; for a managed certificate also `definition` and `issuance`, with the renewal schedule under `issuance.renewal`. |
| `…/certs/<name>/status` | read | `state` (`valid`, `renewal_due`, `renewing`, `issuing`, `pending`, `failing`, `expired`), `expires_in`, what is running now, the last ten attempts, and any attempt in flight or interrupted. |
| `…/certs/<name>/versions/<n>` | read | An earlier version, like the certificate itself. |
| `…/certs/<name>/rollback` | write | `version`: make it current again. |
| `…/certs/<name>/destroy` | write | `versions`, or `spki_sha256` for every version holding that key: destroy the private keys, keep the descriptions. |
| `…/certs/<name>/renew` | write | Renew now, ignoring the schedule and any backoff. `rotate_key=true` takes a new key this once. |
| `…/certs/<name>/unmanage` | write | Back to import-only, keeping the versions. |
| `accounts/<account>/certs/` | list | Names. With `?covers=<host>`, only those whose names cover the host. |
| `accounts/<account>/status` | read | The account's certificates, each with its state and expiry, and for a failing one `failing_since` and `last_error`, and any `leftovers`: challenge records not yet removed. Also `counts` per state, and the account's registration state under `accounts`. |
| `status` | read | The same for every account, in one read. |

Read `status` with `bao read -format=yaml …`: the default table prints nested values on one line.

Renewal follows the CA's suggested window (ARI, RFC 9773) where offered, which also picks up a
CA's request to renew early, and otherwise happens when a third of the lifetime remains.

If OpenBao restarts or fails over in the middle of an attempt, the engine afterwards stores a
certificate the CA had already issued, instead of ordering a new one, and removes the challenge
records the attempt left. It removes only a record with exactly the value it published, and
leaves other records at the same name alone. A record it cannot remove is shown in `status` and
tried again.

### A complete setup with Domeneshop

```sh
bao write certificates/config/accounts/team-a directory_url=letsencrypt email=ops@example.com terms_of_service_agreed=true
bao write -f certificates/config/accounts/team-a/register   # optional: done at the first issuance
bao read -field=caa_records certificates/config/accounts/team-a
bao write certificates/accounts/team-a/dns/team-a-domeneshop type=domeneshop api_token=… api_secret=…
bao write certificates/accounts/team-a/certs/team-a-www names=example.com,*.example.com dns=team-a-domeneshop
bao read  certificates/accounts/team-a/certs/team-a-www/status
bao write -f certificates/accounts/team-a/certs/team-a-www/renew   # later, to renew ahead of schedule
```

### Outgoing traffic

| Path | Method | |
|---|---|---|
| `config/network` | write, read, delete | `proxy_url`: a forward proxy (`http://` or `https://`, credentials write-only) that carries **all** of the engine's HTTP, with no direct fallback. `proxy_ca_bundle` trusts the proxy's certificate. DNS-01 settings: `dns_resolvers`, `dns_propagation_check` (`authoritative`, the default, or `resolvers` or `none`), `dns_propagation_delay`, `dns_tcp_only`. |

The engine never reads `HTTPS_PROXY` or similar from the environment. With a proxy, HTTPS goes
through `CONNECT`, so the proxy can allow-list host names such as `acme-v02.api.letsencrypt.org`.
DNS cannot go through it: by default the engine needs UDP and TCP port 53 to the recursive
resolvers in `/etc/resolv.conf` and to the authoritative servers of each zone it issues for
(`dig NS <zone>`). See [design §7.1](docs/design.md).

### Policies

```hcl
# a team: everything done with its own account
path "certificates/accounts/team-a/*" { capabilities = ["create", "read", "update", "delete", "list"] }

# … that may also read its account's settings, such as the CAA records to publish
path "certificates/config/accounts/team-a" { capabilities = ["read"] }

# a team whose DNS credentials the operator manages: certificates only
path "certificates/accounts/team-a/certs/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "certificates/accounts/team-a/status"  { capabilities = ["read"] }

# a consumer: one certificate, key included
path "certificates/accounts/team-a/certs/team-a-www" { capabilities = ["read"] }

# monitoring: every certificate's state, no keys
path "certificates/status" { capabilities = ["read"] }

# the operator: network settings and accounts
path "certificates/config/network"    { capabilities = ["create", "read", "update", "delete"] }
path "certificates/config/accounts/*" { capabilities = ["create", "read", "update", "delete", "list"] }
```

Write `accounts/team-a/*`, with the slash: `accounts/team-a*` also matches `accounts/team-ab/…`.

## Licence

[MPL-2.0](LICENSE), like OpenBao.
