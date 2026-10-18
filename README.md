# bao-acme

An [OpenBao](https://openbao.org) secrets engine for TLS certificates that OpenBao did not issue
itself: Let's Encrypt and other public CAs. It stores each certificate with its private key,
versioned, together with a description it extracts from the certificate itself (names, validity,
issuer, fingerprints). Policies can then grant the description without the key.

The goal is for the engine to obtain and renew certificates itself, over ACME with DNS-01. That
part is not built yet. Today it stores certificates that something else issued, such as certbot.
See [docs/design.md](docs/design.md) for the design and the plan.

> Status: early. Imported certificates work (v0.1.0). The engine obtains and renews certificates over ACME with DNS-01.

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
bao write certificates/certs/example.com/import fullchain=@fullchain.pem privkey=@privkey.pem
bao read certificates/certs/example.com/info     # description, no key
bao read certificates/certs/example.com          # certificate and key
```

## Installing in a real OpenBao

Each [release](https://github.com/torstei/bao-acme/releases) has a static binary for linux/amd64
and linux/arm64, a `SHA256SUMS` file, and build provenance. Fetch and check it on each node, or
wherever your configuration management builds its packages:

```sh
v=v0.3.0
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
  command   = "bao-acme-v0.3.0"
  version   = "v0.3.0"
  sha256sum = "<the bao-acme_linux_amd64 line of SHA256SUMS>"
}
```

**Always set `sha256sum`.** Without it, OpenBao registers the plugin with no checksum and runs
whatever file is at that path. With it, a replaced binary is refused with `checksums did not
match`.

Then, once:

```sh
bao secrets enable -path=certificates -plugin-version=v0.3.0 bao-acme
```

To upgrade, install the new binary next to the old one, and add a second `plugin` block for the
new version. Blocks with the same name and different versions may sit side by side. Send OpenBao
`SIGHUP`, then switch the mount and reload:

```sh
bao secrets tune -plugin-version=v0.4.0 certificates
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

| Path | Method | |
|---|---|---|
| `certs/<name>/import` | write | `fullchain`, `privkey` (PEM), optional `max_versions` (default 3). An import identical to the current version writes nothing (`written: false`). |
| `certs/<name>` | read | Current version: `fullchain`, `certificate`, `chain`, `privkey` and the description. |
| `certs/<name>` | delete | The certificate and all its versions. |
| `certs/<name>/info` | read | Description and version state. No key material. |
| `certs/<name>/versions/<n>` | read | An earlier version, like `certs/<name>`. |
| `certs/<name>/rollback` | write | `version`: make it current again. |
| `certs/<name>/destroy` | write | `versions`, or `spki_sha256` for every version holding that key: destroy the private keys, keep the descriptions. |
| `certs/` | list | Names. With `?covers=<host>`, only those whose names cover the host. |

Managed certificates, obtained and renewed by the engine over ACME with DNS-01:

| Path | Method | |
|---|---|---|
| `certs/<name>` | write | `names`, `account`, `dns_provider`, optionally `key_type` (default `ecdsa-p256`) and `reuse_key` (renew with the same key, for consumers that pin it). Returns at once; the certificate is obtained in the background. An imported certificate under the same name keeps its versions. |
| `certs/<name>/info` | read | Adds `definition` and `issuance`: why one is needed, last attempt and success, last error, failures, next attempt. |
| `certs/<name>/renew` | write | Renew now, ignoring the schedule and any backoff. `rotate_key=true` takes a new key this once. |
| `certs/<name>/status` | read | `state` (`valid`, `renewal_due`, `renewing`, `issuing`, `pending`, `failing`, `expired`), `expires_in`, what is running now, the last ten attempts, and any attempt in flight or interrupted. Imported certificates too. |
| `status` | read | Every certificate's state and expiry, and `counts` per state, in one read. |
| `certs/<name>/unmanage` | write | Back to import-only, keeping the versions. |

If OpenBao restarts or fails over in the middle of an attempt, the engine afterwards stores a
certificate the CA had already issued, instead of ordering a new one, and removes the challenge
records the attempt left. With Cloudflare, leftover records cannot be found again after a restart;
`status` lists them for removal by hand.

Renewal follows the CA's suggested window (ARI, RFC 9773) where offered, which also picks up a
CA's request to renew early, and otherwise happens when a third of the lifetime remains.
`certs/<name>/info` shows the schedule under `issuance.renewal`.

A complete setup with Domeneshop:

```sh
bao write certificates/config/accounts/le directory_url=letsencrypt email=ops@example.com terms_of_service_agreed=true
bao write certificates/config/dns/domeneshop provider=domeneshop api_token=… api_secret=…
bao write certificates/certs/example.com names=example.com,*.example.com account=le dns_provider=domeneshop
bao read  certificates/certs/example.com/info
```

ACME accounts:

| Path | Method | |
|---|---|---|
| `config/accounts/<name>` | write | `directory_url` (URL, or a CA name such as `letsencrypt-staging`), `email`, `key_type`, `eab_kid`, `eab_hmac_key`, `ca_bundle`, `terms_of_service_agreed`. The key is generated by the engine. |
| `config/accounts/<name>` | read, delete | Settings and registration state, and once registered, `caa_records`: the CAA records that allow only this account to issue, and only through DNS-01. Never the key or the EAB HMAC key. |
| `config/accounts/<name>/register` | write | Register with the CA, or update the contact and refresh the status. |
| `config/accounts/` | list | Names. |

```sh
bao write certificates/config/accounts/le directory_url=letsencrypt email=ops@example.com terms_of_service_agreed=true
bao write certificates/config/accounts/le/register
```

After registering, publish the CAA records that `bao read -field=caa_records
certificates/config/accounts/le` lists, on each zone's apex. Until certbot is retired, also
publish an `issue` record with its account URL, or certbot is refused.

DNS providers, for DNS-01 (used once issuance exists):

| Path | Method | |
|---|---|---|
| `config/dns/<name>` | write | `provider` (`domeneshop`, `cloudflare` or `dnsupdate` for RFC 2136), then that provider's settings; credentials are write-only. `bao path-help certificates/config/dns/x` lists them. |
| `config/dns/<name>` | read, delete | Settings, `<secret>_set` flags, and `egress`: where the provider connects. |
| `config/dns/` | list | Names. |

```sh
bao write certificates/config/dns/domeneshop provider=domeneshop api_token=… api_secret=…
```

Outgoing traffic:

| Path | Method | |
|---|---|---|
| `config/network` | write, read, delete | `proxy_url`: a forward proxy (`http://` or `https://`, credentials write-only) that carries **all** of the engine's HTTP, with no direct fallback. `proxy_ca_bundle` trusts the proxy's certificate. DNS-01 settings: `dns_resolvers`, `dns_propagation_check` (`authoritative`, the default, or `resolvers` or `none`), `dns_propagation_delay`, `dns_tcp_only`. |

The engine never reads `HTTPS_PROXY` or similar from the environment. With a proxy, HTTPS goes
through `CONNECT`, so the proxy can allow-list host names such as `acme-v02.api.letsencrypt.org`.
DNS cannot go through it: by default the engine needs UDP and TCP port 53 to the recursive
resolvers in `/etc/resolv.conf` and to the authoritative servers of each zone it issues for
(`dig NS <zone>`). See [design §7.1](docs/design.md).

```hcl
path "certificates/certs/example.com"   { capabilities = ["read"] }   # a consumer
path "certificates/certs/+/info"        { capabilities = ["read"] }   # monitoring
path "certificates/certs/+/import"      { capabilities = ["update"] } # an importer
path "certificates/status"              { capabilities = ["read"] }   # monitoring, one read for all
```

## Licence

[MPL-2.0](LICENSE), like OpenBao.
