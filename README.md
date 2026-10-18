# bao-acme

An [OpenBao](https://openbao.org) secrets engine for TLS certificates that OpenBao did not issue
itself: Let's Encrypt and other public CAs. It stores each certificate with its private key,
versioned, together with a description it extracts from the certificate itself (names, validity,
issuer, fingerprints). Policies can then grant the description without the key.

The goal is for the engine to obtain and renew certificates itself, over ACME with DNS-01. That
part is not built yet. Today it stores certificates that something else issued, such as certbot.
See [docs/design.md](docs/design.md) for the design and the plan.

> Status: early. Imported certificates work; ACME issuance is next. Not yet released.

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
and linux/arm64, a `SHA256SUMS` file, and build provenance:

```sh
curl -LO https://github.com/torstei/bao-acme/releases/latest/download/bao-acme_linux_amd64
gh attestation verify bao-acme_linux_amd64 --repo torstei/bao-acme

install -m 0755 bao-acme_linux_amd64 /path/to/plugin_directory/bao-acme
bao plugin register -sha256="$(sha256sum bao-acme_linux_amd64 | cut -d' ' -f1)" secret bao-acme
bao secrets enable -path=certificates bao-acme
```

Or build it yourself with `make build`, which writes `bin/bao-acme`.

## Releasing

Push an annotated tag `vX.Y.Z` on a commit that has passed CI on `main`. The release workflow
refuses a commit without passing `checks` and `integration` runs. The tag's annotation leads the
release notes.

## API

| Path | Method | |
|---|---|---|
| `certs/<name>/import` | write | `fullchain`, `privkey` (PEM), optional `max_versions` (default 3). An import identical to the current version writes nothing (`written: false`). |
| `certs/<name>` | read | Current version: `fullchain`, `certificate`, `chain`, `privkey` and the description. |
| `certs/<name>` | delete | The certificate and all its versions. |
| `certs/<name>/info` | read | Description and version state. No key material. |
| `certs/<name>/versions/<n>` | read | An earlier version, like `certs/<name>`. |
| `certs/<name>/rollback` | write | `version`: make it current again. |
| `certs/<name>/destroy` | write | `versions`: destroy their private keys, keep their descriptions. |
| `certs/` | list | Names. With `?covers=<host>`, only those whose names cover the host. |

```hcl
path "certificates/certs/example.com"   { capabilities = ["read"] }   # a consumer
path "certificates/certs/+/info"        { capabilities = ["read"] }   # monitoring
path "certificates/certs/+/import"      { capabilities = ["update"] } # an importer
```

## Licence

[MPL-2.0](LICENSE), like OpenBao.
