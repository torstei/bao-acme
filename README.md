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
make dev        # builds, starts a throwaway OpenBao dev server on 127.0.0.1:18200
```

In another terminal:

```sh
export BAO_ADDR=http://127.0.0.1:18200 BAO_TOKEN=root
bao write certificates/certs/example.com/import fullchain=@fullchain.pem privkey=@privkey.pem
bao read certificates/certs/example.com/info     # description, no key
bao read certificates/certs/example.com          # certificate and key
```

## Installing in a real OpenBao

```sh
make build
cp bin/bao-acme /path/to/plugin_directory/
bao plugin register -sha256="$(sha256sum bin/bao-acme | cut -d' ' -f1)" secret bao-acme
bao secrets enable -path=certificates bao-acme
```

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
