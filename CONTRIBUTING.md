# Contributing to bao-acme

## Building and testing

You need Go 1.27 or later and the `bao` CLI.

```sh
make build        # writes bin/bao-acme
make test
make integration  # needs Docker: runs the plugin in OpenBao (quay.io/openbao/openbao, override with BAO_IMAGE)
make dev          # builds, starts a throwaway OpenBao dev server on 127.0.0.1:18200
```

`make dev` mounts the plugin at `certificates/`. In another terminal:

```sh
export BAO_ADDR=http://127.0.0.1:18200 BAO_TOKEN=root
bao write -f certificates/config/accounts/demo      # an account, here just holding imports
bao write certificates/accounts/demo/certs/web-certname/import fullchain=@fullchain.pem privkey=@privkey.pem
bao read  certificates/accounts/demo/certs/web-certname/info   # description, no key
bao read  certificates/accounts/demo/certs/web-certname        # certificate and key
```

The design, and the reasons behind it, are in [docs/design.md](docs/design.md).

## Changes

Work is planned in GitHub issues, with one milestone per release. Each change goes in a pull request
that fixes an issue. `main` accepts a pull request only once the `checks` and `integration` jobs
have passed.

## Releasing

Push an annotated tag `vX.Y.Z` on a commit that has passed CI on `main`. The release workflow
refuses a commit without passing `checks` and `integration` runs. The tag's annotation leads the
release notes; list API changes there. Releases from v0.1.1 on are immutable: once published,
neither the binaries nor the tag can change, so a fix is always a new version.

Before tagging, update the version in the README's install examples.
