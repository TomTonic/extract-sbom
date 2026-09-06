# BUILD

This document describes how to build extract-sbom from source. For installing
a finished release binary, see [INSTALL.md](INSTALL.md).

## Prerequisites

- Go `1.26.2` or newer — see [go.mod](go.mod)
- `git`

## Build

```bash
go build -o extract-sbom ./cmd/extract-sbom
```

The resulting binary is statically linked (CGO disabled) and has no external
Go runtime dependencies.

## Install via go install

```bash
go install github.com/TomTonic/extract-sbom/cmd/extract-sbom@latest
```

The binary is installed into `$(go env GOPATH)/bin/extract-sbom`.

## GoReleaser (cross-platform release build)

The project uses [GoReleaser](https://goreleaser.com) to produce all release
artifacts. GoReleaser is configured in [.goreleaser.yml](.goreleaser.yml).

Install GoReleaser (requires `~> v2`):

```bash
brew install goreleaser/tap/goreleaser    # macOS
go install github.com/goreleaser/goreleaser/v2@latest  # any platform
```

Test the release build locally without publishing:

```bash
goreleaser release --snapshot --clean
```

Artifacts appear in `dist/`.

## Cutting a release

Pushing a `v*` tag runs [release.yml](.github/workflows/release.yml), which
runs GoReleaser and publishes everything except one step.

**Credentials.** GoReleaser writes to two repositories outside this one -
`TomTonic/homebrew-tap` (the cask) and `TomTonic/winget-pkgs` (the WinGet
manifest). Both pushes go over SSH using a per-repository **deploy key**,
held in the repository secrets `HOMEBREW_TAP_DEPLOY_KEY` and
`WINGET_FORK_DEPLOY_KEY`. Deploy keys are used deliberately instead of a
personal access token: each is valid for exactly one repository and can be
revoked on its own, whereas any PAT able to write to the tap would be an
account-wide credential. The keys are passphrase-less because the workflow
runs unattended - GoReleaser rejects passphrase-protected keys outright.
Rotating one means generating a new key pair, replacing the deploy key on
the target repository, and updating the secret here.

**The one manual step: the WinGet pull request.** GoReleaser pushes the
generated manifests to a branch `extract-sbom-<version>` on our fork
`TomTonic/winget-pkgs` and stops there - over SSH it has no API token, so it
cannot open the pull request. After the release, open a PR from that branch
against `microsoft/winget-pkgs` (branch `master`) yourself and respond to the
validation bot. This is intentional: automating it would require a token that
can write to a fork of a Microsoft repository and open pull requests under
this account, which is far broader than pushing a single branch - and every
`winget-pkgs` submission is human-reviewed anyway.

## Running Tests

```bash
go test ./...
go test -race ./...
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

## Running the Linter

```bash
golangci-lint run
```

Configuration: [.golangci.yml](.golangci.yml) (if present).
