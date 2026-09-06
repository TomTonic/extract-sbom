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
runs GoReleaser and publishes everything in one go - no manual follow-up.

**Credentials.** GoReleaser writes to exactly one repository outside this one:
`TomTonic/homebrew-tap`, where the cask lives. That push goes over SSH using a
**deploy key**, held in the repository secret `HOMEBREW_TAP_DEPLOY_KEY`. A
deploy key is used deliberately instead of a personal access token: it is
valid for that one repository and can be revoked on its own, whereas any PAT
able to write to the tap would be an account-wide credential. The key is
passphrase-less because the workflow runs unattended - GoReleaser rejects
passphrase-protected keys outright. Rotating it means generating a new key
pair, replacing the deploy key on the tap, and updating the secret here.

**Windows distribution.** Windows ships as the plain `.zip` release asset
only - no WinGet manifest, no Chocolatey package, no Microsoft Store listing.
That is a deliberate choice, not an omission. Every third-party index pins the
installer URL and its SHA-256 permanently, and none of them lets the publisher
withdraw a version once it is accepted: `winget-pkgs` needs a pull request to
Microsoft to remove one, and Chocolatey states plainly that "once approved,
there is no reject". Since withdrawing a bad release has to stay possible for a
security tool, this project only publishes through channels it controls
end-to-end: the Homebrew tap, and the package repository at
[pkg.tomtonic.de](https://pkg.tomtonic.de) for Linux.

The corollary is a rule worth stating: **published release assets are never
deleted or replaced, only superseded by a new version.** The Homebrew cask and
the Linux repository both reference assets by URL and checksum, so removing
one breaks installs that already point at it.

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
