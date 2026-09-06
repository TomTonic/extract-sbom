# INSTALL

This document explains how to install a release build of extract-sbom, install its
runtime dependencies, recognize missing dependencies, and get them in common
environments.

For building from source or for development, see [BUILD.md](BUILD.md).

## Linux: package repository (recommended - auto-updating)

extract-sbom is available through the
[TomTonic package repository](https://pkg.tomtonic.de), a signed
`apt`/`dnf`/`zypper`/`pacman`/`apk` repository built directly from this
project's own GitHub Releases (see
[TomTonic/pkg-repo](https://github.com/TomTonic/pkg-repo) for how it's
built and why only the index, not every package, is signed). Once added,
`apt upgrade`/`dnf upgrade`/`pacman -Syu`/`apk upgrade` pick up new
releases automatically - no manual downloads needed.

* **Debian / Ubuntu** (and derivatives such as Linux Mint, Pop!_OS, Raspberry Pi OS):

  ```bash
  curl -fsSL https://pkg.tomtonic.de/pubkey.gpg | sudo tee /etc/apt/keyrings/tomtonic.asc
  echo "deb [signed-by=/etc/apt/keyrings/tomtonic.asc] https://pkg.tomtonic.de/apt stable main" | \
    sudo tee /etc/apt/sources.list.d/tomtonic.list
  sudo apt update && sudo apt install extract-sbom
  ```

* **Fedora / RHEL / CentOS / Rocky / AlmaLinux / openSUSE / SLES**:

  ```bash
  sudo curl -fsSL -o /etc/yum.repos.d/tomtonic.repo https://pkg.tomtonic.de/rpm/tomtonic.repo
  sudo dnf install extract-sbom   # or: sudo zypper install extract-sbom
  ```

* **Arch Linux** (and derivatives such as Manjaro, EndeavourOS):

  ```bash
  # add to /etc/pacman.conf:
  #   [tomtonic]
  #   SigLevel = Optional TrustedOnly DatabaseRequired
  #   Server = https://pkg.tomtonic.de/pacman/$arch
  curl -fsSL https://pkg.tomtonic.de/pubkey.gpg | sudo pacman-key --add -
  sudo pacman-key --lsign-key AA9C6D63B7B6C0BC18A89693E3725F71EDDAEC03
  sudo pacman -Sy extract-sbom
  ```

* **Alpine Linux**:

  ```bash
  sudo curl -fsSL -o /etc/apk/keys/tomtonic.rsa.pub https://pkg.tomtonic.de/alpine/tomtonic.rsa.pub
  echo "https://pkg.tomtonic.de/apk" | sudo tee -a /etc/apk/repositories
  sudo apk update && sudo apk add extract-sbom
  ```

The `deb`/`rpm` packages declare the external tools from
[section 4](#4-runtime-dependencies) below as recommended (not required)
dependencies - `apt install`/`dnf install` pulls in whichever of the known
package name aliases (e.g. `7zip` or `p7zip-full`) resolves on your specific
distro/version, and silently skips the rest, without failing the install.
The `apk`/`pacman` packages declare them as regular (required) dependencies
instead, since Alpine and Arch don't have a weak-dependency mechanism nfpm
can target - `apk add`/`pacman -S` therefore install them automatically too.
On Alpine, this requires the `community` repository to be enabled (it is by
default on most installs); if it isn't, enable it in
`/etc/apk/repositories` before installing, since `unshield` lives there.

## Linux: manual package download

Every [release](https://github.com/TomTonic/extract-sbom/releases) also
ships the same packages as plain assets, for anyone who'd rather not add
the repository above. Since the binary has no C library dependency (no
cgo), one package per architecture works across all versions of the
corresponding distro family that are still supported by the Go toolchain
used to build it - there is no need to pick a package per Ubuntu/Debian/
Fedora version.

* **Debian / Ubuntu** (and derivatives): download the `.deb` asset, then run:

  ```bash
  sudo apt install ./extract-sbom_<version>_<amd64|arm64>.deb
  ```

* **Fedora / RHEL / CentOS / Rocky / AlmaLinux**: download the `.rpm` asset, then run:

  ```bash
  sudo dnf install ./extract-sbom-<version>-1.<x86_64|aarch64>.rpm
  ```

* **openSUSE / SLES**: same `.rpm` asset, installed with:

  ```bash
  sudo zypper install ./extract-sbom-<version>-1.<x86_64|aarch64>.rpm
  ```

* **Alpine Linux**: download the `.apk` asset, then run:

  ```bash
  sudo apk add --allow-untrusted ./extract-sbom_<version>_<x86_64|aarch64>.apk
  ```

* **Arch Linux** (and derivatives): download the `.pkg.tar.zst` asset, then run:

  ```bash
  sudo pacman -U ./extract-sbom-<version>-1-<x86_64|aarch64>.pkg.tar.zst
  ```

All of these install the `extract-sbom` binary to `/usr/bin/extract-sbom`,
so it is immediately available on your `PATH`.

## macOS: Homebrew (recommended - auto-updating)

extract-sbom is available via a [Homebrew tap](https://github.com/TomTonic/homebrew-tap)
maintained alongside this project (not homebrew-core), published automatically
by each release:

```bash
brew install TomTonic/tap/extract-sbom
```

`brew upgrade` picks up new releases automatically. This cask does not declare
the optional external tools as Homebrew dependencies (to avoid pulling in tools
most users won't need) - install them yourself if needed, see
[section 7.1](#71-macos-homebrew).

## Linux / macOS: manual tar.gz download

Prebuilt binaries for Linux and macOS (amd64 and arm64) are also available as
plain `tar.gz` archives at:

```text
https://github.com/TomTonic/extract-sbom/releases
```

Each release ships:

- `extract-sbom_<version>_<os>_<arch>.tar.gz` - binary archive
- `checksums.txt` - SHA-256 checksums for all archives

Example for Linux amd64:

```bash
VERSION=v1.0.0
curl -Lo extract-sbom.tar.gz \
  "https://github.com/TomTonic/extract-sbom/releases/download/${VERSION}/extract-sbom_${VERSION}_linux_amd64.tar.gz"
curl -Lo checksums.txt \
  "https://github.com/TomTonic/extract-sbom/releases/download/${VERSION}/checksums.txt"
```

Verify the checksum:

```bash
sha256sum --check --ignore-missing checksums.txt
```

Expected output:

```text
extract-sbom.tar.gz: OK
```

Do not proceed if verification fails. Then extract and install:

```bash
tar xzf extract-sbom.tar.gz
sudo mv extract-sbom /usr/local/bin/extract-sbom
```

Or place the binary anywhere on your `PATH`.

On macOS the binary is not notarized, so Gatekeeper will quarantine it on
first run. Either right-click the file in Finder -> **Open** and confirm in
the dialog, or clear the quarantine flag yourself:

```bash
xattr -d com.apple.quarantine extract-sbom
```

## Windows: WinGet (recommended - auto-updating)

```powershell
winget install TomTonic.extract-sbom
```

`winget upgrade` picks up new releases automatically. This installs a
portable `extract-sbom.exe` (no system-wide installer, no registry changes)
and adds it to your `PATH` via WinGet's app-execution-alias mechanism.

## Windows: manual download

Every [release](https://github.com/TomTonic/extract-sbom/releases) also ships
`extract-sbom_<version>_windows_<amd64|arm64>.zip` directly, for anyone who'd
rather not use WinGet:

```powershell
Expand-Archive extract-sbom_<version>_windows_amd64.zip
```

Since the binary isn't code-signed, Windows SmartScreen will warn on first
run: click **More info** -> **Run anyway** (or right-click the file ->
**Properties** -> **Unblock**).

Note that the `bwrap` sandbox (used by default on Linux to run external
extraction tools) is Linux-only. On Windows, run with `--unsafe` in trusted
environments when external tools are needed; see
[section 6.5](#65-missing-bwrap-sandbox) below.

## 4. Runtime Dependencies

The binary itself has no external Go runtime dependencies. Certain input formats,
however, require external tools at runtime:

- `7zz` (7-Zip): required for CAB, 7z, MSI payload, RAR, ISO, CPIO, TAR XZ/Zstd, and encrypted ZIP fallback extraction; also the Squashfs fallback extractor
- `unshield`: required for InstallShield CAB extraction
- `unsquashfs` (squashfs-tools): preferred extractor for Squashfs filesystem images and Snap packages (`.snap`, `.squashfs`); 7-Zip is used as a fallback when it is absent
- `bwrap` (Bubblewrap, Linux only): required for sandboxed external extraction unless `--unsafe` is used

Encrypted archive note:

- encrypted ZIPs are detected and re-routed to 7-Zip automatically
- password-protected external formats (ZIP via 7-Zip re-route, 7z, RAR, MSI/CAB payload paths, InstallShield via unshield) use ordered password attempts
- passwords can be supplied via `--password` (repeatable), `EXTRACT_SBOM_PASSWORDS` (comma-separated), or `--password-file` (one password per line)

Syft is compiled into the binary. No separate Syft installation is needed.

## 5. Verify Installation

Binary available:

```bash
extract-sbom --version
```

Dependency checks:

```bash
command -v 7zz || echo "7zz missing"
command -v unshield || echo "unshield missing"
command -v unsquashfs || echo "unsquashfs missing (Squashfs/Snap; 7zz is the fallback)"
command -v bwrap || echo "bwrap missing (Linux sandbox mode)"
```

## 6. How Missing Dependencies Show Up

### 6.1 Missing output or work directory permissions

Symptoms:

- startup error like `output directory is not writable` or `work directory is not writable`

Fix:

- create directory and set permissions
- pass explicit `--output-dir` / `--work-dir`

### 6.2 Missing 7zz

When input requires 7-Zip-backed extraction (e.g., CAB, 7z, MSI, RAR, encrypted ZIP):

- extraction node status becomes `tool-missing`
- status detail mentions `7zz (7-Zip) is not installed`
- run may become partial (exit code 1) depending on policy/results

### 6.3 Missing unshield

When processing InstallShield CAB:

- extraction node status becomes `tool-missing`
- status detail mentions `unshield is not installed`

### 6.4 Missing unsquashfs

When processing a Squashfs filesystem image or Snap package:

- extract-sbom falls back to 7-Zip automatically
- if 7-Zip also cannot handle the image, the extraction node status becomes `tool-missing`

### 6.5 Missing bwrap (sandbox)

If `bwrap` is unavailable and you did not pass `--unsafe`:

- report/issues include sandbox resolution/execution denial
- external extraction is denied with explicit message referring to `--unsafe`

If you pass `--unsafe`, extract-sbom will run external tools unsandboxed and prints a warning on startup.

## 7. Getting Dependencies (Typical)

### 7.1 macOS (Homebrew)

```bash
brew install p7zip unshield squashfs
```

Sandbox note:

- `bwrap` is Linux-focused; on macOS use `--unsafe` in trusted environments when external tools are needed.

### 7.2 Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y p7zip-full unshield squashfs-tools bubblewrap
```

On newer releases (e.g. Ubuntu 24.04+) where `p7zip-full` is no longer
packaged, install the `7zip` package instead (it provides the `7zz` binary
directly).

### 7.3 Fedora / RHEL-like

```bash
sudo dnf install -y p7zip p7zip-plugins unshield squashfs-tools bubblewrap
```

Package names can vary by distribution version.
If a package is not found, search for the equivalent `7zip`, `unshield`, `squashfs-tools`, or `bubblewrap` package.

### 7.4 Arch Linux

```bash
sudo pacman -S p7zip unshield squashfs-tools bubblewrap
```

### 7.5 Alpine Linux

```bash
sudo apk add p7zip unshield squashfs-tools bubblewrap
```

`unshield` lives in the `community` repository - enable it in
`/etc/apk/repositories` if it isn't already (it is on most installs).

## 8. Minimal Post-Install Smoke Test

```bash
mkdir -p out
extract-sbom --unsafe --output-dir out integration/testdata/release/release-happy-path.zip
```

Expected:

- non-crashing execution
- generated `*.cdx.json` and report file in `out/`
- exit code 0 or 1 (partial is possible depending on available tools and scan results)
