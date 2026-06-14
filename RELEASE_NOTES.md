# Release Notes

This release centers on a rebuilt report layer, additional SBOM and report
output formats, broader archive/container support, and a number of behavioral
and architectural changes. The notes below are grouped by theme and kept
high-level; see [USAGE.md](USAGE.md) for exact flags and
[MODULE_GUIDE.md](MODULE_GUIDE.md) for the package layout.

## Overview & Philosophy

**Evidence-first reporting.** The report layer was rebuilt around a single
principle: every component, suppression, and vulnerability claim must be
traceable back to observable evidence — a delivery path, an evidence path, a
cataloger, or a tool. The absence of a component is now explicitly framed as
"no usable metadata was observed," never as proof the code is absent.

**One projection, many renderers.** Reports are no longer assembled ad hoc per
format. A delivery is first projected into a strongly-typed, deterministic data
model; the Markdown, HTML, JSON, and SARIF renderers are then pure views over
that one projection. This guarantees the four formats describe exactly the same
facts.

**Deterministic by contract.** The pipeline pins the input by hash, keeps
logical delivery paths stable, sorts components and dependencies into a
canonical order, and records errors and coverage gaps instead of hiding them.
Cross-renderer ordering-contract tests lock this in.

**Auditability over brevity.** The report separates a concise executive layer
(Summary, Analysis Overview, Vulnerability Summary) from an exhaustive appendix
(Component Occurrence Index, Component Normalization, Extraction and Scan logs).
The appendix is intentionally complete for spot-checks and evidence export.

## New Features

**SPDX 2.3 JSON output.** Alongside the existing CycloneDX JSON, the tool can
now emit an SPDX 2.3 document (`--format spdx-json`), mapping components to SPDX
packages, PURLs to download locations, and the CycloneDX dependency graph to
`DEPENDS_ON` relationships — for ISO/IEC 5962 and EO 14028 style compliance
workflows.

**CycloneDX XML output.** `--format cyclonedx-xml` produces the same BOM as
CycloneDX 1.6 XML for toolchains that require it.

**Standalone HTML report.** `--report html` writes a self-contained HTML file
with embedded CSS, a sticky table-of-contents sidebar, severity-colored
vulnerability badges, a click-to-sort vulnerability table, and collapsible
sections — no external assets, suitable for handing to auditors.

**SARIF 2.1.0 report.** `--report sarif` emits one result per vulnerability
match with severity mapped to SARIF levels (error/warning/note), designed to
drop straight into GitHub/GitLab code-scanning gates via `upload-sarif`.

**Combined report modes.** `--report all` produces the Markdown, JSON, and HTML
reports in a single run; `--report both` produces Markdown + JSON.

**New container/filesystem formats.** Format detection and extraction now cover
ISO 9660 images, CPIO archives, and Squashfs filesystem images including Snap
packages. AppImage bundles are detected and reported (extraction is not yet
supported).

**unsquashfs integration.** Squashfs and Snap images are extracted with
`unsquashfs` when available, falling back to 7-Zip otherwise.

**Bilingual reports.** The Markdown and HTML reports render fully in English or
German (`--language de`) from one shared translation catalog; the SBOM and the
JSON report stay English for machine consumption.

**Parallel scanning.** Package scanning runs across a bounded worker pool whose
default is derived from `GOMAXPROCS`, with `--parallel` to tune it — faster on
large deliveries without oversubscribing the host.

**Pluggable Markdown engines.** The Markdown report can be rendered via the
default deterministic writer, a template-wrapper, or a full template-document
backend (`--markdown-render-engine`, `--markdown-template-file`) for custom
framing.

## Behavioral Changes

**JSON report defaults to the v2 schema.** The structured JSON report is now
emitted in the canonical, semantically-typed v2 schema by default. The
deprecated v1 schema is still available, but only via `--legacy-json`, for
consumers that have not yet migrated. v2 places raw provenance under a `raw`
envelope and exposes typed projections alongside it.

**Flag and output renaming.** The "human" and "machine" outputs are now
consistently called "markdown" and "json". The old `--human-render-engine` and
`--human-template-file` flags are deprecated aliases that still work; new usage
should prefer the `--markdown-*` equivalents.

**Policy mode default clarified.** The effective default policy mode is
`partial` (matching the CLI default), and the report's Configuration table now
reflects that accurately rather than a struct zero value.

**Report content reorganization.** Input, Configuration, and Sandbox details
were consolidated into a top-level "Run & Scope" section; the old bullet-list
"Key Findings" was replaced by an "Analysis Overview" of flowing prose with
inline deep links to the sections that substantiate each claim.

**Honest sandbox messaging.** When `bwrap` isolation is unavailable the report
now explains the three distinct causes (unsupported platform such as
macOS/Windows, not installed on Linux, or deliberately disabled) and what each
means for coverage, instead of a single misleading line.

**Hardened sandbox mounting.** External extractors are mounted at a fixed
`/tool/<name>` inside the sandbox (with a `/bin → /usr/bin` symlink for
shell-script shebangs), fixing cases where a tool living under `/tmp` was
shadowed by the tmpfs mount.

## Architectural Changes

**The report monolith was dissolved.** The previously large `internal/report`
package was split into focused internal subpackages: `model` (shared
contracts), `domain` (aggregation logic grouped by noun — occurrences,
vulnerabilities, suppressions, statistics), and one package per output format
(`markdown`, `html`, `json`, `sarif`). The root `report` package is now a thin
facade exposing only what the orchestrator needs.

**Shared i18n package.** All localized labels and prose live in one
`internal/report/internal/i18n` catalog with a small inline-Markdown-to-HTML
converter, so the Markdown and HTML renderers stay textually identical and
translations are maintained in exactly one place.

**Schema-validated JSON v2.** The v2 report ships with a published JSON Schema
and is validated against it in tests, so the machine contract cannot silently
drift from the implementation.

**Extraction internals refactored.** The external-extractor path was split into
separate error-classification and archive-metadata modules, making
7-Zip/unshield/unsquashfs failure handling and metadata capture independently
testable.
