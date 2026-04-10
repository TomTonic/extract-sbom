# sbom-sentry — Software Module Guide

This document describes the solution architecture, tool selection, module
structure, interfaces, and implementation plan for sbom-sentry. It fulfils the
requirement in AGENT.md §3.1 and serves as the primary reference for subsequent
coding agent invocations.

---

## 1. Tool and Library Selection

### 1.1 Go Libraries

| Library | Version | Purpose | Rationale |
|---|---|---|---|
| `github.com/anchore/syft` | v1.x (latest stable) | SBOM cataloging in library mode | Mandatory per DESIGN.md §9.2. `syft.GetSource()` resolves a path to a `source.Source`; `syft.CreateSBOM(ctx, src, cfg)` returns an `sbom.SBOM`. Builder-pattern config via `DefaultCreateSBOMConfig().WithTool(…)`. Avoids shelling out. |
| `github.com/CycloneDX/cyclonedx-go` | v0.10.x | SBOM data model, encoding, decoding | Standard Go binding for CycloneDX 1.6. Provides `BOM`, `Component`, `Dependency`, `Composition` types plus JSON/XML encoder/decoder. Used for merging per-subtree SBOMs and adding container components. |
| `github.com/mholt/archives` | v0.1.x | Archive extraction (pure Go) | Supports ZIP, TAR (+gzip/bz2/xz/zstd/lz4), RAR (read-only), 7z (read-only). Pure Go, no cgo. Provides `archives.Identify()` for format detection, `format.Extract(ctx, input, handler)`, and `archives.FileSystem()` returning `io/fs.FS`. Does **not** support CAB or MSI. |
| `github.com/spf13/cobra` | v1.x | CLI framework | De facto standard for Go CLIs. Provides flag parsing, subcommands, help generation. Low-risk, widely adopted. |
| `github.com/spf13/viper` | v1.x | Configuration binding | Binds CLI flags, env vars, and config files to a single config struct. Pairs naturally with cobra. |

### 1.2 External Binaries

| Binary | Purpose | Rationale |
|---|---|---|
| **7-Zip** (`7z` / `7zz`) | Extract CAB and MSI files | mholt/archives does not support CAB or MSI. 7-Zip handles both natively, is widely packaged on Linux, and is the preferred extractor per DESIGN.md §9.2. It is the **only** external binary dependency for extraction. |
| **Bubblewrap** (`bwrap`) | Sandbox for external binary invocations | Lightweight Linux namespace sandbox (LGPL-2.1). Used by Flatpak. Provides mount, PID, network, and IPC namespace isolation without requiring root or Docker. Applicable to all `7z` invocations. |

### 1.3 Tool Availability Strategy

| Mechanism | Available | Not Available |
|---|---|---|
| `bwrap` | All `7z` invocations are sandboxed | User must pass `--unsafe` flag; extraction runs unsandboxed. Prominently flagged in report. |
| `7z` | CAB and MSI extraction proceeds normally | CAB/MSI archives are recorded as non-extractable components in the SBOM. Audit report notes missing tool. |
| Syft | Required; binary can also serve as fallback | Fatal error. |

---

## 2. Module Overview

```
cmd/
  sbom-sentry/          CLI entry point

internal/
  config/               Configuration types and defaults
  identify/             Format detection
  extract/              Archive extraction engine
  safeguard/            Security validation (paths, symlinks, ratios)
  sandbox/              Isolation wrapper (bwrap / passthrough)
  scan/                 Syft integration
  assembly/             CycloneDX SBOM merge and construction
  report/               Audit report generation
  policy/               Policy enforcement (strict / partial)
  orchestrator/         End-to-end pipeline coordination
```

---

## 3. Module Specifications

### 3.1 `cmd/sbom-sentry`

**Purpose:** Binary entry point. Parses CLI arguments, constructs a `config.Config`,
and delegates to the orchestrator.

**Interface:**
```
main()
  → cobra root command
    → run(cfg config.Config) error
```

**Key flags:**
- `--input` / positional arg: path to delivery file
- `--output-dir`: target directory for SBOM + report
- `--format`: SBOM output format (`cyclonedx-json` default)
- `--policy`: `strict` (default) | `partial`
- `--mode`: `installer-semantic` (default) | `physical`
- `--report`: `human` (default) | `machine` | `both`
- `--language`: `en` (default) | `de`
- `--unsafe`: enable unsandboxed extraction (must never be silent)
- `--max-depth`, `--max-files`, `--max-size`, `--max-entry-size`,
  `--max-ratio`, `--timeout`: override default limits

**Design decisions:**
- No subcommands. Single verb: run the inspection.
- `--unsafe` prints a hard warning to stderr before proceeding.

---

### 3.2 `internal/config`

**Purpose:** Central configuration struct and defaults.

**Interface:**
```go
type Config struct {
    InputPath       string
    OutputDir       string
    SBOMFormat      string        // "cyclonedx-json"
    PolicyMode      PolicyMode    // Strict | Partial
    InterpretMode   InterpretMode // Physical | InstallerSemantic
    ReportMode      ReportMode    // Human | Machine | Both
    Language        string        // "en" | "de"
    Unsafe          bool
    Limits          Limits
}

type Limits struct {
    MaxDepth     int
    MaxFiles     int
    MaxTotalSize int64  // bytes
    MaxEntrySize int64  // bytes
    MaxRatio     int
    Timeout      time.Duration
}

func DefaultLimits() Limits
func (c *Config) Validate() error
```

**Design decisions:**
- All limits have tested defaults matching DESIGN.md §6.1.
- `Validate()` enforces invariants (e.g. input file must exist, output dir writable).

---

### 3.3 `internal/identify`

**Purpose:** Detect the format of a file without extracting it.

**Interface:**
```go
type FormatInfo struct {
    Format     Format   // ZIP, TAR, GzipTAR, CAB, MSI, SevenZip, RAR, Unknown
    MIMEType   string
    Extension  string
    NativeGo   bool     // true if mholt/archives can handle it
}

func Identify(ctx context.Context, path string) (FormatInfo, error)
```

**Design decisions:**
- Uses `archives.Identify()` first. If that returns no match, falls back to
  file-magic heuristics (first 8 bytes) for CAB (`MSCF` signature) and MSI
  (OLE compound document signature `D0 CF 11 E0`).
- Never attempts extraction. Read-only, bounded I/O.

---

### 3.4 `internal/safeguard`

**Purpose:** Validate extracted paths and entries before they are written to disk.
This is the hard security boundary (DESIGN.md §6.2 / §6.3).

**Interface:**
```go
// ValidatePath checks a single entry name/path for safety violations.
// Returns a non-nil HardSecurityError on path traversal, symlink escape,
// special files, or unsafe permissions.
func ValidatePath(name string, baseDir string) error

// ValidateEntry checks size, ratio, and file-type constraints.
func ValidateEntry(header EntryHeader, limits config.Limits, stats *ExtractionStats) error

// HardSecurityError signals a non-overridable violation.
type HardSecurityError struct { /* … */ }
```

**Design decisions:**
- Hard security failures (path traversal, symlink escape, special files)
  are **never** overridable, not even in unsafe mode. They abort the
  current extraction subtree immediately.
- Ratio checking compares compressed vs. uncompressed size per entry.
- Counters for file count and total size are accumulated in `ExtractionStats`
  and checked per entry.

---

### 3.5 `internal/sandbox`

**Purpose:** Wrap external binary execution in an isolated namespace.

**Interface:**
```go
type Sandbox interface {
    // Run executes the command inside the sandbox.
    // inputPath is bind-mounted read-only; outputDir is bind-mounted read-write.
    Run(ctx context.Context, cmd string, args []string, inputPath string, outputDir string) error

    // Available reports whether this sandbox mechanism is functional.
    Available() bool

    // Name returns a human-readable identifier for audit logging.
    Name() string
}

func NewBwrapSandbox() Sandbox       // Bubblewrap implementation
func NewPassthroughSandbox() Sandbox // No isolation (unsafe fallback)
func Resolve(cfg config.Config) (Sandbox, error)
```

**Bubblewrap invocation pattern:**
```
bwrap \
  --ro-bind <input-file-dir> /input \
  --bind <output-dir> /output \
  --tmpfs /tmp \
  --proc /proc \
  --dev /dev \
  --unshare-all \
  --new-session \
  --die-with-parent \
  -- 7zz x /input/<filename> -o/output
```

**Design decisions:**
- `--unshare-all` creates new mount, PID, IPC, UTS, network, and user namespaces.
- `--die-with-parent` ensures cleanup if the parent (sbom-sentry) crashes.
- `--new-session` mitigates `TIOCSTI` injection.
- `Resolve()` checks `Available()` on the bwrap sandbox; if unavailable and
  `cfg.Unsafe == true`, returns passthrough; otherwise returns an error.
- Every invocation is logged with the sandbox name for the audit trail.

---

### 3.6 `internal/extract`

**Purpose:** Recursive, auditable extraction of archive formats.

**Interface:**
```go
// ExtractionTree is the central processing data structure.
// Each node represents a container artifact encountered during traversal.
type ExtractionNode struct {
    Path          string         // original path relative to delivery root
    Format        identify.FormatInfo
    Status        ExtractionStatus // Extracted, Skipped, Failed, SecurityBlocked
    StatusDetail  string
    ExtractedDir  string         // filesystem path of extracted contents
    Children      []*ExtractionNode
    Tool          string         // "mholt/archives" | "7zz" | "syft-native"
    SandboxUsed   string         // "bwrap" | "passthrough" | ""
    Duration      time.Duration
    EntriesCount  int
    TotalSize     int64
}

// Extract recursively extracts the given file according to config.
// Returns the root of the extraction tree.
func Extract(ctx context.Context, inputPath string, cfg config.Config, sandbox sandbox.Sandbox) (*ExtractionNode, error)
```

**Internal strategy dispatch:**
```
Identify format
  ├─ NativeGo == true  → extract with mholt/archives (in-process)
  ├─ CAB or MSI        → extract with 7zz via sandbox
  └─ Unknown           → mark as leaf (pass to Syft as-is)

For each extracted child:
  if child is a recognized container format → recurse (depth + 1)
  else → mark as leaf
```

**Design decisions:**
- **mholt/archives extraction** runs in-process but enforces all safeguard
  checks per entry via the extraction callback.
- **7-Zip extraction** is always mediated by the sandbox interface.
- Depth, file count, total size, and per-entry limits from `config.Limits`
  are enforced continuously. Violations trigger policy behavior:
  `strict` → abort entire run, `partial` → skip subtree, continue.
- Every node logs tool, sandbox, timing, and outcome for the audit trail.
- Temporary extraction directories use `os.MkdirTemp` under a
  configurable work directory and are cleaned up after processing.

---

### 3.7 `internal/scan`

**Purpose:** Invoke Syft in library mode to catalog software components in
an extracted directory tree.

**Interface:**
```go
type ScanResult struct {
    NodePath string        // matches ExtractionNode.Path
    SBOM     *cyclonedx.BOM // CycloneDX BOM for this subtree
    Error    error
}

// ScanAll walks the extraction tree and invokes Syft on each extractable leaf.
func ScanAll(ctx context.Context, root *extract.ExtractionNode, cfg config.Config) ([]ScanResult, error)
```

**Internal flow per node:**
```go
src, err := syft.GetSource(ctx, node.ExtractedDir, nil)
syftSBOM, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig().
    WithTool("sbom-sentry", version))
// Encode Syft's internal SBOM to CycloneDX JSON bytes
// Decode with cyclonedx-go into *cyclonedx.BOM
```

**Design decisions:**
- Each extracted leaf directory gets its own Syft scan.
- Syft's internal `sbom.SBOM` is serialized to CycloneDX JSON using
  Syft's own format encoder, then deserialized with `cyclonedx-go` to
  produce a standard `*cyclonedx.BOM`. This avoids coupling to Syft
  internals while preserving Syft's tested CycloneDX conversion.
- Scan errors are captured per node, not fatal to the overall run.
  The policy module decides how to handle them.

---

### 3.8 `internal/assembly`

**Purpose:** Merge per-node CycloneDX BOMs into one consolidated SBOM. Add
container-as-module components and the dependency graph.

**Interface:**
```go
// Assemble builds the final, unified CycloneDX BOM.
func Assemble(tree *extract.ExtractionNode, scans []scan.ScanResult, cfg config.Config) (*cyclonedx.BOM, error)
```

**Assembly rules:**
1. Create a top-level `Component` (type `Application`) for the input file itself.
2. For every `ExtractionNode`:
   - Create a `Component` (type `File`) representing the container artifact.
   - Set `BOMRef` to a deterministic identifier derived from the node path.
   - Attach any hashes (SHA-256 at minimum) computed during extraction.
3. For every `ScanResult`:
   - Merge its `BOM.Components` into the unified component list.
   - Prefix each `BOMRef` with the node path to avoid collisions.
4. Build `Dependencies`:
   - Each container component `dependsOn` its child container components
     and the packages discovered inside it.
5. Set `Compositions`:
   - `Complete` for fully extracted subtrees.
   - `Incomplete` for skipped, failed, or security-blocked nodes.
   - `Unknown` for nodes where Syft scan failed.
6. Set `Metadata.Tools` to include sbom-sentry + Syft version info.
7. Encode to CycloneDX JSON via `cyclonedx.NewBOMEncoder(writer, cyclonedx.BOMFileFormatJSON)`.

**Design decisions:**
- BOMRef namespacing by node path guarantees uniqueness across merged BOMs.
- Composition completeness annotations enable downstream consumers to
  programmatically assess coverage without reading the audit report.
- The dependency graph models containment/origin (per DESIGN.md §5.2),
  not runtime linkage.

---

### 3.9 `internal/report`

**Purpose:** Generate the audit report from the processing state.

**Interface:**
```go
type ReportData struct {
    Input            InputSummary
    Config           config.Config
    Tree             *extract.ExtractionNode
    Scans            []scan.ScanResult
    PolicyDecisions  []policy.Decision
    SandboxInfo      SandboxSummary
    StartTime        time.Time
    EndTime          time.Time
}

// GenerateHuman writes a human-readable Markdown report.
func GenerateHuman(data ReportData, lang string, w io.Writer) error

// GenerateMachine writes a structured JSON report.
func GenerateMachine(data ReportData, w io.Writer) error
```

**Required content (per DESIGN.md §10.4):**
- Input identification (filename, size, SHA-256, SHA-512)
- Configuration snapshot (limits, policy, mode, language)
- Interpretation mode and policy mode
- Full recursive extraction log (tree-structured)
- Tools and isolation used per extraction step
- SBOM modeling assumptions
- Whether unsafe override was active
- Summary of completeness and limitations
- Explicit residual risk statement

**Design decisions:**
- Human-readable output is Markdown (renders well in terminals, browsers, and
  PDF pipelines).
- Machine-readable output is JSON matching a documented schema.
- i18n uses Go `embed` with simple template files per language. No heavy
  localization framework. Two languages: EN (default), DE.
- The report is generated after all processing is complete, from a read-only
  snapshot of the processing state.

---

### 3.10 `internal/policy`

**Purpose:** Evaluate limit violations and determine processing behavior.

**Interface:**
```go
type Decision struct {
    Trigger    string       // what limit was hit
    NodePath   string       // where in the tree
    Action     Action       // Abort | Skip | Continue
    Detail     string
}

type Engine struct { /* … */ }

func NewEngine(mode config.PolicyMode) *Engine
func (e *Engine) Evaluate(violation Violation) Decision
func (e *Engine) Decisions() []Decision
```

**Design decisions:**
- In `strict` mode, any violation produces `Abort`.
- In `partial` mode, the offending subtree is `Skip`-ped; processing
  continues elsewhere.
- Hard security failures (`safeguard.HardSecurityError`) always produce
  `Abort` regardless of policy mode.
- All decisions are collected for the audit report.

---

### 3.11 `internal/orchestrator`

**Purpose:** Coordinate the end-to-end processing pipeline.

**Interface:**
```go
func Run(ctx context.Context, cfg config.Config) error
```

**Pipeline:**
```
1. cfg.Validate()
2. Compute input file hash (SHA-256, SHA-512)
3. sandbox.Resolve(cfg) → Sandbox
4. extract.Extract(ctx, cfg.InputPath, cfg, sandbox) → ExtractionTree
5. scan.ScanAll(ctx, tree, cfg) → []ScanResult
6. assembly.Assemble(tree, scans, cfg) → *cyclonedx.BOM
7. Write SBOM to output file
8. report.Generate*(reportData, cfg, outputWriter)
9. Clean up temporary directories
10. Return exit code (0 = success, 1 = partial/incomplete, 2 = hard failure)
```

**Design decisions:**
- The orchestrator owns the lifecycle of temporary directories.
- Exit codes are deterministic and machine-parseable.
- Errors at any stage are captured in `ReportData` before the report
  is generated, so all failures are always documented.

---

## 4. Data Flow Diagram

```
                        ┌────────────────┐
                        │  Input File    │
                        └──────┬─────────┘
                               │
                    ┌──────────▼──────────┐
                    │  identify.Identify  │
                    └──────────┬──────────┘
                               │ FormatInfo
                    ┌──────────▼──────────┐
                    │  extract.Extract    │◄───── safeguard.*
                    │  (recursive)        │◄───── sandbox.Run
                    └──────────┬──────────┘
                               │ ExtractionTree
                    ┌──────────▼──────────┐
                    │  scan.ScanAll       │  (Syft library mode)
                    └──────────┬──────────┘
                               │ []ScanResult (CycloneDX BOMs)
                    ┌──────────▼──────────┐
                    │  assembly.Assemble  │
                    └──────────┬──────────┘
                               │ *cyclonedx.BOM (unified)
              ┌────────────────┼────────────────┐
              ▼                                  ▼
     SBOM output file                  report.Generate*
     (CycloneDX JSON)                  (Markdown / JSON)
```

---

## 5. Key Architectural Decisions

### 5.1 Syft SBOM → CycloneDX Conversion Path

Syft internally uses its own `sbom.SBOM` type. To produce a CycloneDX BOM:

1. Encode `sbom.SBOM` to CycloneDX JSON bytes using Syft's built-in
   `cyclonedxjson` format encoder.
2. Decode those bytes with `cyclonedx-go`'s `NewBOMDecoder` into a
   standard `*cyclonedx.BOM`.

This approach avoids deep coupling to Syft's internal types while
leveraging Syft's well-tested CycloneDX conversion logic.

### 5.2 ExtractionTree as Central State

The `ExtractionNode` tree is the single source of truth for what was
processed, how, and with what outcome. Both the SBOM assembly and the
audit report are derived from this tree. This guarantees consistency
between the two outputs.

### 5.3 Hard Security vs. Policy Limits

Two distinct categories, enforced at different layers:

| Category | Examples | Layer | Overridable? |
|---|---|---|---|
| Hard security | Path traversal, symlink escape, special files | `safeguard` | Never |
| Resource limits | Depth, file count, total size, ratio, timeout | `extract` + `policy` | Via policy mode |

The `--unsafe` flag affects only the sandbox requirement, never the
hard security checks.

### 5.4 Single External Binary

7-Zip is the only required external binary. It covers the two format
families (CAB with all compressed variants, MSI via OLE compound
document extraction) that have no viable pure-Go library. All other
formats are handled in-process.

### 5.5 Deterministic Output

- Components are sorted by BOMRef before encoding.
- Dependencies are sorted by Ref.
- Hashes are computed before any processing begins.
- Timestamps in the SBOM use the input file's modification time,
  not the current wall clock.

---

## 6. Implementation Plan

### Phase 1 — Foundation

**Goal:** Minimal end-to-end pipeline for a single non-nested archive.

1. Project scaffolding: `go.mod`, directory skeleton, CI (lint + test)
2. `config`: types, defaults, `Validate()`
3. `identify`: ZIP/TAR/GzipTAR detection via mholt/archives
4. `safeguard`: path validation, symlink check, ratio check
5. `extract`: single-level extraction for ZIP/TAR via mholt/archives
6. `scan`: Syft library-mode integration for one extracted directory
7. `assembly`: single-BOM passthrough (CycloneDX encoding)
8. `orchestrator`: wire everything, produce SBOM output file
9. `cmd/sbom-sentry`: cobra CLI with core flags
10. Basic end-to-end test: ZIP → SBOM

### Phase 2 — Recursive Extraction and SBOM Modeling

**Goal:** Nested containers, dependency graph, container-as-module.

1. `extract`: recursive traversal with depth tracking
2. `assembly`: multi-BOM merge, container components, dependency graph,
   composition annotations
3. `policy`: strict/partial engine
4. `report`: basic human-readable Markdown report (EN only)
5. Integration tests with nested archives (ZIP-in-ZIP, TAR.GZ-in-ZIP)

### Phase 3 — CAB/MSI and Sandbox

**Goal:** Cover Windows-native delivery formats under isolation.

1. `identify`: CAB/MSI detection via file-magic heuristics
2. `sandbox`: Bubblewrap implementation + passthrough fallback
3. `extract`: 7-Zip invocation via sandbox for CAB/MSI
4. `--unsafe` flag and associated warning logic
5. Integration tests with CAB and MSI test fixtures
6. Test sandbox availability detection and fallback behavior

### Phase 4 — Reporting and Modes

**Goal:** Full audit report, i18n, interpretation modes.

1. `report`: complete human-readable report with all required sections
2. `report`: machine-readable JSON schema and encoder
3. `report`: German language support via embedded templates
4. Installer-semantic interpretation mode in `extract` + `assembly`
5. `--report`, `--language`, `--mode` CLI flags
6. End-to-end tests for all report/mode combinations

### Phase 5 — Hardening

**Goal:** Production readiness.

1. Fuzz tests for archive parsing paths
2. Stress tests with large / deeply nested archives
3. RAR and 7z (as input formats) testing
4. macOS compatibility testing and fixes
5. Documentation review and finalization
6. Performance profiling and optimization if needed

---

## 7. Test Fixture Strategy

Test archives will be generated programmatically in Go test helpers where
possible (using `archive/zip`, `archive/tar`, etc.). For CAB and MSI
formats where no Go creation library exists, pre-built minimal test
fixtures will be committed to `testdata/`.

Fixture naming convention: `testdata/<format>/<scenario>.<ext>`
Examples:
- `testdata/zip/flat-three-files.zip`
- `testdata/zip/nested-zip-in-zip.zip`
- `testdata/cab/simple.cab`
- `testdata/msi/minimal.msi`
- `testdata/tar/gzip-nested-cab.tar.gz`

---

## 8. Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success: SBOM and report produced, all subtrees fully processed |
| 1 | Partial: some subtrees skipped or incomplete (partial policy) |
| 2 | Hard failure: security violation, missing required tool, or configuration error |
