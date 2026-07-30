# Coding Agent Instructions — extract-sbom

This document defines **how** the project must be implemented,
independent of the functional design in DESIGN.md.

---

## 1. Language and Project Basics

- All relevant code must be written in **Go**
- Use Go modules for dependency management
- Minimize external dependencies where practical
- Existing, well-maintained tools and libraries may be used when they
   reduce implementation risk, improve archive coverage, or provide
   stronger safety guarantees than a bespoke implementation
- The selection of such tools is a solution design decision and must be
   documented in the software module guide, including the reason for the
   choice and the intended scope of use

---

## 2. Code Style and Quality

- Go source files should be small, cohesive, and responsibility-focused
- Target: ≤ 400 LOC for ~85% of files
- More than 600 LOC is a strong indicator for splitting
- Follow standard Go conventions (`gofmt`, `go vet`)
- Use `golangci-lint` with a project configuration
- Keep functions focused and reasonably small
- Prefer returned errors over panics
- Use error wrapping (`fmt.Errorf("context: %w", err)`)
- Never use `panic` in library code

---

## 3. Documentation Requirements

All project documentation shall be in English.

### 3.1 Solution Design Documentation

An overall software module guide shall be maintained, describing:

- The abstract interaction between the software modules
- The abstract interface definition of every software module
- The design decisions encapsulated within every software module
- It shall cover own code as well as external tools, libraries, and
   helper binaries selected for the implementation

### 3.2 Code Documentation

Every non-trivial function or data structure must have a GoDoc comment describing:

- What it does
- Why it exists
- How it is typically used
- Relevant parameters and return values
- Constraints or assumptions

### 3.3 Test Documentation

Each test must be documented **outside-in**, from the user's perspective:

- What end-user behavior is being validated
- In which part of the system the behavior belongs
- What concrete outcome is expected

Table-driven tests must have descriptive subtest names
that read as explicit assertions.

---

## 4. Testing Requirements

### 4.1 Mandatory Test Categories

The project must include:

1. **Unit tests**
   - Happy path + corner cases
   - Load and stress tests where advisable

2. **Integration tests**
   - Focussed on interfaces between software modules
   - Between Go modules
   - Between Go code and external tools
   - Include tests with real supported archive formats (for example ZIP, CAB, MSI, TAR)

3. **End-to-end tests**
   - One input file → SBOM + audit report
   - Nested container scenarios
   - Limit-trigger behavior

### 4.2 Coverage

- Aim for high and meaningful coverage (>80%)
- Critical security paths must be explicitly tested
- Fuzz tests are encouraged for archive parsing

---

## 5. Security Expectations

- Treat all input as hostile
- Protect against zip bombs, path traversal, and resource exhaustion
- Isolation failures must surface as explicit, testable outcomes

---

## 6. CI / CD Requirements

All changes must be validated by automated checks, including:

- `go build`
- `go test`
- `go test -race`
- `go test -cover`
- `golangci-lint`
- Additional format-specific linters or validators when the project
   introduces such file types; the selection is a solution design
   decision documented in the software module guide

CI must fail on linting or test failures.

---

## 7. Commit Message Rules

- Use imperative mood (“Add feature”, not “Added feature”)
- Keep subject lines concise
- Prefix dependency updates consistently (`deps-upd:`)
- Separate subject and body with a blank line

---

## 8. Syft Usage Guidelines

- Syft is mandatory
- Prefer library-mode usage
- Do not shell out unless unavoidable
- Capture sufficient metadata for SBOM and report explanation

---

## 9. Reporting Obligations

- Reports must be deterministic in structure
- All skipped or failed steps must be documented
- Language selection (EN/DE) must be explicit
- Avoid jargon; explain decisions and consequences

---

## 10. Definition of Done

Work is complete when:

- The tool builds and runs on Linux
- One input file yields one SBOM and one audit report
- Recursive extraction behaves as specified
- Limits and policies are enforced and tested
- CI passes without exceptions
- Output is auditable, reproducible, and understandable

---

## 11. Release Notes

Release notes cover everything changed since the last published git tag (i.e.
`git log <last-tag>..HEAD`). Describe what actually changed and why it
matters — not a log replay.

Output: raw Markdown source in the chat response, ready to paste directly into
GitHub's "Release notes" text box. Do not write a `RELEASE_NOTES_*.md` file (or
any other file) unless explicitly asked for one.

Always emit all six section headers below, in order, even when a section has
nothing to report — never drop a header. An empty section gets a single
italicized line, e.g. `_Nothing to report this release._`, instead of content.

### New Features
User-visible capabilities that did not exist in the previous release. Describe
each feature from the user's perspective: what they can do now that they
couldn't before, and when they would use it. Avoid internal implementation
detail unless it directly affects usage. Include capabilities inherited from
an upstream update of a core functional dependency (see "Core dependency
pass-through" below), attributed as such.

### Changed Behavior
Existing functionality that works differently after the upgrade. Call out
anything that could require users to update their configuration, tooling, or
expectations. If a change is breaking, flag it explicitly. Include behavior
changes inherited from a core functional dependency's own bug fixes (see
below), attributed as such.

### Architectural Changes
Significant restructuring of the codebase that affects how components interact,
how the project is organized, or how it is extended. Include here only changes
that a contributor or integrator would notice. Pure internal refactors with no
external impact may be omitted (this is the one section that may legitimately
stay empty release after release).

### Source Code Updates
Language/runtime dependency updates, including Go toolchain bumps (a new
compiler may change runtime behavior or safety guarantees), plus notable
direct/transitive module bumps.

**CVE enumeration (IDs only, no descriptions):** for every dependency bumped
in this release, check whether the new version fixes a disclosed CVE/GHSA that
was *not* already fixed in the version used at the last release. Verify each
candidate against the dependency's own release notes/changelog or the
GitHub/Go vulnerability databases — never guess or infer an identifier. List
every ID that is newly fixed by this update batch, regardless of whether this
project's code actually exercises the affected component — a CVE scanner run
against this project's dependency tree would flag it either way, so it belongs
here too. If none are newly fixed, state that explicitly (e.g. "No CVEs were
fixed by this update batch.") rather than silently omitting the check.

**Core dependency pass-through:** `github.com/anchore/syft` is this project's
core functional dependency (it does the actual SBOM extraction), so its own
upstream changelog matters as much as this project's commits. Whenever syft is
bumped, read its release notes for the covered version range and surface:
new capabilities → New Features; bug fixes/behavior changes → Changed
Behavior; security fixes → the CVE enumeration above (same newly-fixed rule).
Attribute each as "Inherited from the syft upgrade: ...".

### Flagged Advisories (Not Applicable)
CVE/GHSA IDs that a scanner would likely still flag against a bumped
dependency's version number, but that do not apply to code this project
actually exercises — e.g. an advisory in Docker Engine's buildkit component
when this project only imports the `docker/cli` library, or an advisory
already fixed before this project's last release baseline. List each ID with
a very short (few-words) reason it doesn't apply, so readers cross-checking
scanner output against this changelog aren't left wondering why it's missing
from Source Code Updates.

### CI Updates
CI pipeline changes: linter upgrades, new analysis rules, runner image updates,
build matrix or workflow restructuring. Flag linter changes that now reject
previously accepted patterns.

### Writing Guidelines

- Plain English; assume domain knowledge, not day-to-day development context.
- Concrete names (component, flag, or file) — not "various improvements".
- Cross-mention items that span sections (e.g. a CVE fix in Source Code Updates and Security).
- One–two sentences per bullet; link to the relevant issue/PR when available.
- Synthesize commits; do not restate them verbatim.
