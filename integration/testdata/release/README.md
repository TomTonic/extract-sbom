# Release Happy-Path Fixture

This directory contains a single release validation input archive:

- `release-happy-path.zip`

The archive is intentionally synthetic and focuses on happy-path processing.
It contains nested artifacts that exercise recursive extraction and Syft-native
handling:

- nested `.7z`
- nested `.cab`
- nested `.tgz`
- nested `.jar`
- multi-level nesting (`zip -> 7z -> tgz -> jar`)

## License Sources

Fixture payload files are built from permissively licensed open-source license
texts copied into [third_party_licenses](third_party_licenses):

- github.com/spf13/cobra (Apache-2.0)
- github.com/spf13/viper (MIT)
- github.com/anchore/syft (Apache-2.0)

## Validation Target

The release workflow runs the built candidate in a Docker container with
`7zz` and `unshield` installed and verifies:

- a valid CycloneDX SBOM is produced
- required delivery-path entries exist in the SBOM
- extraction status for `.7z`, `.cab`, `.tgz` is `extracted`
- `.jar` entries are handled as `syft-native`
