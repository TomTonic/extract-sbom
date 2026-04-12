#!/usr/bin/env bash
set -euo pipefail

candidate="/opt/extract-sbom/extract-sbom"
input_zip="/opt/extract-sbom/testdata/vendor-suite-3.2.zip"
expected_paths="/opt/extract-sbom/testdata/expected-delivery-paths.txt"
out_dir="$(mktemp -d /tmp/extract-sbom-release-test.XXXXXX)"

cleanup() {
  rm -rf "$out_dir"
}
trap cleanup EXIT

set +e
"$candidate" --unsafe --output-dir "$out_dir" --root-name "vendor-suite" "$input_zip"
exit_code=$?
set -e

if [[ "$exit_code" -ne 0 && "$exit_code" -ne 1 ]]; then
  echo "unexpected extract-sbom exit code: $exit_code"
  exit 1
fi

sbom_path="$out_dir/vendor-suite-3.2.cdx.json"
report_path="$out_dir/vendor-suite-3.2.report.md"

[[ -f "$sbom_path" ]] || { echo "missing SBOM output"; exit 1; }
[[ -f "$report_path" ]] || { echo "missing report output"; exit 1; }

echo "--- checking BOM format ---"
jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.6"' "$sbom_path" >/dev/null
jq -e '.metadata.component.name == "vendor-suite"' "$sbom_path" >/dev/null

echo "--- checking expected delivery paths ---"
while IFS= read -r expected; do
  [[ -z "$expected" ]] && continue
  jq -e --arg p "$expected" \
    '[.components[]? | .properties[]? | select(.name == "extract-sbom:delivery-path") | .value] | index($p) != null' \
    "$sbom_path" >/dev/null
  echo "  ok: $expected"
done < "$expected_paths"

echo "--- checking extraction statuses ---"
jq -e '
  [
    .components[]? as $c |
    ($c.properties // []) as $props |
    {
      path: ($props[]? | select(.name == "extract-sbom:delivery-path") | .value),
      status: ($props[]? | select(.name == "extract-sbom:extraction-status") | .value)
    }
  ] as $rows |
  any($rows[]; (.path | endswith(".rpm"))    and .status == "syft-native") and
  any($rows[]; (.path | endswith(".deb"))    and .status == "syft-native") and
  any($rows[]; (.path | endswith(".jar"))    and .status == "syft-native") and
  any($rows[]; (.path | endswith(".ear"))    and .status == "syft-native") and
  any($rows[]; (.path | endswith(".tar.gz")) and .status == "extracted")   and
  any($rows[]; (.path | endswith(".tgz"))    and .status == "extracted")   and
  any($rows[]; (.path | endswith(".msi"))    and .status == "extracted")   and
  any($rows[]; (.path | endswith(".cab") and (.path | contains("prereqs"))) and .status == "extracted") and
  any($rows[]; (.path | endswith(".7z"))     and .status == "extracted")' "$sbom_path" >/dev/null
echo "  ok: all format extraction statuses correct"

echo "--- checking MSI metadata ---"
jq -e '
  .components[]? |
  select(
    (.properties // []) | any(.name == "extract-sbom:delivery-path" and (.value | endswith("client-setup.msi")))
  ) |
  .name == "Vendor FatClient" and
  .version == "3.2.0.0" and
  ((.properties // []) | any(.name == "extract-sbom:msi-product-code"))' "$sbom_path" >/dev/null
echo "  ok: MSI name, version, and product-code present"

echo "--- checking npm package from 7z ---"
jq -e '
  .components[]? |
  select(.name == "minimist" and .version == "0.0.8") |
  (.properties // []) | any(
    .name == "extract-sbom:delivery-path" and (.value | endswith(".7z"))
  )' "$sbom_path" >/dev/null
echo "  ok: minimist@0.0.8 attributed to .7z"

echo "--- checking excluded files are absent ---"
# data1.hdr must not appear (companion file, not an archive — D1 fix)
if jq -e '[.components[]? | .properties[]? | select(.name == "extract-sbom:delivery-path" and (.value | endswith("data1.hdr")))] | length > 0' "$sbom_path" >/dev/null 2>&1; then
  echo "FAIL: data1.hdr unexpectedly present in SBOM"
  exit 1
fi
echo "  ok: data1.hdr absent"

# release-notes.pdf (and any other plain files) must not appear
if jq -e '[.components[]? | .properties[]? | select(.name == "extract-sbom:delivery-path" and (.value | endswith(".pdf")))] | length > 0' "$sbom_path" >/dev/null 2>&1; then
  echo "FAIL: PDF file unexpectedly present in SBOM"
  exit 1
fi
echo "  ok: plain PDF absent"

echo "release candidate passed containerized release test"

