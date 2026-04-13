package assembly

import cdx "github.com/CycloneDX/cyclonedx-go"

// Suppression reason constants used in SuppressionRecord.
const (
	// SuppressionFSArtifact identifies Syft file-cataloger entries that carry
	// an absolute temp-directory path as the component Name. These represent
	// the physical file record and are always superseded by a dedicated
	// package cataloger (e.g. java-archive-cataloger) when one is present.
	// When no package cataloger identifies the file, the entry is dropped to
	// prevent temp-path leakage and SBOM noise.
	SuppressionFSArtifact = "fs-cataloger-artifact"

	// SuppressionLowValueFile identifies type=file entries that carry no
	// PURL, version, or foundBy metadata. They convey no identification
	// value and cannot be matched to a vulnerability database.
	SuppressionLowValueFile = "low-value-file"

	// SuppressionWeakDuplicate identifies entries at the same
	// (delivery-path, evidence-path) locus whose quality score is lower than
	// the best entry in that group. Only dropped when the best entry is
	// clearly superior (score >= 4, i.e. has a PURL).
	SuppressionWeakDuplicate = "weak-duplicate"

	// SuppressionPURLDuplicate identifies entries that carry the same PURL as
	// another component and are therefore collapsed into a single surviving
	// representative. The survivor inherits all unique leaf-most delivery and
	// evidence paths from the whole group.
	SuppressionPURLDuplicate = "purl-duplicate"
)

// SuppressionRecord documents a component that was removed from the SBOM
// during normalization or deduplication. Every record that appears here must
// also appear in the audit report so that the suppression decision is traceable.
type SuppressionRecord struct {
	// Reason is one of the Suppression* constants.
	Reason string
	// Component is the suppressed entry exactly as emitted by Syft.
	Component cdx.Component
	// FoundBy is the syft:package:foundBy value of the suppressed entry.
	FoundBy string
	// DeliveryPath is the delivery-path context at the time of suppression.
	DeliveryPath string
	// KeptName is the name of the component that replaced this one.
	// Only set for duplicate suppressions.
	KeptName string
	// KeptFoundBy is the foundBy of the replacement component.
	// Only set for duplicate suppressions.
	KeptFoundBy string
}

// scanComponentCandidate is the normalized in-memory representation of one
// scan-derived component before BOMRef assignment and final assembly.
//
// It keeps enough context to make deterministic deduplication decisions:
// delivery locus, optional evidence paths, cataloger provenance, and original
// order from the scanner output.
type scanComponentCandidate struct {
	component    cdx.Component
	deliveryPath string
	evidence     []string
	foundBy      string
	order        int
}

// mergedPropertyNames lists the property names that are collected across all
// entries in a PURL group and merged into the surviving component.
var mergedPropertyNames = []string{
	"extract-sbom:delivery-path",
	"extract-sbom:evidence-path",
	"extract-sbom:evidence-source",
}
