package assembly

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"sort"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/TomTonic/extract-sbom/internal/extract"
	"github.com/TomTonic/extract-sbom/internal/scan"
)

var shortBOMRefEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// bomRefAssigner maintains a deterministic bijection between semantic keys
// (node paths and component identity keys) and short CycloneDX BOM refs.
//
// It pre-allocates refs in sorted key order and resolves rare hash collisions
// by salting, ensuring stable output across runs.
type bomRefAssigner struct {
	byKey   map[string]string
	byRef   map[string]string
	makeRef func(string, int) string
}

// newBOMRefAssigner builds a pre-seeded assigner from the extraction tree and
// scan results so every reference used during assembly is deterministic.
func newBOMRefAssigner(tree *extract.ExtractionNode, scanMap map[string]*scan.ScanResult) *bomRefAssigner {
	return newBOMRefAssignerWithKeys(collectBOMRefKeys(tree, scanMap), makeBOMRefWithSalt)
}

// newBOMRefAssignerWithKeys creates an assigner and eagerly assigns refs in
// sorted order, making collision handling deterministic.
func newBOMRefAssignerWithKeys(keys []string, factory func(string, int) string) *bomRefAssigner {
	assigner := &bomRefAssigner{
		byKey:   make(map[string]string, len(keys)),
		byRef:   make(map[string]string, len(keys)),
		makeRef: factory,
	}

	sortedKeys := append([]string(nil), keys...)
	sort.Strings(sortedKeys)
	for _, key := range sortedKeys {
		assigner.assign(key)
	}

	return assigner
}

// RefForNode returns the deterministic BOMRef for an extraction-node path.
func (a *bomRefAssigner) RefForNode(deliveryPath string) string {
	return a.assign(deliveryPath)
}

// RefForComponent returns the deterministic BOMRef for a normalized component
// in the context of one scan node.
func (a *bomRefAssigner) RefForComponent(nodePath string, component cdx.Component, index int) string {
	return a.assign(componentRefKey(nodePath, component, index))
}

// assign returns an existing ref for key or creates a new one, retrying with
// increasing salt until any collision is resolved.
func (a *bomRefAssigner) assign(key string) string {
	if ref, ok := a.byKey[key]; ok {
		return ref
	}

	for salt := 0; ; salt++ {
		ref := a.makeRef(key, salt)
		existingKey, exists := a.byRef[ref]
		if !exists || existingKey == key {
			a.byKey[key] = ref
			a.byRef[ref] = key
			return ref
		}
	}
}

// collectBOMRefKeys traverses the tree and scan results to enumerate all keys
// that may need references during assembly.
func collectBOMRefKeys(tree *extract.ExtractionNode, scanMap map[string]*scan.ScanResult) []string {
	if tree == nil {
		return nil
	}

	seen := make(map[string]struct{})
	var visit func(node *extract.ExtractionNode)
	visit = func(node *extract.ExtractionNode) {
		if node == nil {
			return
		}

		seen[node.Path] = struct{}{}
		if sr, ok := scanMap[node.Path]; ok && sr != nil && sr.Error == nil && sr.BOM != nil && sr.BOM.Components != nil {
			candidates, _ := normalizeScanComponents(node, sr)
			for i := range candidates {
				seen[componentRefKey(node.Path, candidates[i].component, i)] = struct{}{}
			}
		}

		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(tree)

	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	return keys
}

// componentRefKey builds a stable identity key for one scan component within a
// node. Existing scanner BOMRefs are preferred; otherwise semantic fields plus
// index provide a deterministic fallback.
func componentRefKey(nodePath string, component cdx.Component, index int) string {
	if component.BOMRef != "" {
		return "component\x00" + nodePath + "\x00" + component.BOMRef
	}

	return fmt.Sprintf(
		"component\x00%s\x00%d\x00%s\x00%s\x00%s",
		nodePath,
		index,
		component.Type,
		component.Name,
		component.Version,
	)
}

// makeBOMRef creates a deterministic BOMRef from a delivery path.
func makeBOMRef(deliveryPath string) string {
	return makeBOMRefWithSalt(deliveryPath, 0)
}

// makeBOMRefWithSalt hashes key and salt into a short human-friendly token.
// Salt is only used when collision resolution is required.
func makeBOMRefWithSalt(key string, salt int) string {
	payload := key
	if salt > 0 {
		payload = fmt.Sprintf("%s\x00%d", key, salt)
	}

	h := sha256.Sum256([]byte(payload))
	token := shortBOMRefEncoding.EncodeToString(h[:5])
	return "extract-sbom:" + token[:4] + "_" + token[4:8]
}
