package json

import "fmt"

// buildIntegrityV2 validates entity and projection references and computes integrity metrics.
//
// entityConflicts carries structural warnings detected during entity building
// (e.g. duplicate BOMRefs) that are surfaced alongside dangling-reference errors.
func buildIntegrityV2(entities entitiesV2, projections ProjectionsV2, entityConflicts []string) integrityV2 {
	allEntityIDs := map[string]struct{}{}
	nodeIDs := map[string]struct{}{}
	componentIDs := map[string]struct{}{}

	for i := range entities.Nodes {
		allEntityIDs[entities.Nodes[i].ID] = struct{}{}
		nodeIDs[entities.Nodes[i].ID] = struct{}{}
	}
	for i := range entities.ScanTasks {
		allEntityIDs[entities.ScanTasks[i].ID] = struct{}{}
	}
	for i := range entities.Components {
		allEntityIDs[entities.Components[i].ID] = struct{}{}
		componentIDs[entities.Components[i].ID] = struct{}{}
	}
	for i := range entities.PackageGroups {
		allEntityIDs[entities.PackageGroups[i].ID] = struct{}{}
	}
	for i := range entities.Vulnerabilities {
		allEntityIDs[entities.Vulnerabilities[i].ID] = struct{}{}
	}
	for i := range entities.Suppressions {
		allEntityIDs[entities.Suppressions[i].ID] = struct{}{}
	}
	for i := range entities.PolicyDecisions {
		allEntityIDs[entities.PolicyDecisions[i].ID] = struct{}{}
	}
	for i := range entities.Issues {
		allEntityIDs[entities.Issues[i].ID] = struct{}{}
	}

	validationErrors := make([]string, 0)
	validationErrors = append(validationErrors, entityConflicts...)
	dangling := 0

	addMissing := func(msg string) {
		dangling++
		validationErrors = append(validationErrors, msg)
	}

	for i := range entities.ScanTasks {
		if entities.ScanTasks[i].NodeID == "" {
			addMissing(fmt.Sprintf("scanTasks[%d] missing nodeId", i))
		} else if _, ok := nodeIDs[entities.ScanTasks[i].NodeID]; !ok {
			addMissing(fmt.Sprintf("scanTasks[%d] references unknown nodeId %q", i, entities.ScanTasks[i].NodeID))
		}
		for j := range entities.ScanTasks[i].ComponentIDs {
			if _, ok := componentIDs[entities.ScanTasks[i].ComponentIDs[j]]; !ok {
				addMissing(fmt.Sprintf("scanTasks[%d] references unknown componentId %q", i, entities.ScanTasks[i].ComponentIDs[j]))
			}
		}
	}

	for i := range entities.PackageGroups {
		for j := range entities.PackageGroups[i].ComponentIDs {
			if _, ok := componentIDs[entities.PackageGroups[i].ComponentIDs[j]]; !ok {
				addMissing(fmt.Sprintf("packageGroups[%d] references unknown componentId %q", i, entities.PackageGroups[i].ComponentIDs[j]))
			}
		}
	}

	for i := range entities.Vulnerabilities {
		if entities.Vulnerabilities[i].ComponentID == "" {
			addMissing(fmt.Sprintf("vulnerabilities[%d] missing componentId", i))
			continue
		}
		if _, ok := componentIDs[entities.Vulnerabilities[i].ComponentID]; !ok {
			addMissing(fmt.Sprintf("vulnerabilities[%d] references unknown componentId %q", i, entities.Vulnerabilities[i].ComponentID))
		}
	}

	for i := range entities.Suppressions {
		if entities.Suppressions[i].SuppressedComponentID != "" {
			if _, ok := componentIDs[entities.Suppressions[i].SuppressedComponentID]; !ok {
				addMissing(fmt.Sprintf("suppressions[%d] references unknown suppressedComponentId %q", i, entities.Suppressions[i].SuppressedComponentID))
			}
		}
		if entities.Suppressions[i].KeptComponentID != "" {
			if _, ok := componentIDs[entities.Suppressions[i].KeptComponentID]; !ok {
				addMissing(fmt.Sprintf("suppressions[%d] references unknown keptComponentId %q", i, entities.Suppressions[i].KeptComponentID))
			}
		}
	}

	for i := range entities.PolicyDecisions {
		if entities.PolicyDecisions[i].NodeID == "" {
			continue
		}
		if _, ok := nodeIDs[entities.PolicyDecisions[i].NodeID]; !ok {
			addMissing(fmt.Sprintf("policyDecisions[%d] references unknown nodeId %q", i, entities.PolicyDecisions[i].NodeID))
		}
	}

	checkRefs := func(contextName string, refs []string) {
		for _, ref := range refs {
			if _, ok := allEntityIDs[ref]; !ok {
				addMissing(fmt.Sprintf("%s references unknown sourceRef %q", contextName, ref))
			}
		}
	}

	for i := range projections.ExtractionLog {
		checkRefs(fmt.Sprintf("extractionLog[%d]", i), projections.ExtractionLog[i].SourceRefs)
	}
	for i := range projections.Vulnerabilities {
		checkRefs(fmt.Sprintf("vulnerabilities[%d]", i), projections.Vulnerabilities[i].SourceRefs)
	}
	for i := range projections.Issues {
		checkRefs(fmt.Sprintf("issues[%d]", i), projections.Issues[i].SourceRefs)
	}
	for i := range projections.ComponentIndex {
		group := &projections.ComponentIndex[i]
		checkRefs(fmt.Sprintf("componentIndex[%d]", i), group.SourceRefs)
		for j := range group.Occurrences {
			checkRefs(fmt.Sprintf("componentIndex[%d].occurrences[%d]", i, j), group.Occurrences[j].SourceRefs)
		}
	}

	state := "ok"
	if dangling > 0 {
		state = "warning"
	}

	return integrityV2{
		Counts: integrityCountsV2{
			Nodes:           len(entities.Nodes),
			ScanTasks:       len(entities.ScanTasks),
			Components:      len(entities.Components),
			PackageGroups:   len(entities.PackageGroups),
			Vulnerabilities: len(entities.Vulnerabilities),
			Suppressions:    len(entities.Suppressions),
			PolicyDecisions: len(entities.PolicyDecisions),
			Issues:          len(entities.Issues),
		},
		DanglingReferenceCount: dangling,
		ValidationState:        state,
		ValidationErrors:       validationErrors,
	}
}
