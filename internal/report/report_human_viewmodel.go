package report

// humanReportViewModel is the precomputed state consumed by human renderers.
// It separates expensive aggregation from output formatting.
type humanReportViewModel struct {
	data         ReportData
	language     string
	translations translations
	sections     []reportSection
	occurrences  []componentOccurrence
	indexStats   componentIndexStats
	extStats     extractionStats
	scnStats     scanStats
	polStats     policyStats
}

// buildHumanReportViewModel derives deterministic section and statistics data
// once so different renderer backends can reuse the same snapshot.
func buildHumanReportViewModel(data ReportData, lang string) humanReportViewModel {
	occurrences, indexStats := collectComponentOccurrences(data.BOM)
	t := getTranslations(lang)
	return humanReportViewModel{
		data:         data,
		language:     lang,
		translations: t,
		sections:     reportSections(t),
		occurrences:  occurrences,
		indexStats:   indexStats,
		extStats:     collectExtractionStats(data.Tree),
		scnStats:     collectScanStats(data.Scans),
		polStats:     collectPolicyStats(data.PolicyDecisions),
	}
}
