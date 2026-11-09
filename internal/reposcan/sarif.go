package reposcan

// SARIF 2.1.0 output, enough for GitHub code scanning upload.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// SARIF converts the report.
func (r *Report) SARIF(version string) any {
	seen := map[string]bool{}
	var rules []sarifRule
	var res []sarifResult
	for _, f := range r.Findings {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			rules = append(rules, sarifRule{ID: f.Rule})
		}
		lvl := "note"
		switch f.Severity {
		case SevFail:
			lvl = "error"
		case SevWarn:
			lvl = "warning"
		}
		text := f.Message
		if f.Evidence != "" {
			text += " | evidence: " + f.Evidence
		}
		if f.Decoded != "" {
			text += " | decoded: " + f.Decoded
		}
		sr := sarifResult{RuleID: f.Rule, Level: lvl, Message: sarifMessage{Text: text}}
		if f.Path != "" {
			loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.Path}}}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
			}
			sr.Locations = []sarifLocation{loc}
		}
		res = append(res, sr)
	}
	if res == nil {
		res = []sarifResult{}
	}
	if rules == nil {
		rules = []sarifRule{}
	}
	return sarifLog{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0",
		Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "toolchain-verify scan", Version: version,
			InformationURI: "https://github.com/Sanilas-ai/toolchain-verify", Rules: rules}}, Results: res}}}
}
