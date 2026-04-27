package llmenrich

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/llm"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

// knownNoAssertionValues is the set of SPDX "no information" license identifiers.
// A package whose every license value is in this set (or has no licenses) is
// eligible for LLM classification.
var knownNoAssertionValues = map[string]bool{
	"NOASSERTION": true,
	"NONE":        true,
	"":            true,
}

// placeholderSPDXLicenses is a tiny representative sample of common SPDX
// identifiers used to bound the structured-output schema enum.
//
// TODO: load the full SPDX license list from internal/spdxlicense in a
// follow-up PR.
var placeholderSPDXLicenses = []string{
	"MIT",
	"Apache-2.0",
	"GPL-2.0-only",
	"GPL-2.0-or-later",
	"GPL-3.0-only",
	"GPL-3.0-or-later",
	"LGPL-2.1-only",
	"LGPL-2.1-or-later",
	"BSD-2-Clause",
	"BSD-3-Clause",
	"ISC",
	"MPL-2.0",
	"CDDL-1.0",
	"EPL-2.0",
	"AGPL-3.0-only",
	"Unlicense",
	"CC0-1.0",
	"NOASSERTION",
}

// licenseClassifierSystemPrompt is the system-level instruction for the model.
// TODO: tune prompt and add few-shot examples in a follow-up PR.
const licenseClassifierSystemPrompt = `You are an expert software license analyst.
Your task is to identify the most likely SPDX license identifier for a software package.
Always respond with valid JSON matching the provided schema.
If you are not confident, set "confidence" to a low value and use "NOASSERTION".`

// licenseClassifierPromptTemplate is the user-facing prompt template.
// The placeholder %s is replaced with the package summary at runtime.
//
// TODO: tune prompt and add few-shot examples in a follow-up PR.
const licenseClassifierPromptTemplate = `Identify the SPDX license for the following package:

Name: %s
Version: %s
Type: %s
Language: %s

Respond ONLY with JSON matching this schema:
{"license": "<SPDX-ID>", "confidence": <0.0-1.0>}`

// licenseClassifyResponse is the expected JSON response from the model.
type licenseClassifyResponse struct {
	License    string  `json:"license"`
	Confidence float64 `json:"confidence"`
}

// LicenseClassifier is an EnrichmentTask that targets packages with
// NOASSERTION / empty SPDX licenses and attempts to classify them using the
// configured LLM.
type LicenseClassifier struct{}

// NewLicenseClassifier returns a new LicenseClassifier.
func NewLicenseClassifier() *LicenseClassifier {
	return &LicenseClassifier{}
}

var _ EnrichmentTask = (*LicenseClassifier)(nil)

// Name returns the stable task identifier.
func (lc *LicenseClassifier) Name() string {
	return "licenses"
}

// Applies returns true when the package has no known SPDX license — i.e. all
// license SPDXExpressions are NOASSERTION / NONE / empty, or the package has
// no licenses at all.
func (lc *LicenseClassifier) Applies(p pkg.Package) bool {
	licenses := p.Licenses.ToSlice()
	if len(licenses) == 0 {
		return true
	}
	for _, l := range licenses {
		expr := strings.TrimSpace(l.SPDXExpression)
		if !knownNoAssertionValues[expr] {
			// At least one license already has a recognised SPDX expression —
			// no need to enrich this package.
			return false
		}
	}
	return true
}

// Enrich calls the LLM to classify the package license, attaches evidence
// metadata, and returns a modified copy of the package.  Returns nil if the
// model response fails the confidence threshold.
func (lc *LicenseClassifier) Enrich(ctx context.Context, p pkg.Package, client llm.Client) (*pkg.Package, error) {
	prompt := fmt.Sprintf(licenseClassifierPromptTemplate,
		p.Name, p.Version, p.Type, p.Language)

	req := llm.Request{
		Prompt:       prompt,
		SystemPrompt: licenseClassifierSystemPrompt,
		Temperature:  0.0,
	}

	resp, err := client.Generate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("llm license classifier: generate: %w", err)
	}

	var classified licenseClassifyResponse
	if err := json.Unmarshal([]byte(resp.Content), &classified); err != nil {
		log.WithFields("package", p.Name, "raw", resp.Content).
			Debug("llm: could not parse license classifier response as JSON")
		return nil, fmt.Errorf("llm license classifier: parse response: %w", err)
	}

	// Validate that the returned license is in our known list.
	if !isKnownSPDXID(classified.License) {
		log.WithFields("package", p.Name, "license", classified.License).
			Debug("llm: returned license not in known SPDX list, discarding")
		return nil, nil
	}

	// Create a value copy of the package.  We replace only Licenses and
	// Metadata (via AttachEvidence), and never mutate any shared reference
	// fields (Locations, etc.), so a shallow copy followed by full field
	// replacement is safe here.
	enriched := p
	enriched.Licenses = pkg.NewLicenseSet(pkg.License{
		SPDXExpression: classified.License,
		Value:          classified.License,
		Type:           license.Concluded,
	})

	// Attach evidence metadata so consumers know this field is LLM-derived.
	info := client.ModelInfo()
	AttachEvidence(&enriched, llm.Evidence{
		Source:     "llm",
		Model:      info.Name,
		Confidence: classified.Confidence,
		PromptHash: resp.PromptHash,
	})

	return &enriched, nil
}

// isKnownSPDXID checks whether the given identifier is in the placeholder
// SPDX license list.
//
// TODO: replace with a full lookup via internal/spdxlicense in a follow-up PR.
func isKnownSPDXID(id string) bool {
	for _, s := range placeholderSPDXLicenses {
		if strings.EqualFold(s, id) {
			return true
		}
	}
	return false
}
