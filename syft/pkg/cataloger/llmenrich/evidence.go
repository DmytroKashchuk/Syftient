package llmenrich

import (
	"github.com/anchore/syft/internal/llm"
	"github.com/anchore/syft/syft/pkg"
)

// LLMEvidenceMetadataKey is the key used to store LLM evidence inside the
// pkg.Package.Metadata map.  Using a dedicated map avoids altering the standard
// SBOM schema while still surviving a JSON round-trip.
const LLMEvidenceMetadataKey = "llm-evidence"

// llmEvidenceMetadata is the concrete type stored at LLMEvidenceMetadataKey
// inside a Package's Metadata when Metadata is a map[string]any.
type llmEvidenceMetadata struct {
	Evidence llm.Evidence `json:"llm-evidence"`
}

// AttachEvidence stores LLM Evidence metadata on the package.
//
// Strategy:
//   - If pkg.Metadata is already a map[string]any the evidence is added under
//     LLMEvidenceMetadataKey.
//   - Otherwise the existing Metadata is preserved as-is and evidence is wrapped
//     alongside it in a new map[string]any.  This keeps the original cataloger
//     metadata intact and survives a JSON round-trip.
//
// NOTE: this does NOT alter the standard SBOM schema.  The evidence lives
// exclusively in Metadata, which is serialised as a JSON object by the Syft
// formatters.
func AttachEvidence(p *pkg.Package, ev llm.Evidence) {
	meta := llmEvidenceMetadata{Evidence: ev}

	switch existing := p.Metadata.(type) {
	case map[string]any:
		existing[LLMEvidenceMetadataKey] = meta
		p.Metadata = existing
	case nil:
		p.Metadata = map[string]any{
			LLMEvidenceMetadataKey: meta,
		}
	default:
		// Preserve the original cataloger metadata and add evidence alongside it.
		p.Metadata = map[string]any{
			"original":             existing,
			LLMEvidenceMetadataKey: meta,
		}
	}
}

// GetEvidence retrieves the LLM Evidence stored on a package, if any.
// Returns (evidence, true) when evidence is present, (zero, false) otherwise.
func GetEvidence(p pkg.Package) (llm.Evidence, bool) {
	m, ok := p.Metadata.(map[string]any)
	if !ok {
		return llm.Evidence{}, false
	}
	raw, ok := m[LLMEvidenceMetadataKey]
	if !ok {
		return llm.Evidence{}, false
	}
	meta, ok := raw.(llmEvidenceMetadata)
	if !ok {
		return llm.Evidence{}, false
	}
	return meta.Evidence, true
}
