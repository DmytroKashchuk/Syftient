// Package llm provides a provider-agnostic interface for local LLM enrichment.
//
// The default Syft behaviour is UNCHANGED when LLM enrichment is not explicitly
// enabled via --llm-enabled.  All types in this package are opt-in.
package llm

import "context"

// Client is the provider-agnostic interface for LLM interactions.
// Future providers (OpenAI, Anthropic, …) can be added by implementing this
// interface without touching the rest of the enrichment pipeline.
type Client interface {
	// Generate sends a Request to the model and returns the generated Response.
	Generate(ctx context.Context, req Request) (*Response, error)

	// HealthCheck verifies that the provider is reachable and the configured
	// model is available.  Callers MUST treat a non-nil error as a soft failure
	// and continue without LLM enrichment (graceful degradation).
	HealthCheck(ctx context.Context) error

	// ModelInfo returns metadata about the model this Client is configured to use.
	ModelInfo() ModelInfo
}
