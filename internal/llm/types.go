package llm

import "time"

// Request is the input to an LLM generation call.
type Request struct {
	// Prompt is the user-facing prompt to send to the model.
	Prompt string `json:"prompt"`

	// SystemPrompt is the optional system-level instruction for the model.
	SystemPrompt string `json:"system_prompt,omitempty"`

	// Schema is a JSON schema string for structured (JSON) output mode.
	// When non-empty the provider SHOULD constrain its response to this schema.
	Schema string `json:"schema,omitempty"`

	// Temperature controls randomness; 0.0 = fully deterministic.
	Temperature float64 `json:"temperature"`

	// Seed enables reproducibility when the provider supports it.
	Seed int `json:"seed,omitempty"`

	// MaxTokens is the maximum number of tokens to generate.
	MaxTokens int `json:"max_tokens,omitempty"`

	// Timeout overrides the client-level timeout for this specific request.
	// Zero means: use the client default.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// Response is the output of an LLM generation call.
type Response struct {
	// Content is the primary (parsed) content from the model.
	Content string `json:"content"`

	// RawContent is the full, unmodified response body from the provider.
	RawContent string `json:"raw_content,omitempty"`

	// Latency is the wall-clock time of the generation call.
	Latency time.Duration `json:"latency"`

	// PromptTokens is the number of tokens consumed by the prompt.
	PromptTokens int `json:"prompt_tokens"`

	// ResponseTokens is the number of tokens produced by the response.
	ResponseTokens int `json:"response_tokens"`

	// Model is the model name/tag that produced this response.
	Model string `json:"model"`

	// PromptHash is a sha256 digest of (promptTemplate + input + model + modelVersion)
	// used as the cache key.
	PromptHash string `json:"prompt_hash"`

	// Confidence is a [0,1] score extracted from structured JSON output, if present.
	Confidence float64 `json:"confidence,omitempty"`
}

// ModelInfo describes the LLM model being used by a Client.
type ModelInfo struct {
	// Provider is the backend name (e.g. "ollama").
	Provider string `json:"provider"`

	// Name is the model name/tag (e.g. "llama3.2:3b").
	Name string `json:"name"`

	// Version is the model digest or version string, if available.
	Version string `json:"version,omitempty"`
}

// Evidence is the structured metadata attached to every LLM-derived SBOM field.
// It is stored in pkg.Package.Metadata under the key LLMEvidenceMetadataKey so
// that it survives a JSON round-trip without altering the standard SBOM schema.
type Evidence struct {
	// Source is always "llm".
	Source string `json:"source"`

	// Model is the ModelInfo.Name of the model that produced this value.
	Model string `json:"model"`

	// Confidence is a [0,1] score as reported by the model.
	Confidence float64 `json:"confidence"`

	// PromptHash is the sha256 digest used to derive the cache key.
	PromptHash string `json:"prompt_hash"`
}
