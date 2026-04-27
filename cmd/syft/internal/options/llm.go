package options

import (
	"fmt"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
)

// LLM holds the configuration for the opt-in, local-first LLM enrichment layer.
//
// The feature is DISABLED by default.  Set Enabled=true (or pass --llm-enabled)
// to activate it.  Syft's default behaviour is completely unchanged when Enabled
// is false.
//
// Only the "ollama" provider is supported in this release.  Future providers
// (OpenAI, Anthropic, …) will be added in subsequent PRs without breaking this
// interface.
type LLM struct {
	// Enabled turns the LLM enrichment layer on or off.  Default: false.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Provider selects the LLM backend.  Currently only "ollama" is supported.
	Provider string `yaml:"provider" json:"provider" mapstructure:"provider"`

	// Endpoint is the base URL of the LLM provider.  Default: http://localhost:11434.
	Endpoint string `yaml:"endpoint" json:"endpoint" mapstructure:"endpoint"`

	// Model is the model name/tag to use.  Default: llama3.2:3b.
	Model string `yaml:"model" json:"model" mapstructure:"model"`

	// Timeout is the per-request timeout passed to the LLM provider.  Default: 30s.
	Timeout time.Duration `yaml:"timeout" json:"timeout" mapstructure:"timeout"`

	// Temperature controls randomness; 0.0 = fully deterministic.  Default: 0.0.
	Temperature float64 `yaml:"temperature" json:"temperature" mapstructure:"temperature"`

	// MinConfidence is the minimum confidence score [0,1] required to accept an
	// LLM-derived field.  Values below this threshold are discarded.  Default: 0.75.
	MinConfidence float64 `yaml:"min-confidence" json:"min_confidence" mapstructure:"min-confidence"`

	// Tasks lists the enrichment task names to run.  An empty slice means "run all
	// registered tasks".  In this release only "licenses" is registered.
	Tasks []string `yaml:"tasks" json:"tasks" mapstructure:"tasks"`

	// MaxTokens is the soft per-scan token budget.  The enricher will stop
	// processing new packages once this budget is exhausted.  Default: 100000.
	MaxTokens int `yaml:"max-tokens" json:"max_tokens" mapstructure:"max-tokens"`
}

var _ interface {
	clio.FlagAdder
	clio.FieldDescriber
	clio.PostLoader
} = (*LLM)(nil)

// DefaultLLM returns an LLM config with all defaults applied.
func DefaultLLM() LLM {
	return defaultLLM()
}

// defaultLLM returns an LLM config with all defaults applied.
func defaultLLM() LLM {
	return LLM{
		Enabled:       false,
		Provider:      "ollama",
		Endpoint:      "http://localhost:11434",
		Model:         "llama3.2:3b",
		Timeout:       30 * time.Second,
		Temperature:   0.0,
		MinConfidence: 0.75,
		Tasks:         nil,
		MaxTokens:     100000,
	}
}

// AddFlags registers the LLM flags on the provided FlagSet.
func (l *LLM) AddFlags(flags clio.FlagSet) {
	flags.BoolVarP(&l.Enabled, "llm-enabled", "",
		"enable opt-in LLM enrichment of the SBOM (requires a running Ollama instance)")

	flags.StringVarP(&l.Provider, "llm-provider", "",
		`LLM backend provider (only "ollama" is supported in this release)`)

	flags.StringVarP(&l.Endpoint, "llm-endpoint", "",
		"base URL of the LLM provider")

	flags.StringVarP(&l.Model, "llm-model", "",
		"model name/tag to use for LLM enrichment (e.g. llama3.2:3b)")
}

// DescribeFields adds human-readable descriptions for the configuration fields.
func (l *LLM) DescribeFields(descriptions fangs.FieldDescriptionSet) {
	descriptions.Add(&l.Enabled, "enable the opt-in LLM enrichment layer; disabled by default — Syft's default behaviour is unchanged when this is false")
	descriptions.Add(&l.Provider, `LLM backend provider; only "ollama" is supported in this release`)
	descriptions.Add(&l.Endpoint, "base URL of the LLM provider daemon (e.g. http://localhost:11434 for Ollama)")
	descriptions.Add(&l.Model, "model name / tag to load (e.g. llama3.2:3b); the model must already be pulled with: ollama pull <model>")
	descriptions.Add(&l.Timeout, "per-request timeout for LLM calls; zero uses the provider default")
	descriptions.Add(&l.Temperature, "sampling temperature passed to the model; 0.0 = fully deterministic")
	descriptions.Add(&l.MinConfidence, "minimum confidence score [0,1] required to accept an LLM-derived field; fields below this threshold are discarded")
	descriptions.Add(&l.Tasks, `enrichment tasks to run; empty = all registered tasks; available tasks: "licenses"`)
	descriptions.Add(&l.MaxTokens, "soft per-scan token budget; enrichment stops when this limit is reached")
}

// PostLoad validates the configuration after it has been loaded.
func (l *LLM) PostLoad() error {
	if !l.Enabled {
		return nil
	}

	if l.Provider != "ollama" {
		return fmt.Errorf("llm: unsupported provider %q; only \"ollama\" is supported in this release", l.Provider)
	}

	if l.MinConfidence < 0 || l.MinConfidence > 1 {
		return fmt.Errorf("llm: min-confidence must be in [0, 1]; got %v", l.MinConfidence)
	}

	if l.MaxTokens <= 0 {
		return fmt.Errorf("llm: max-tokens must be > 0; got %d", l.MaxTokens)
	}

	return nil
}
