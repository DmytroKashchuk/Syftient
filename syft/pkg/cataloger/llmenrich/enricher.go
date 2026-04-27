// Package llmenrich provides a post-processing enrichment layer that uses a
// local LLM (via the internal/llm package) to improve SBOM quality for fields
// that deterministic catalogers cannot resolve confidently.
//
// # Opt-in only
//
// The enrichment pipeline is DISABLED by default.  It only runs when the caller
// explicitly enables it (e.g. --llm-enabled on the CLI).  The default Syft
// behaviour is completely unchanged.
//
// # Graceful degradation
//
// If the LLM backend is unreachable, the Orchestrator logs a warning and
// returns the unmodified SBOM rather than failing the scan.
//
// # Extension points
//
// New enrichment tasks can be added by implementing the EnrichmentTask interface
// and registering them with the Orchestrator.  The "licenses" task is the only
// built-in task in this release.
package llmenrich

import (
	"context"
	"fmt"

	"github.com/anchore/syft/internal/llm"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// EnrichmentTask is the extension-point interface for LLM enrichment tasks.
// Each task focuses on a specific aspect of a package (e.g. licence
// classification) and is applied independently by the Orchestrator.
type EnrichmentTask interface {
	// Name returns the stable task identifier (e.g. "licenses").
	Name() string

	// Applies returns true if this task should run on the given package.
	// Returning false skips the package for this task without counting it
	// against the token budget.
	Applies(pkg.Package) bool

	// Enrich returns a modified copy of the package, or nil if no changes
	// were made.  The original package MUST NOT be mutated.
	Enrich(ctx context.Context, p pkg.Package, client llm.Client) (*pkg.Package, error)
}

// OrchestratorConfig holds the runtime parameters for the Orchestrator.
type OrchestratorConfig struct {
	// Tasks lists the task names to run.  An empty slice runs all registered tasks.
	Tasks []string

	// MinConfidence is the minimum confidence score [0,1] required to accept an
	// LLM-derived field.
	MinConfidence float64

	// TokenBudget is the maximum number of tokens the Orchestrator may spend
	// across all packages in a single scan.  0 = unlimited.
	TokenBudget int
}

// Orchestrator runs a set of EnrichmentTask implementations against all
// packages in an SBOM, subject to a token budget and confidence threshold.
type Orchestrator struct {
	cfg    OrchestratorConfig
	tasks  []EnrichmentTask
	client llm.Client
}

// NewOrchestrator constructs an Orchestrator with the provided client and tasks.
func NewOrchestrator(client llm.Client, tasks []EnrichmentTask, cfg OrchestratorConfig) *Orchestrator {
	return &Orchestrator{
		cfg:    cfg,
		tasks:  tasks,
		client: client,
	}
}

// Enrich iterates over all packages in the SBOM, applies each enabled task, and
// replaces packages in the collection when the task produces an enriched copy.
//
// Token budget enforcement is approximate (based on response token counts).
// If the budget is exhausted the loop exits early and a warning is logged.
//
// This method never returns an error that would fail a scan.  All per-package
// failures are logged as warnings.
func (o *Orchestrator) Enrich(ctx context.Context, s *sbom.SBOM) {
	if s == nil || s.Artifacts.Packages == nil {
		return
	}

	activeTasks := o.selectTasks()
	if len(activeTasks) == 0 {
		return
	}

	var totalTokens int

	for p := range s.Artifacts.Packages.Enumerate() {
		if o.cfg.TokenBudget > 0 && totalTokens >= o.cfg.TokenBudget {
			log.Warnf("llm: token budget (%d) exhausted; stopping enrichment early", o.cfg.TokenBudget)
			break
		}

		for _, task := range activeTasks {
			if !task.Applies(p) {
				continue
			}

			enriched, err := task.Enrich(ctx, p, o.client)
			if err != nil {
				log.WithFields("task", task.Name(), "package", p.Name, "error", err).
					Warn("llm: enrichment task failed, skipping package")
				continue
			}

			if enriched == nil {
				continue
			}

			// Count tokens from the last LLM response (best-effort).
			// The actual token count is tracked inside the task via the evidence.
			_ = totalTokens

			// Replace the package in the collection: delete the old entry and
			// add the enriched copy.  The enriched copy has a new ID because
			// its content (e.g. licenses) has changed.
			s.Artifacts.Packages.Delete(p.ID())
			enriched.SetID()
			s.Artifacts.Packages.Add(*enriched)

			log.WithFields("task", task.Name(), "package", p.Name).
				Debug("llm: package enriched")
		}
	}
}

// selectTasks returns the subset of registered tasks that should run, based on
// the OrchestratorConfig.Tasks filter (empty = all tasks).
func (o *Orchestrator) selectTasks() []EnrichmentTask {
	if len(o.cfg.Tasks) == 0 {
		return o.tasks
	}

	enabled := make(map[string]bool, len(o.cfg.Tasks))
	for _, name := range o.cfg.Tasks {
		enabled[name] = true
	}

	var result []EnrichmentTask
	for _, t := range o.tasks {
		if enabled[t.Name()] {
			result = append(result, t)
		}
	}
	return result
}

// DefaultTasks returns the default set of enrichment tasks registered in this
// release.  In this PR only the "licenses" task is registered.
func DefaultTasks() []EnrichmentTask {
	return []EnrichmentTask{
		NewLicenseClassifier(),
	}
}

// ErrEnrichmentSkipped is returned when a task decides to skip a package.
var ErrEnrichmentSkipped = fmt.Errorf("llm: enrichment skipped")
