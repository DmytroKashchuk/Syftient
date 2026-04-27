package llmenrich

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/llm"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func makePackage(name, version string, licenses ...pkg.License) pkg.Package {
	p := pkg.Package{
		Name:     name,
		Version:  version,
		Type:     pkg.PythonPkg,
		Licenses: pkg.NewLicenseSet(licenses...),
	}
	p.SetID()
	return p
}

// alwaysApplyTask is a stub EnrichmentTask that always applies and returns a
// canned enriched package.
type alwaysApplyTask struct {
	enriched *pkg.Package
	err      error
}

func (t *alwaysApplyTask) Name() string { return "stub" }
func (t *alwaysApplyTask) Applies(_ pkg.Package) bool { return true }
func (t *alwaysApplyTask) Enrich(_ context.Context, p pkg.Package, _ llm.Client) (*pkg.Package, error) {
	if t.err != nil {
		return nil, t.err
	}
	if t.enriched != nil {
		return t.enriched, nil
	}
	return &p, nil
}

// neverApplyTask is a stub EnrichmentTask that never applies.
type neverApplyTask struct{}

func (t *neverApplyTask) Name() string { return "never" }
func (t *neverApplyTask) Applies(_ pkg.Package) bool { return false }
func (t *neverApplyTask) Enrich(_ context.Context, _ pkg.Package, _ llm.Client) (*pkg.Package, error) {
	return nil, nil
}

func newTestSBOM(packages ...pkg.Package) *sbom.SBOM {
	collection := pkg.NewCollection(packages...)
	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: collection,
		},
	}
}

func TestOrchestrator_EnrichesPackages(t *testing.T) {
	original := makePackage("mylib", "1.0")
	mc := llm.NewMockClient(llm.ModelInfo{Provider: "mock", Name: "test-model"})

	enriched := original
	enriched.Version = "1.0-enriched"
	enriched.SetID()

	task := &alwaysApplyTask{enriched: &enriched}
	orch := NewOrchestrator(mc, []EnrichmentTask{task}, OrchestratorConfig{})

	s := newTestSBOM(original)
	orch.Enrich(context.Background(), s)

	// The enriched package should be in the collection.
	found := false
	for p := range s.Artifacts.Packages.Enumerate() {
		if p.Version == "1.0-enriched" {
			found = true
		}
	}
	assert.True(t, found, "expected enriched package to be present in SBOM")
}

func TestOrchestrator_SkipsNonApplicablePackages(t *testing.T) {
	original := makePackage("mylib", "1.0")
	mc := llm.NewMockClient(llm.ModelInfo{Provider: "mock", Name: "test-model"})

	task := &neverApplyTask{}
	orch := NewOrchestrator(mc, []EnrichmentTask{task}, OrchestratorConfig{})

	s := newTestSBOM(original)
	orch.Enrich(context.Background(), s)

	// Package count should be unchanged.
	assert.Equal(t, 1, s.Artifacts.Packages.PackageCount())
}

func TestOrchestrator_NilSBOM(t *testing.T) {
	mc := llm.NewMockClient(llm.ModelInfo{})
	orch := NewOrchestrator(mc, DefaultTasks(), OrchestratorConfig{})
	// Should not panic.
	orch.Enrich(context.Background(), nil)
}

func TestOrchestrator_TaskFilterByName(t *testing.T) {
	mc := llm.NewMockClient(llm.ModelInfo{})
	taskA := &alwaysApplyTask{}
	taskB := &neverApplyTask{}

	orch := NewOrchestrator(mc, []EnrichmentTask{taskA, taskB},
		OrchestratorConfig{Tasks: []string{"stub"}})

	selected := orch.selectTasks()
	require.Len(t, selected, 1)
	assert.Equal(t, "stub", selected[0].Name())
}

func TestOrchestrator_EmptyTaskFilter_ReturnsAll(t *testing.T) {
	mc := llm.NewMockClient(llm.ModelInfo{})
	taskA := &alwaysApplyTask{}
	taskB := &neverApplyTask{}

	orch := NewOrchestrator(mc, []EnrichmentTask{taskA, taskB}, OrchestratorConfig{})
	selected := orch.selectTasks()
	assert.Len(t, selected, 2)
}

func TestDefaultTasks(t *testing.T) {
	tasks := DefaultTasks()
	require.Len(t, tasks, 1)
	assert.Equal(t, "licenses", tasks[0].Name())
}
