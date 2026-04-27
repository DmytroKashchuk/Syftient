package llmenrich

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/llm"
	syftlicense "github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

func TestLicenseClassifier_Applies(t *testing.T) {
	lc := NewLicenseClassifier()

	tests := []struct {
		name     string
		licenses []pkg.License
		want     bool
	}{
		{
			name:     "no licenses",
			licenses: nil,
			want:     true,
		},
		{
			name: "NOASSERTION only",
			licenses: []pkg.License{
				{SPDXExpression: "NOASSERTION", Value: "NOASSERTION"},
			},
			want: true,
		},
		{
			name: "NONE only",
			licenses: []pkg.License{
				{SPDXExpression: "NONE", Value: "NONE"},
			},
			want: true,
		},
		{
			name: "empty expression and value",
			licenses: []pkg.License{
				{SPDXExpression: "", Value: ""},
			},
			want: true,
		},
		{
			name: "known SPDX license",
			licenses: []pkg.License{
				{SPDXExpression: "MIT", Value: "MIT"},
			},
			want: false,
		},
		{
			name: "mixed: one known license",
			licenses: []pkg.License{
				{SPDXExpression: "NOASSERTION"},
				{SPDXExpression: "MIT"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := makePackage("testpkg", "1.0", tt.licenses...)
			assert.Equal(t, tt.want, lc.Applies(p))
		})
	}
}

func TestLicenseClassifier_Enrich_Success(t *testing.T) {
	lc := NewLicenseClassifier()
	mc := llm.NewMockClient(llm.ModelInfo{Provider: "mock", Name: "llama3.2:3b", Version: "1"})
	mc.AddResponse(llm.Response{
		Content:    `{"license":"MIT","confidence":0.95}`,
		Model:      "llama3.2:3b",
		PromptHash: "abc123",
	})

	p := makePackage("mypkg", "2.0")
	enriched, err := lc.Enrich(context.Background(), p, mc)

	require.NoError(t, err)
	require.NotNil(t, enriched)

	licenses := enriched.Licenses.ToSlice()
	require.Len(t, licenses, 1)
	assert.Equal(t, "MIT", licenses[0].SPDXExpression)
	assert.Equal(t, syftlicense.Concluded, licenses[0].Type)

	// Check evidence was attached.
	ev, ok := GetEvidence(*enriched)
	require.True(t, ok)
	assert.Equal(t, "llm", ev.Source)
	assert.Equal(t, "llama3.2:3b", ev.Model)
	assert.InDelta(t, 0.95, ev.Confidence, 0.001)
}

func TestLicenseClassifier_Enrich_LLMError(t *testing.T) {
	lc := NewLicenseClassifier()
	mc := llm.NewMockClient(llm.ModelInfo{Provider: "mock", Name: "test-model"})
	mc.AddError(assert.AnError)

	p := makePackage("mypkg", "2.0")
	enriched, err := lc.Enrich(context.Background(), p, mc)

	require.Error(t, err)
	assert.Nil(t, enriched)
}

func TestLicenseClassifier_Enrich_InvalidJSON(t *testing.T) {
	lc := NewLicenseClassifier()
	mc := llm.NewMockClient(llm.ModelInfo{Provider: "mock", Name: "test-model"})
	mc.AddResponse(llm.Response{Content: "not-json"})

	p := makePackage("mypkg", "2.0")
	enriched, err := lc.Enrich(context.Background(), p, mc)

	require.Error(t, err)
	assert.Nil(t, enriched)
}

func TestLicenseClassifier_Enrich_UnknownLicenseID(t *testing.T) {
	lc := NewLicenseClassifier()
	mc := llm.NewMockClient(llm.ModelInfo{Provider: "mock", Name: "test-model"})
	mc.AddResponse(llm.Response{Content: `{"license":"TOTALLY-FAKE-LICENSE","confidence":0.99}`})

	p := makePackage("mypkg", "2.0")
	enriched, err := lc.Enrich(context.Background(), p, mc)

	// Should return nil, nil — unknown license discarded gracefully.
	require.NoError(t, err)
	assert.Nil(t, enriched)
}

func TestLicenseClassifier_Name(t *testing.T) {
	lc := NewLicenseClassifier()
	assert.Equal(t, "licenses", lc.Name())
}
