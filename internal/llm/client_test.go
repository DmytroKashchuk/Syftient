package llm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientInterface verifies that all concrete Client implementations satisfy
// the Client interface at compile time and at runtime.
func TestClientInterface(t *testing.T) {
	var _ Client = (*OllamaClient)(nil)
	var _ Client = (*MockClient)(nil)
	var _ Client = (*CachedClient)(nil)
}

func TestMockClient_Generate(t *testing.T) {
	info := ModelInfo{Provider: "mock", Name: "test-model", Version: "1.0"}
	mc := NewMockClient(info)

	mc.AddResponse(Response{
		Content:        `{"license":"MIT"}`,
		Model:          "test-model",
		PromptTokens:   5,
		ResponseTokens: 10,
		Confidence:     0.9,
	})

	req := Request{Prompt: "what is the license?", Temperature: 0.0}
	resp, err := mc.Generate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, `{"license":"MIT"}`, resp.Content)
	assert.Equal(t, "test-model", resp.Model)
	assert.Equal(t, 1, len(mc.Calls))
	assert.Equal(t, req.Prompt, mc.Calls[0].Req.Prompt)
}

func TestMockClient_GenerateError(t *testing.T) {
	mc := NewMockClient(ModelInfo{Provider: "mock", Name: "test-model"})
	mc.AddError(assert.AnError)

	_, err := mc.Generate(context.Background(), Request{Prompt: "test"})
	require.Error(t, err)
	assert.Equal(t, 1, len(mc.Calls))
}

func TestMockClient_NoMoreResponses(t *testing.T) {
	mc := NewMockClient(ModelInfo{Provider: "mock", Name: "test-model"})

	_, err := mc.Generate(context.Background(), Request{Prompt: "test"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no more canned responses")
}

func TestMockClient_HealthCheck(t *testing.T) {
	mc := NewMockClient(ModelInfo{})
	err := mc.HealthCheck(context.Background())
	assert.NoError(t, err)
}
