package llm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/cache"
)

func TestCachedClient_CachesResponses(t *testing.T) {
	// Set up an in-memory cache so responses are actually stored between calls.
	original := cache.GetManager()
	cache.SetManager(cache.NewInMemory(1 * time.Hour))
	t.Cleanup(func() { cache.SetManager(original) })

	mc := NewMockClient(ModelInfo{Provider: "mock", Name: "test-model", Version: "1"})
	mc.AddResponse(Response{Content: "cached", Model: "test-model"})

	cached := NewCachedClient(mc)

	req := Request{Prompt: "hello", Temperature: 0}

	// First call — should hit mock.
	r1, err := cached.Generate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, r1)

	// Second call with the same request — should be served from cache (mock would
	// return "no more responses" if called again).
	r2, err := cached.Generate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, r2)

	assert.Equal(t, r1.Content, r2.Content)
	// Verify the mock was only called once.
	assert.Equal(t, 1, len(mc.Calls))
}

func TestCachedClient_DifferentRequestsDifferentKeys(t *testing.T) {
	// Set up an in-memory cache so responses are actually stored between calls.
	original := cache.GetManager()
	cache.SetManager(cache.NewInMemory(1 * time.Hour))
	t.Cleanup(func() { cache.SetManager(original) })

	mc := NewMockClient(ModelInfo{Provider: "mock", Name: "test-model", Version: "1"})
	mc.AddResponse(Response{Content: "response-A", Model: "test-model"})
	mc.AddResponse(Response{Content: "response-B", Model: "test-model"})

	cached := NewCachedClient(mc)

	reqA := Request{Prompt: "prompt A", Temperature: 0}
	reqB := Request{Prompt: "prompt B", Temperature: 0}

	rA, err := cached.Generate(context.Background(), reqA)
	require.NoError(t, err)

	rB, err := cached.Generate(context.Background(), reqB)
	require.NoError(t, err)

	assert.NotEqual(t, rA.Content, rB.Content)
	assert.Equal(t, 2, len(mc.Calls))
}

func TestCachedClient_HealthCheckDelegates(t *testing.T) {
	mc := NewMockClient(ModelInfo{})
	cached := NewCachedClient(mc)

	err := cached.HealthCheck(context.Background())
	assert.NoError(t, err)
}

func TestCachedClient_ModelInfoDelegates(t *testing.T) {
	info := ModelInfo{Provider: "mock", Name: "test-model", Version: "2"}
	mc := NewMockClient(info)
	cached := NewCachedClient(mc)

	assert.Equal(t, info, cached.ModelInfo())
}

func TestDeriveKey_Deterministic(t *testing.T) {
	req := Request{Prompt: "hello", SystemPrompt: "sys"}
	info := ModelInfo{Name: "model", Version: "v1"}

	k1 := deriveKey(req, info)
	k2 := deriveKey(req, info)
	assert.Equal(t, k1, k2)
}

func TestDeriveKey_DifferentInputs(t *testing.T) {
	info := ModelInfo{Name: "model", Version: "v1"}

	k1 := deriveKey(Request{Prompt: "a"}, info)
	k2 := deriveKey(Request{Prompt: "b"}, info)
	assert.NotEqual(t, k1, k2)
}
