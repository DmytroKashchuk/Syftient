package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeOllamaGenerateResponse is the test payload returned by the fake server.
var fakeOllamaGenerateResponse = ollamaGenerateResponse{
	Response:        `{"license":"MIT","confidence":0.92}`,
	Model:           "llama3.2:3b",
	PromptEvalCount: 12,
	EvalCount:       20,
	Done:            true,
}

func newFakeOllamaServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/generate":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(fakeOllamaGenerateResponse)
		case "/api/tags":
			payload := map[string]interface{}{
				"models": []map[string]string{{"name": "llama3.2:3b"}},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(payload)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestOllamaClient_Generate(t *testing.T) {
	srv := newFakeOllamaServer(t)
	defer srv.Close()

	client := NewOllamaClient(OllamaConfig{Endpoint: srv.URL, Model: "llama3.2:3b"})
	resp, err := client.Generate(context.Background(), Request{
		Prompt:      "what is the license?",
		Temperature: 0.0,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, fakeOllamaGenerateResponse.Response, resp.Content)
	assert.Equal(t, "llama3.2:3b", resp.Model)
	assert.Equal(t, fakeOllamaGenerateResponse.PromptEvalCount, resp.PromptTokens)
	assert.Equal(t, fakeOllamaGenerateResponse.EvalCount, resp.ResponseTokens)
}

func TestOllamaClient_HealthCheck_Reachable(t *testing.T) {
	srv := newFakeOllamaServer(t)
	defer srv.Close()

	client := NewOllamaClient(OllamaConfig{Endpoint: srv.URL, Model: "llama3.2:3b"})
	err := client.HealthCheck(context.Background())
	assert.NoError(t, err)
}

func TestOllamaClient_HealthCheck_ModelMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return an empty model list — the configured model is absent.
		payload := map[string]interface{}{"models": []map[string]string{}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	client := NewOllamaClient(OllamaConfig{Endpoint: srv.URL, Model: "llama3.2:3b"})
	err := client.HealthCheck(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in Ollama")
}

func TestOllamaClient_HealthCheck_Unreachable(t *testing.T) {
	// Point at an address where nothing is listening.
	client := NewOllamaClient(OllamaConfig{Endpoint: "http://127.0.0.1:19999", Model: "llama3.2:3b"})
	err := client.HealthCheck(context.Background())
	require.Error(t, err)
}

func TestOllamaClient_Generate_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewOllamaClient(OllamaConfig{Endpoint: srv.URL, Model: "llama3.2:3b"})
	_, err := client.Generate(context.Background(), Request{Prompt: "test"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

func TestOllamaClient_ModelInfo(t *testing.T) {
	client := NewOllamaClient(OllamaConfig{Model: "llama3.2:3b"})
	info := client.ModelInfo()
	assert.Equal(t, "ollama", info.Provider)
	assert.Equal(t, "llama3.2:3b", info.Name)
}

func TestOllamaClient_Defaults(t *testing.T) {
	client := NewOllamaClient(OllamaConfig{})
	assert.Equal(t, defaultOllamaEndpoint, client.endpoint)
	assert.Equal(t, defaultModel, client.model)
	assert.Equal(t, defaultTimeout, client.timeout)
}
