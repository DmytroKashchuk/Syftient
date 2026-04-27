package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultOllamaEndpoint = "http://localhost:11434"
	defaultModel          = "llama3.2:3b"
	defaultTimeout        = 30 * time.Second
	maxRetries            = 1
)

// httpDoer is a small interface around *http.Client so the HTTP layer can be
// swapped in unit tests without starting a real Ollama instance.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// OllamaClient implements Client by talking to a local Ollama instance.
type OllamaClient struct {
	endpoint string
	model    string
	timeout  time.Duration
	http     httpDoer
}

// OllamaConfig holds configuration for OllamaClient.
type OllamaConfig struct {
	Endpoint string
	Model    string
	Timeout  time.Duration
}

// NewOllamaClient creates a new OllamaClient with the provided configuration.
// If Endpoint is empty it defaults to http://localhost:11434.
// If Model is empty it defaults to llama3.2:3b.
// If Timeout is zero it defaults to 30 s.
func NewOllamaClient(cfg OllamaConfig) *OllamaClient {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = defaultOllamaEndpoint
	}
	model := cfg.Model
	if model == "" {
		model = defaultModel
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &OllamaClient{
		endpoint: endpoint,
		model:    model,
		timeout:  timeout,
		http:     &http.Client{Timeout: timeout},
	}
}

var _ Client = (*OllamaClient)(nil)

// ModelInfo returns the provider / model metadata for this client.
func (c *OllamaClient) ModelInfo() ModelInfo {
	return ModelInfo{
		Provider: "ollama",
		Name:     c.model,
	}
}

// HealthCheck calls POST /api/tags to verify the Ollama daemon is reachable
// and the configured model is listed.
func (c *OllamaClient) HealthCheck(ctx context.Context) error {
	url := c.endpoint + "/api/tags"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("llm: ollama health-check request creation: %w", err)
	}

	resp, err := c.doWithRetry(req)
	if err != nil {
		return fmt.Errorf("llm: ollama health-check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("llm: ollama health-check returned status %d", resp.StatusCode)
	}

	// Parse the tag list and check that the configured model is present.
	var tagsResp struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err != nil {
		// If we cannot parse the list, treat the daemon as reachable but log.
		return nil
	}
	for _, m := range tagsResp.Models {
		if m.Name == c.model {
			return nil
		}
	}
	return fmt.Errorf("llm: model %q not found in Ollama; run: ollama pull %s", c.model, c.model)
}

// ollamaGenerateRequest mirrors the Ollama /api/generate request body.
type ollamaGenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	System string `json:"system,omitempty"`
	Format string `json:"format,omitempty"`
	Stream bool   `json:"stream"`
	Options struct {
		Temperature float64 `json:"temperature"`
		Seed        int     `json:"seed,omitempty"`
		NumPredict  int     `json:"num_predict,omitempty"`
	} `json:"options"`
}

// ollamaGenerateResponse mirrors the non-streaming Ollama /api/generate response.
type ollamaGenerateResponse struct {
	Response           string `json:"response"`
	Model              string `json:"model"`
	PromptEvalCount    int    `json:"prompt_eval_count"`
	EvalCount          int    `json:"eval_count"`
	Done               bool   `json:"done"`
}

// Generate sends a generate request to Ollama and returns a Response.
func (c *OllamaClient) Generate(ctx context.Context, req Request) (*Response, error) {
	timeout := c.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body := ollamaGenerateRequest{
		Model:  c.model,
		Prompt: req.Prompt,
		System: req.SystemPrompt,
		Stream: false,
	}
	body.Options.Temperature = req.Temperature
	body.Options.Seed = req.Seed
	body.Options.NumPredict = req.MaxTokens

	if req.Schema != "" {
		body.Format = "json"
	}

	start := time.Now()

	raw, ollamaResp, err := c.doGenerate(ctx, body)
	if err != nil {
		return nil, err
	}

	return &Response{
		Content:        ollamaResp.Response,
		RawContent:     raw,
		Latency:        time.Since(start),
		PromptTokens:   ollamaResp.PromptEvalCount,
		ResponseTokens: ollamaResp.EvalCount,
		Model:          ollamaResp.Model,
	}, nil
}

func (c *OllamaClient) doGenerate(ctx context.Context, body ollamaGenerateRequest) (string, *ollamaGenerateResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", nil, fmt.Errorf("llm: marshal ollama request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.endpoint+"/api/generate", bytes.NewReader(payload))
	if err != nil {
		return "", nil, fmt.Errorf("llm: create ollama request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.doWithRetry(httpReq)
	if err != nil {
		return "", nil, fmt.Errorf("llm: ollama generate call: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("llm: ollama returned status %d", httpResp.StatusCode)
	}

	rawBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("llm: read ollama response: %w", err)
	}

	var ollamaResp ollamaGenerateResponse
	if err := json.Unmarshal(rawBytes, &ollamaResp); err != nil {
		return "", nil, fmt.Errorf("llm: decode ollama response: %w", err)
	}

	return string(rawBytes), &ollamaResp, nil
}

// doWithRetry executes the request with at most one retry on transient failure.
func (c *OllamaClient) doWithRetry(req *http.Request) (*http.Response, error) {
	var (
		resp *http.Response
		err  error
	)

	// We clone the body before first attempt so we can replay it on retry.
	var bodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("llm: read request body for retry: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 && len(bodyBytes) > 0 {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		resp, err = c.http.Do(req)
		if err == nil {
			return resp, nil
		}
	}
	return nil, err
}
