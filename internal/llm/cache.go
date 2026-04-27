package llm

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/anchore/syft/internal/cache"
)

const (
	// llmCacheName is the namespace used when obtaining a cache resolver.
	llmCacheName = "llm-responses"
	// llmCacheVersion is bumped whenever the Response schema changes in a
	// backwards-incompatible way so that stale entries are automatically ignored.
	llmCacheVersion = "v1"
)

// CachedClient is a Client decorator that transparently caches responses using
// the internal/cache package.  The cache key is:
//
//	sha256(prompt + systemPrompt + model + modelVersion)
//
// Cache misses are forwarded to the wrapped Client and the result is stored.
type CachedClient struct {
	inner    Client
	resolver cache.Resolver[Response]
}

// NewCachedClient wraps the provided Client with caching.
func NewCachedClient(inner Client) *CachedClient {
	return &CachedClient{
		inner:    inner,
		resolver: cache.GetResolverCachingErrors[Response](llmCacheName, llmCacheVersion),
	}
}

var _ Client = (*CachedClient)(nil)

// ModelInfo delegates to the wrapped client.
func (c *CachedClient) ModelInfo() ModelInfo {
	return c.inner.ModelInfo()
}

// HealthCheck delegates to the wrapped client (health checks are never cached).
func (c *CachedClient) HealthCheck(ctx context.Context) error {
	return c.inner.HealthCheck(ctx)
}

// Generate returns a cached response if available; otherwise it calls the
// wrapped client and stores the result.
func (c *CachedClient) Generate(ctx context.Context, req Request) (*Response, error) {
	key := deriveKey(req, c.inner.ModelInfo())

	resp, err := c.resolver.Resolve(key, func() (Response, error) {
		r, err := c.inner.Generate(ctx, req)
		if err != nil {
			return Response{}, err
		}
		r.PromptHash = key
		return *r, nil
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// deriveKey returns sha256(prompt + systemPrompt + model + modelVersion) as a
// hex string — used as the cache key per the design spec.
func deriveKey(req Request, info ModelInfo) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s", req.Prompt, req.SystemPrompt, info.Name, info.Version)
	return fmt.Sprintf("%x", h.Sum(nil))
}
