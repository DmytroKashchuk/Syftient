package llm

import (
	"context"
	"fmt"
	"sync"
)

// Call records a single invocation of MockClient.Generate.
type Call struct {
	Req Request
	Err error
}

// MockClient is a test-only implementation of Client that returns pre-configured
// responses and records all calls made to it.
type MockClient struct {
	mu        sync.Mutex
	info      ModelInfo
	responses []Response
	errors    []error
	Calls     []Call
	callIdx   int
}

// NewMockClient returns a MockClient configured with the given ModelInfo.
func NewMockClient(info ModelInfo) *MockClient {
	return &MockClient{info: info}
}

var _ Client = (*MockClient)(nil)

// ModelInfo returns the pre-configured ModelInfo.
func (m *MockClient) ModelInfo() ModelInfo {
	return m.info
}

// HealthCheck always returns nil on a MockClient.
func (m *MockClient) HealthCheck(_ context.Context) error {
	return nil
}

// AddResponse queues a canned Response (with nil error) to be returned in order.
func (m *MockClient) AddResponse(r Response) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses = append(m.responses, r)
	m.errors = append(m.errors, nil)
}

// AddError queues a canned error (with zero Response) to be returned in order.
func (m *MockClient) AddError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses = append(m.responses, Response{})
	m.errors = append(m.errors, err)
}

// Generate returns the next canned response/error pair.  It records the call
// regardless of the outcome.
func (m *MockClient) Generate(_ context.Context, req Request) (*Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Calls = append(m.Calls, Call{Req: req})

	if m.callIdx >= len(m.responses) {
		return nil, fmt.Errorf("llm: MockClient has no more canned responses (call %d)", m.callIdx)
	}

	resp := m.responses[m.callIdx]
	err := m.errors[m.callIdx]
	m.callIdx++

	if err != nil {
		return nil, err
	}
	return &resp, nil
}
