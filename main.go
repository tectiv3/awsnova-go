package bedrock-go

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client represents an Amazon Bedrock client for the Anthropic Claude model
type Client struct {
	httpClient  *http.Client
	region      string
	credentials AWSCredentials
}

// AWSCredentials holds AWS authentication details
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // Optional
}

// NewClient creates a new Bedrock client
func NewClient(region string, creds AWSCredentials) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		region:      region,
		credentials: creds,
	}
}

// Request represents the input for a model invocation
type Request struct {
	Prompt       string
	MaxTokens    int
	Temperature  float64
	TopP         float64
	TopK         int
	StopSequence []string
}

// Response represents the model's output
type Response struct {
	Completion string
	StopReason string
	Error      string
}

// Invoke sends a request to the Claude model and returns its response
func (c *Client) Invoke(ctx context.Context, req Request) (*Response, error) {
	// Construct the API endpoint URL
	url := fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com/model/arn%3Aaws%3Abedrock%3Aus-west-2%3A081854276596%3Ainference-profile%2Fus.amazon.nova-pro-v1%3A0/invoke", c.region)

	// Prepare the request body
	body := map[string]interface{}{
		"prompt":               req.Prompt,
		"max_tokens_to_sample": req.MaxTokens,
		"temperature":          req.Temperature,
		"top_p":                req.TopP,
		"top_k":                req.TopK,
		"stop_sequences":       req.StopSequence,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add required headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	// Sign the request with AWS SigV4
	if err := c.signRequest(httpReq); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Send the request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for non-200 status code
	if resp.StatusCode != http.StatusOK {
		return &Response{
			Error: fmt.Sprintf("API error: %s - %s", resp.Status, string(respBody)),
		}, nil
	}

	// Parse response
	var result struct {
		Completion string `json:"completion"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &Response{
		Completion: result.Completion,
		StopReason: result.StopReason,
	}, nil
}

// signRequest signs the request with AWS SigV4 authentication
func (c *Client) signRequest(req *http.Request) error {
	// Note: This is a placeholder. In a real implementation, you would use the
	// AWS SDK's signing package or implement AWS SigV4 signing here.
	// For brevity, the actual signing implementation is omitted.

	// Add basic authentication headers
	req.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	if c.credentials.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.credentials.SessionToken)
	}

	return nil
}
