package bedrock

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// Client represents an Amazon Bedrock client for the Anthropic Claude model
type Client struct {
	httpClient  *http.Client
	region      string
	modelID     string
	credentials AWSCredentials
}

// AWSCredentials holds AWS authentication details
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // Optional
}

// NewClient creates a new Bedrock client
func NewClient(region, modelID string, creds AWSCredentials) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		region:      region,
		modelID:     modelID,
		credentials: creds,
	}
}

// Request represents the input for a model invocation
type Request struct {
	Prompt      string
	MaxTokens   int
	Temperature float64
	TopP        float64
	TopK        int
}

// Response represents the model's output
type Response struct {
	Output *struct {
		Message struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"message"`
	} `json:"output,omitempty"`
	Type  string `json:"__type"`
	Usage *struct {
		InputTokens  int `json:"inputTokens"`
		OutputTokens int `json:"outputTokens"`
	} `json:"usage,omitempty"`
	Error string `json:"error"`
}

// Invoke sends a request to the Claude model and returns its response
func (c *Client) Invoke(ctx context.Context, req Request) (*Response, error) {
	// Construct the API endpoint URL
	url := "https://bedrock-runtime.us-west-2.amazonaws.com/model/arn%3Aaws%3Abedrock%3Aus-west-2%3A081854276596%3Ainference-profile%2Fus.amazon.nova-pro-v1%3A0/invoke"

	// Prepare the request body
	body := map[string]interface{}{
		"schemaVersion": "messages-v1",
		"inferenceConfig": map[string]interface{}{
			"max_new_tokens": req.MaxTokens,
			"temperature":    req.Temperature,
			"top_p":          req.TopP,
			"top_k":          req.TopK,
		},
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{"text": req.Prompt},
				},
			},
		},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	log.Printf("Request body: %s", jsonBody)

	// Create HTTP request with a seekable body
	bodyReader := bytes.NewReader(jsonBody)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add required headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(jsonBody)))
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-Amzn-Bedrock-Invocation-Action", "InvokeModel")
	httpReq.Header.Set("X-Amz-User-Agent", "aws-sdk-js/1.0.0 os/macOS/10.15.7 lang/js md/browser/Chrome_131.0.0.0 api/bedrock_runtime/1.0.0 Bedrock")

	// Sign the request with AWS SigV4
	if err := c.signRequest(httpReq); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Reset the body reader after signing
	if _, err := bodyReader.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to reset request body: %w", err)
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
		return nil, fmt.Errorf("%s", string(respBody))
	}
	log.Printf("Response body: %s", string(respBody))
	// Parse response
	var result Response
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// LoadCredentials loads AWS credentials from a CSV file
func LoadCredentials(filepath string) (AWSCredentials, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return AWSCredentials{}, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// Skip header if exists
	reader.FieldsPerRecord = -1

	// Read all records from the CSV file
	records, err := reader.ReadAll()
	if err != nil {
		return AWSCredentials{}, err
	}
	if len(records) == 0 {
		return AWSCredentials{}, fmt.Errorf("no records found in %s", filepath)
	}
	// Skip the header row if it exists
	if len(records) > 1 {
		records = records[1:]
	}

	return AWSCredentials{
		AccessKeyID:     records[0][0],
		SecretAccessKey: records[0][1],
	}, nil
}
