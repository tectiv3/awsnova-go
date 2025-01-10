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
	Output struct {
		Message struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"message"`
	} `json:"output"`
	Type  string `json:"__type"`
	Usage struct {
		InputTokens  int `json:"inputTokens"`
		OutputTokens int `json:"outputTokens"`
	} `json:"usage"`
	Error string `json:"error"`
}

// Invoke sends a request to the Claude model and returns its response
func (c *Client) Invoke(ctx context.Context, req Request) (*Response, error) {
	// Construct the API endpoint URL
	url := fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com/model/%s/invoke", c.region, c.modelID)

	// Prepare the request body
	body := map[string]interface{}{
		"schemaVersion": "messages-v1",
		"inferenceConfig": map[string]interface{}{
			"max_new_tokens": req.MaxTokens,
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
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-Amzn-Bedrock-Invocation-Action", "InvokeModel")

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
		return &Response{
			Error: fmt.Sprintf("API error: %s - %s", resp.Status, string(respBody)),
		}, nil
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

	first, err := reader.Read()
	if err != nil {
		return AWSCredentials{}, err
	}

	// If first row looks like a header, read next row
	if first[0] == "Access key ID" || first[0] == "AccessKeyId" {
		first, err = reader.Read()
		if err != nil {
			return AWSCredentials{}, err
		}
	}

	return AWSCredentials{
		AccessKeyID:     first[0],
		SecretAccessKey: first[1],
	}, nil
}
