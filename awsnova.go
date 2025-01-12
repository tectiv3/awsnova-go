package awsnova

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	sigv4 "github.com/imacks/aws-sigv4"
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

type InferenceConfig struct {
	MaxTokens   *int     `json:"max_new_tokens,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
	TopK        *int     `json:"top_k,omitempty"`
}

// Request represents the input for a model invocation
type Request struct {
	Prompt          string
	InferenceConfig `json:",inline"`
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

func (c *Client) buildRequestURL() string {
	return fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com/model/%s/invoke",
		c.region, url.QueryEscape(c.modelID))
}

func (c *Client) buildRequestBody(req Request) ([]byte, error) {
	body := map[string]interface{}{
		"schemaVersion":   "messages-v1",
		"inferenceConfig": req.InferenceConfig,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{"text": req.Prompt},
				},
			},
		},
	}
	return json.Marshal(body)
}

func (c *Client) sendRequest(ctx context.Context, httpReq *http.Request) (*Response, error) {
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", string(respBody))
	}

	var result Response
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// Invoke sends a request to the model and returns its response
func (c *Client) Invoke(ctx context.Context, req Request) (*Response, error) {
	jsonBody, err := c.buildRequestBody(req)

	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.buildRequestURL(), bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	signer, err := sigv4.New(
		sigv4.WithCredential(c.credentials.AccessKeyID, c.credentials.SecretAccessKey, ""),
		sigv4.WithRegionService("us-west-2", "bedrock"))
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	if err := signer.Sign(httpReq, c.hashPayload(httpReq), sigv4.NewTime(time.Now())); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	return c.sendRequest(ctx, httpReq)
}

func (c *Client) InvokeAsync(ctx context.Context, req Request) <-chan *Response {
	respChan := make(chan *Response, 1)

	go func() {
		defer close(respChan)

		resp, err := c.Invoke(ctx, req)
		if err != nil {
			log.Printf("Error in async invocation: %v", err)
			return
		}

		respChan <- resp
	}()

	return respChan
}

func (c *Client) hashPayload(req *http.Request) string {
	if req.Body == nil {
		log.Println("Request body is nil")
		return c.hashHex([]byte{})
	}

	body, _ := req.GetBody()
	if body == nil {
		log.Println("Failed to get request body")
		return c.hashHex([]byte{})
	}
	defer body.Close()

	data, _ := io.ReadAll(body)

	return c.hashHex(data)
}

func (c *Client) hashHex(data []byte) string {
	hash := sha256.Sum256(data)

	return hex.EncodeToString(hash[:])
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
