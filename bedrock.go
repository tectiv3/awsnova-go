package bedrock

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
	url := fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com/model/%s/invoke",
		c.region,
		url.QueryEscape(c.modelID))

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
	bodyBytes := bytes.NewReader(jsonBody)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	signer, err := sigv4.New(
		sigv4.WithCredential(c.credentials.AccessKeyID, c.credentials.SecretAccessKey, ""),
		sigv4.WithRegionService("us-west-2", "bedrock"))
	if err != nil {
		panic(err)
	}

	err = signer.Sign(httpReq, c.hashPayload(httpReq), sigv4.NewTime(time.Now()))
	if err != nil {
		panic(err)
	}

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
	log.Printf("Response body: %s", string(respBody))

	var result Response
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
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
