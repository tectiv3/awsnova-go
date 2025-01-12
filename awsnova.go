package awsnova

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/tectiv3/awsnova-go/eventstream"
	// "github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

const maxPayloadLen = 1024 * 1024 * 16 // 16MB

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

// Invoke sends a request to the Claude model and returns its response
func (c *Client) Invoke(ctx context.Context, req Request) (*Response, error) {
	jsonBody, err := c.buildRequestBody(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx,
		"POST",
		fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com/model/%s/invoke",
			c.region,
			url.QueryEscape(c.modelID),
		),
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	signer, err := sigv4.New(
		sigv4.WithCredential(c.credentials.AccessKeyID, c.credentials.SecretAccessKey, ""),
		sigv4.WithRegionService("us-west-2", "bedrock"))
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	if err := signer.Sign(httpReq, c.hashPayload(httpReq), sigv4.NewTime(time.Now().UTC())); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	return c.sendRequest(ctx, httpReq)
}

func (c *Client) buildRequestBody(req Request) ([]byte, error) {
	body := map[string]interface{}{
		"schemaVersion":   "messages-v1",
		"inferenceConfig": req.InferenceConfig,
		"messages":        req.Messages,
	}

	if req.System != "" {
		body["system"] = []map[string]interface{}{
			{"text": req.System},
		}
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

// InvokeAsync calls Invoke method in a goroutine and returns a channel to receive the response
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

// InvokeModelWithResponseStream sends a request to the Claude model and streams the response to a channel
func (c *Client) InvokeModelWithResponseStream(ctx context.Context, req Request) (<-chan *StreamResponse, error) {
	respChan := make(chan *StreamResponse, 1)

	jsonBody, err := c.buildRequestBody(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx,
		"POST",
		fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com/model/%s/invoke-with-response-stream",
			c.region, url.QueryEscape(c.modelID)),
		bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/vnd.amazon.eventstream")

	signer, err := sigv4.New(
		sigv4.WithCredential(c.credentials.AccessKeyID, c.credentials.SecretAccessKey, ""),
		sigv4.WithRegionService("us-west-2", "bedrock"))
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	if err := signer.Sign(httpReq, c.hashPayload(httpReq), sigv4.NewTime(time.Now().UTC())); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	go func() {
		defer close(respChan)
		defer resp.Body.Close()

		decoder := eventstream.NewDecoder()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				payloadBuf := make([]byte, maxPayloadLen)
				message, err := decoder.Decode(resp.Body, payloadBuf)
				if err != nil {
					if err == io.EOF {
						return
					}
					log.Printf("Error decoding message: %v", err)
					respChan <- &StreamResponse{Error: err.Error()}
					return
				}
				log.Println("Message: ", string(message.Payload))
				// Parse the JSON payload
				var payloadMap map[string]interface{}
				if err := json.Unmarshal(message.Payload, &payloadMap); err != nil {
					log.Printf("Error unmarshalling payload: %v", err)
					continue
				}

				// Extract and decode the base64 bytes field
				if messageStr, ok := payloadMap["message"].(string); ok {
					respChan <- &StreamResponse{
						Error: messageStr,
						Done:  true,
					}
					return
				}

				if bytesStr, ok := payloadMap["bytes"].(string); ok {
					content, err := base64.StdEncoding.DecodeString(bytesStr)
					if err != nil {
						log.Printf("Error decoding base64 bytes: %v", err)
						continue
					}

					var msgContent MessageContent
					if err := json.Unmarshal(content, &msgContent); err != nil {
						log.Printf("Error unmarshalling message content: %v", err)
						continue
					}

					// Handle different message types
					switch {
					case msgContent.MessageStart != nil:
						respChan <- &StreamResponse{
							Role: msgContent.MessageStart.Role,
						}
					case msgContent.ContentBlockDelta != nil:
						respChan <- &StreamResponse{
							Content: msgContent.ContentBlockDelta.Delta.Text,
							Index:   msgContent.ContentBlockDelta.ContentBlockIndex,
						}
					case msgContent.ContentBlockStop != nil:
						respChan <- &StreamResponse{
							Index: msgContent.ContentBlockStop.ContentBlockIndex,
							Done:  false,
						}
					case msgContent.MessageStop != nil:
						respChan <- &StreamResponse{
							Done: true,
						}
					case msgContent.Metadata != nil:
						respChan <- &StreamResponse{
							Usage: &struct {
								InputTokens  int
								OutputTokens int
							}{
								InputTokens:  msgContent.Metadata.Usage.InputTokens,
								OutputTokens: msgContent.Metadata.Usage.OutputTokens,
							},
						}
					}
				}
			}
		}
	}()

	return respChan, nil
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
