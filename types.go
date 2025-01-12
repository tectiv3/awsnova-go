package awsnova

import (
	"net/http"
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

type StreamResponse struct {
    Role    string // assistant, system, etc
    Content string // actual text content
    Index   int    // block index
    Done    bool   // indicates if this block is complete
    Error   string // any error message
    Usage   *struct {
        InputTokens  int
        OutputTokens int
    } // token usage stats
}

type MessageContent struct {
	MessageStart      *MessageStart       `json:"messageStart,omitempty"`
    ContentBlockDelta *ContentBlockDelta  `json:"contentBlockDelta,omitempty"`
    ContentBlockStop  *ContentBlockStop   `json:"contentBlockStop,omitempty"`
    MessageStop       *MessageStop        `json:"messageStop,omitempty"`
    Metadata          *StreamMetadata     `json:"metadata,omitempty"`
}

type MessageStart struct {
    Role string `json:"role"`
}

type MessageStop struct {
    StopReason string `json:"stopReason"`
}

type StreamMetadata struct {
    Usage struct {
        InputTokens  int `json:"inputTokens"`
        OutputTokens int `json:"outputTokens"`
    } `json:"usage"`
    Metrics struct{} `json:"metrics"`
    Trace   struct{} `json:"trace"`
}

type ContentBlockDelta struct {
    Delta struct {
        Text string `json:"text"`
    } `json:"delta"`
    ContentBlockIndex int `json:"contentBlockIndex"`
}

type ContentBlockStop struct {
    ContentBlockIndex int `json:"contentBlockIndex"`
}
