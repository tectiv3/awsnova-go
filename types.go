package awsnova

import (
	"net/http"
)

// Client represents an Amazon Bedrock client
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
}

// InferenceConfig represents the configuration for model inference
type InferenceConfig struct {
	MaxTokens   *int     `json:"max_new_tokens,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
	TopK        *int     `json:"top_k,omitempty"`
}

// Request represents the input for a model invocation
type Request struct {
	Messages        []Message `json:"messages"`
	System          string    `json:"system"`
	InferenceConfig `json:",inline"`
}

// Response represents the model's output
type Response struct {
	Output *Output `json:"output,omitempty"`
	Type   string  `json:"__type"`
	Usage  *struct {
		InputTokens  int `json:"inputTokens"`
		OutputTokens int `json:"outputTokens"`
	} `json:"usage,omitempty"`
	Error string `json:"error"`
}

// Output represents the model's response
type Output struct {
	Message Message `json:"message"`
}

// StreamResponse represents the model's response in a streaming context
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

// MessageContent represents the content of a message
type MessageContent struct {
	MessageStart      *MessageStart      `json:"messageStart,omitempty"`
	ContentBlockDelta *ContentBlockDelta `json:"contentBlockDelta,omitempty"`
	ContentBlockStop  *ContentBlockStop  `json:"contentBlockStop,omitempty"`
	MessageStop       *MessageStop       `json:"messageStop,omitempty"`
	Metadata          *StreamMetadata    `json:"metadata,omitempty"`
}

// MessageStart represents the start of a message in a stream
type MessageStart struct {
	Role string `json:"role"`
}

// MessageStop represents the end of a message in a stream
type MessageStop struct {
	StopReason string `json:"stopReason"`
}

// StreamMetadata represents the metadata of a stream
type StreamMetadata struct {
	Usage struct {
		InputTokens  int `json:"inputTokens"`
		OutputTokens int `json:"outputTokens"`
	} `json:"usage"`
	Metrics struct{} `json:"metrics"`
	Trace   struct{} `json:"trace"`
}

// ContentBlockDelta represents a block of content in a stream
type ContentBlockDelta struct {
	Delta struct {
		Text string `json:"text"`
	} `json:"delta"`
	ContentBlockIndex int `json:"contentBlockIndex"`
}

// ContentBlockStop represents the end of a block of content in a stream
type ContentBlockStop struct {
	ContentBlockIndex int `json:"contentBlockIndex"`
}

// Message represents a message to be sent to the model
type Message struct {
	Role    string    `json:"role"`
	Content []Content `json:"content"`
}

// Content represents the content of a message
type Content struct {
	Text  *string `json:"text,omitempty"`
	Image *Image  `json:"image,omitempty"`
	Video *Video  `json:"video,omitempty"`
}

// Image represents an image in a message
type Image struct {
	Format string `json:"format"`
	Source struct {
		Bytes string `json:"bytes"`
	} `json:"source"`
}

type Video struct {
	Format string `json:"format"`
	Source struct {
		S3Location struct {
			URI         string `json:"uri"`
			BucketOwner string `json:"bucketOwner"`
		} `json:"s3Location"`
		Bytes string `json:"bytes"`
	} `json:"source"`
}
