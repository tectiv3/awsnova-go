package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/tectiv3/awsnova-go"
)

func main() {
	//load access keys from csv file and parse csv file
	filename := "keys.csv"
	creds, err := awsnova.LoadCredentials(filename)
	if err != nil {
		log.Fatalf("failed to load credentials: %v", err)
	}

	c := awsnova.NewClient("us-west-2", "arn:aws:bedrock:us-west-2:081854276596:inference-profile/us.amazon.nova-pro-v1:0", creds)

	maxTokens := 1000
	prompt := "What is the capital of France?"
	req := awsnova.Request{
		Messages: []awsnova.Message{{
			Role: "user",
			Content: []awsnova.Content{
				{Text: &prompt},
			}},
		},
		InferenceConfig: awsnova.InferenceConfig{
			MaxTokens: &maxTokens,
		},
		System: "Be conscise",
	}

	// r, err := c.Invoke(context.Background(), req)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// if r.Output != nil {
	// 	log.Printf("response: %+v", r.Output.Message)
	// } else {
	// 	log.Printf("response: %+v", r)
	// }

	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Invoke the model with response stream
	respChan, err := c.InvokeModelWithResponseStream(ctx, req)
	if err != nil {
		log.Fatalf("Failed to invoke model: %v", err)
	}

	done := false
	for resp := range respChan {
		if resp.Error != "" {
			log.Printf("Error: %s", resp.Error)
			continue
		}
		if resp.Content != "" {
			fmt.Print(resp.Content)
		}
		if resp.Done {
			done = true
			continue
		}
		if resp.Usage != nil {
			log.Printf("Input tokens: %d, Output tokens: %d", resp.Usage.InputTokens, resp.Usage.OutputTokens)
			break
		}
	}
	if done {
		log.Println("Response stream ended")
	} else {
		<-ctx.Done()
	}
}
