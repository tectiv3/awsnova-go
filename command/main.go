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
	ch, err := c.InvokeModelWithResponseStream(ctx, req)
	if err != nil {
		log.Fatalf("Failed to invoke model: %v", err)
	}

	for {
		select {
		case comp, ok := <-ch:
			if !ok {
				// channel closed
				return
			}

			if comp.Error != "" {
				log.Printf("Error: %s", comp.Error)
				return
			}
			if comp.Content != "" {
				fmt.Print(comp.Content)
			}
			if comp.Done {
				fmt.Println()
				log.Println("Done")
				return
			}
			if comp.Usage != nil {
				log.Printf("Input tokens: %d, Output tokens: %d", comp.Usage.InputTokens, comp.Usage.OutputTokens)
				break
			}
		case <-ctx.Done():
			log.Println("Timeout")
			return
		}
	}

}
