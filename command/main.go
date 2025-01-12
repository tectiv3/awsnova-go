package main

import (
	"context"
	"log"

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
	r, err := c.Invoke(context.Background(), awsnova.Request{
		Prompt: "How are you?",
		InferenceConfig: awsnova.InferenceConfig{
			MaxTokens: &maxTokens,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	if r.Output != nil {
		log.Printf("response: %+v", r.Output.Message)
	} else {
		log.Printf("response: %+v", r)
	}
}
