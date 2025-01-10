package main

import (
	"context"
	"log"

	"github.com/tectiv3/bedrock-go"
)

func main() {
	//load access keys from csv file and parse csv file
	filename := "keys.csv"
	creds, err := bedrock.LoadCredentials(filename)
	if err != nil {
		log.Fatalf("failed to load credentials: %v", err)
	}

	c := bedrock.NewClient("us-west-2", "arn:aws:bedrock:us-west-2:081854276596:inference-profile/us.amazon.nova-pro-v1:0", creds)

	r, err := c.Invoke(context.Background(), bedrock.Request{
		Prompt:      "How are you?",
		MaxTokens:   100,
		Temperature: 0.7,
		TopP:        0.9,
		TopK:        40,
	})
	if err != nil {
		log.Fatalf("failed to invoke model: %v", err)
	}
	log.Printf("response: %+v", r)
}
