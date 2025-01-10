package bedrock

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	awsAlgorithm   = "AWS4-HMAC-SHA256"
	awsService     = "bedrock"
	awsRequestType = "aws4_request"
	signedHeaders  = "content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amzn-bedrock-invocation-action;x-amz-user-agent"
)

// signRequest signs an HTTP request with AWS SigV4
func (c *Client) signRequest(req *http.Request) error {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Ensure host is set
	if req.Host == "" {
		req.Host = req.URL.Host
	}

	// Calculate payload hash
	payloadHash := c.hashPayload(req)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// Add required headers
	req.Header.Set("X-Amz-Date", amzDate)

	// Task 1: Create canonical request
	canonicalRequest := c.createCanonicalRequest(req, payloadHash)

	// Task 2: Create string to sign
	stringToSign := c.createStringToSign(canonicalRequest, amzDate, dateStamp)

	// Task 3: Calculate signature
	signature := c.calculateSignature(stringToSign, dateStamp)

	// Task 4: Add signature to header
	credential := fmt.Sprintf("%s/%s/%s/%s/%s",
		c.credentials.AccessKeyID, dateStamp, c.region, awsService, awsRequestType)

	authHeader := fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s",
		awsAlgorithm, credential, signedHeaders, signature)

	req.Header.Set("Authorization", authHeader)
	log.Printf("Authorization header: %s", authHeader)

	return nil
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
	req.Body = io.NopCloser(bytes.NewReader(data))

	return c.hashHex(data)
}

func (c *Client) createCanonicalRequest(req *http.Request, payloadHash string) string {
	canonicalURI := c.getCanonicalURI(req.URL)
	canonicalQueryString := c.getCanonicalQueryString(req.URL)
	canonicalHeaders := c.getCanonicalHeaders(req)

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash)
}

func (c *Client) createStringToSign(canonicalRequest, amzDate, dateStamp string) string {
	scope := fmt.Sprintf("%s/%s/%s/%s", dateStamp, c.region, awsService, awsRequestType)

	return fmt.Sprintf("%s\n%s\n%s\n%s",
		awsAlgorithm,
		amzDate,
		scope,
		c.hashHex([]byte(canonicalRequest)))
}

func (c *Client) calculateSignature(stringToSign, dateStamp string) string {
	kDate := c.hmacSHA256([]byte("AWS4"+c.credentials.SecretAccessKey), []byte(dateStamp))
	kRegion := c.hmacSHA256(kDate, []byte(c.region))
	kService := c.hmacSHA256(kRegion, []byte(awsService))
	kSigning := c.hmacSHA256(kService, []byte(awsRequestType))
	signature := c.hmacSHA256(kSigning, []byte(stringToSign))

	return hex.EncodeToString(signature)
}

func (c *Client) getCanonicalURI(u *url.URL) string {
	uri := u.EscapedPath()
	if uri == "" {
		return "/"
	}

	return uri
}

func (c *Client) getCanonicalQueryString(u *url.URL) string {
	params := u.Query()
	if len(params) == 0 {
		return ""
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		values := params[k]
		sort.Strings(values)
		for _, v := range values {
			pairs = append(pairs, fmt.Sprintf("%s=%s",
				url.QueryEscape(k), url.QueryEscape(v)))
		}
	}

	return strings.Join(pairs, "&")
}

func (c *Client) getCanonicalHeaders(req *http.Request) string {
	headers := map[string][]string{
		"content-length":                   {req.Header.Get("Content-Length")},
		"content-type":                     {req.Header.Get("Content-Type")},
		"host":                             {req.Host},
		"x-amz-content-sha256":             {req.Header.Get("X-Amz-Content-Sha256")},
		"x-amz-date":                       {req.Header.Get("X-Amz-Date")},
		"x-amzn-bedrock-invocation-action": {req.Header.Get("X-Amzn-Bedrock-Invocation-Action")},
		"x-amz-user-agent":                 {req.Header.Get("X-Amz-User-Agent")},
	}

	if token := req.Header.Get("X-Amz-Security-Token"); token != "" {
		headers["x-amz-security-token"] = []string{token}
	}

	var canonicalHeaders strings.Builder
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		values := headers[k]
		sort.Strings(values)
		canonicalHeaders.WriteString(k)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.Join(values, ","))
		canonicalHeaders.WriteString("\n")
	}

	return canonicalHeaders.String()
}

func (c *Client) hashHex(data []byte) string {
	hash := sha256.Sum256(data)

	return hex.EncodeToString(hash[:])
}

func (c *Client) hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)

	return mac.Sum(nil)
}
