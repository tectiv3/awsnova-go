package bedrock-go

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	awsAlgorithm    = "AWS4-HMAC-SHA256"
	awsService      = "bedrock"
	awsRequestType  = "aws4_request"
	signedHeaders   = "content-type;host;x-amz-content-sha256;x-amz-date"
)

// signRequest signs an HTTP request with AWS SigV4
func (c *Client) signRequest(req *http.Request) error {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Add basic required headers
	req.Header.Set("X-Amz-Date", amzDate)
	if c.credentials.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.credentials.SessionToken)
	}

	// Calculate payload hash
	payloadHash := hashPayload(req)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// Task 1: Create canonical request
	canonicalRequest := createCanonicalRequest(req, payloadHash)

	// Task 2: Create string to sign
	stringToSign := createStringToSign(canonicalRequest, amzDate, dateStamp, c.region)

	// Task 3: Calculate signature
	signature := calculateSignature(stringToSign, dateStamp, c.region, c.credentials.SecretAccessKey)

	// Task 4: Add signature to header
	credential := fmt.Sprintf("%s/%s/%s/%s/%s",
		c.credentials.AccessKeyID, dateStamp, c.region, awsService, awsRequestType)

	authHeader := fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s",
		awsAlgorithm, credential, signedHeaders, signature)

	req.Header.Set("Authorization", authHeader)
	return nil
}

func hashPayload(req *http.Request) string {
	if req.Body == nil {
		return hashHex([]byte{})
	}

	body, _ := req.GetBody()
	if body == nil {
		return hashHex([]byte{})
	}

	payload, _ := req.GetBody()
	data, _ := bytes.ReadAll(payload)
	req.Body = bytes.NewReader(data)
	return hashHex(data)
}

func createCanonicalRequest(req *http.Request, payloadHash string) string {
	canonicalURI := getCanonicalURI(req.URL)
	canonicalQueryString := getCanonicalQueryString(req.URL)
	canonicalHeaders := getCanonicalHeaders(req)

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash)
}

func createStringToSign(canonicalRequest, amzDate, dateStamp, region string) string {
	scope := fmt.Sprintf("%s/%s/%s/%s", dateStamp, region, awsService, awsRequestType)
	return fmt.Sprintf("%s\n%s\n%s\n%s",
		awsAlgorithm,
		amzDate,
		scope,
		hashHex([]byte(canonicalRequest)))
}

func calculateSignature(stringToSign, dateStamp, region, secretKey string) string {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(awsService))
	kSigning := hmacSHA256(kService, []byte(awsRequestType))
	return hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))
}

func getCanonicalURI(u *url.URL) string {
	uri := u.EscapedPath()
	if uri == "" {
		return "/"
	}
	return uri
}

func getCanonicalQueryString(u *url.URL) string {
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

func getCanonicalHeaders(req *http.Request) string {
	headers := map[string][]string{
		"content-type":           {req.Header.Get("Content-Type")},
		"host":                   {req.Host},
		"x-amz-content-sha256":  {req.Header.Get("X-Amz-Content-Sha256")},
		"x-amz-date":            {req.Header.Get("X-Amz-Date")},
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

func hashHex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
