package oms

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (o *OmsLogger) newPostRequest(ctx context.Context, body []byte, logType LogType) (*http.Request, error) {
	const contentType = "application/json"
	const resource = "/api/logs"
	contentLength := len(body)

	// Azure doesn't support UTC, so we need to change it to GMT
	rfc1123date := strings.Replace(time.Now().UTC().Format(time.RFC1123), "UTC", "GMT", 1)
	// Build signature
	signature := buildSignature(o.SharedKey, o.CustomerId, rfc1123date, contentLength, http.MethodPost, contentType, resource)
	uri := fmt.Sprintf("https://%s.ods.opinsights.azure.com%s?api-version=2016-04-01", o.CustomerId, resource)

	req, err := http.NewRequest(http.MethodPost, uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", contentType)
	req.Header.Add("Authorization", signature)
	req.Header.Add("Log-Type", logType)
	req.Header.Add("x-ms-date", rfc1123date)
	req.Header.Add("time-generated-field", "time_generated")
	return req.WithContext(ctx), nil
}

func buildSignature(sharedKey, customerId string, date string, length int, method string, contentType string, resource string) string {
	xHeaders := fmt.Sprintf("x-ms-date:%s", date)
	stringToHash := fmt.Sprintf("%s\n%d\n%s\n%s\n%s", method, length, contentType, xHeaders, resource)
	bytesToHash := []byte(stringToHash)
	decodeKey, _ := base64.StdEncoding.DecodeString(sharedKey)
	mac := hmac.New(sha256.New, decodeKey)
	mac.Write(bytesToHash)
	encodedHash := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	authorization := fmt.Sprintf("SharedKey %s:%s", customerId, encodedHash)
	return authorization
}
