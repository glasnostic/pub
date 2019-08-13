package oms

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type OmsLogger struct {
	CustomerId    string
	SharedKey     string
	LogTypes      []string
	GinLogMatcher *regexp.Regexp
}

func NewOmsLogger(customerId, sharedKey, logType string) *OmsLogger {
	return &OmsLogger{
		CustomerId:    customerId,
		SharedKey:     sharedKey,
		LogTypes:      []string{fmt.Sprintf("%s_LOGS", logType), fmt.Sprintf("%s_HTTP", logType)},
		GinLogMatcher: regexp.MustCompile(ginPattern),
	}
}

func (o *OmsLogger) Write(p []byte) (n int, err error) {
	now := time.Now()
	matches := o.GinLogMatcher.FindStringSubmatch(string(p))
	if len(matches) > 0 {
		httpStatus, latency := parseFromGinLog(matches)
		return o.writeHTTP(now, p, httpStatus, latency)
	}
	return o.writeLogs(now, p)
}

func (o *OmsLogger) buildSignature(date string, length int, method string, contentType string, resource string) string {
	xHeaders := fmt.Sprintf("x-ms-date:%s", date)
	stringToHash := fmt.Sprintf("%s\n%d\n%s\n%s\n%s", method, length, contentType, xHeaders, resource)
	bytesToHash := []byte(stringToHash)
	decodeKey, _ := base64.StdEncoding.DecodeString(o.SharedKey)
	mac := hmac.New(sha256.New, decodeKey)
	mac.Write(bytesToHash)
	encodedHash := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	authorization := fmt.Sprintf("SharedKey %s:%s", o.CustomerId, encodedHash)
	return authorization
}

func (o *OmsLogger) postData(now time.Time, body []byte, logType string) (n int, err error) {
	contentType := "application/json"
	resource := "/api/logs"
	contentLength := len(body)

	// Azure doesn't support UTC so we need to change it to GMT
	rfc1123date := strings.Replace(now.UTC().Format(time.RFC1123), "UTC", "GMT", 1)
	// Build signature
	signature := o.buildSignature(rfc1123date, contentLength, http.MethodPost, contentType, resource)
	uri := fmt.Sprintf("https://%s.ods.opinsights.azure.com%s?api-version=2016-04-01", o.CustomerId, resource)

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, uri, bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}
	req.Header.Add("content-type", contentType)
	req.Header.Add("Authorization", signature)
	req.Header.Add("Log-Type", logType)
	req.Header.Add("x-ms-date", rfc1123date)

	if _, err := client.Do(req); err != nil {
		return 0, err
	}
	return contentLength, nil
}
