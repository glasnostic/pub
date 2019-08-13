package oms

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	updatePeriod = time.Minute
)

type OmsLogger struct {
	CustomerId    string
	SharedKey     string
	LogTypes      []LogType
	GinLogMatcher *regexp.Regexp

	queue   chan logEntry
	batches map[LogType][]*logEntry
}

func NewOmsLogger(customerId, sharedKey, logTypePrefix LogType) *OmsLogger {
	logger := &OmsLogger{
		CustomerId:    customerId,
		SharedKey:     sharedKey,
		LogTypes:      []LogType{fmt.Sprintf("%s_LOGS", logTypePrefix), fmt.Sprintf("%s_HTTP", logTypePrefix)},
		GinLogMatcher: regexp.MustCompile(ginPattern),

		queue:   make(chan logEntry),
		batches: make(map[LogType][]*logEntry),
	}
	go logger.run()
	return logger
}

func (o *OmsLogger) Write(p []byte) (n int, err error) {
	matches := o.GinLogMatcher.FindStringSubmatch(string(p))
	if len(matches) > 0 {
		httpStatus, latency := parseFromGinLog(matches)
		return o.writeLogs(p, o.LogTypes[1], WithHttpStatus(httpStatus), WithLatency(latency))
	}
	return o.writeLogs(p, o.LogTypes[0])
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

func (o *OmsLogger) postData(body []byte, logType LogType) (n int, err error) {
	contentType := "application/json"
	resource := "/api/logs"
	contentLength := len(body)

	// Azure doesn't support UTC so we need to change it to GMT
	rfc1123date := strings.Replace(time.Now().UTC().Format(time.RFC1123), "UTC", "GMT", 1)
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
	req.Header.Add("time-generated-field", "time_generated")

	if _, err := client.Do(req); err != nil {
		return 0, err
	}
	return contentLength, nil
}

func (o *OmsLogger) run() {
	tick := time.Tick(updatePeriod)
	for {
		select {
		case <-tick:
			for logType, entries := range o.batches {
				if len(entries) == 0 {
					continue
				}
				data, _ := json.Marshal(entries)
				o.postData(data, logType)
			}
			o.batches = make(map[LogType][]*logEntry)

		case log := <-o.queue:
			o.batches[log.LogType] = append(o.batches[log.LogType], &log)
		}
	}
}
