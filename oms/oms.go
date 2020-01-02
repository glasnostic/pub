package oms

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	// bufferSize is for creating a buffered channel that could
	// prevent blocking the log writer when we are trying to send
	// logs to Azure.
	// Thinking of how many logging messages we will receive
	// in a time duration "updateTimeout".
	bufferSize = 1024
	// updateTimeout is for preventing sending logs to Azure takes too
	// much time and eventually blocks the log writer.
	updateTimeout = time.Second * 10

	updatePeriod = time.Minute
)

type OmsLogger struct {
	CustomerId    string
	SharedKey     string
	LogTypes      []LogType
	GinLogMatcher *regexp.Regexp

	client  *http.Client
	queue   chan logEntry
	batches map[LogType][]*logEntry
}

func NewOmsLogger(customerId, sharedKey, logTypePrefix LogType) *OmsLogger {
	logger := &OmsLogger{
		CustomerId:    customerId,
		SharedKey:     sharedKey,
		LogTypes:      []LogType{fmt.Sprintf("%s_LOGS", logTypePrefix), fmt.Sprintf("%s_HTTP", logTypePrefix)},
		GinLogMatcher: regexp.MustCompile(ginPattern),

		client:  &http.Client{},
		queue:   make(chan logEntry, bufferSize),
		batches: make(map[LogType][]*logEntry),
	}
	go logger.run()
	return logger
}

func (o *OmsLogger) Write(p []byte) (n int, err error) {
	ginLog, err := NewGinLog(p)
	if err == nil {
		return o.writeLogs(p, o.LogTypes[1], WithHttpStatus(ginLog.HttpStatus), WithLatency(ginLog.Latency))
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

func (o *OmsLogger) doPostRequest(ctx context.Context, body []byte, logType LogType) error {
	req, err := o.newPostRequest(body, logType)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	if _, err := o.client.Do(req); err != nil {
		return err
	}
	return nil
}

func (o *OmsLogger) newPostRequest(body []byte, logType LogType) (*http.Request, error) {
	const contentType = "application/json"
	const resource = "/api/logs"
	contentLength := len(body)

	// Azure doesn't support UTC, so we need to change it to GMT
	rfc1123date := strings.Replace(time.Now().UTC().Format(time.RFC1123), "UTC", "GMT", 1)
	// Build signature
	signature := o.buildSignature(rfc1123date, contentLength, http.MethodPost, contentType, resource)
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
	return req, nil
}

func (o *OmsLogger) run() {
	tick := time.Tick(updatePeriod)
	for {
		select {
		case <-tick:
			for logType, entries := range o.batches {
				o.sendLogs(logType, entries)
			}
		case log := <-o.queue:
			o.batches[log.LogType] = append(o.batches[log.LogType], &log)
		}
	}
}

// sendLogs should be only called by run()
func (o *OmsLogger) sendLogs(logType LogType, entries []*logEntry) {
	if len(entries) == 0 {
		return
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	if err := o.doPostRequest(ctx, data, logType); err != nil {
		log.Println("[OMS] Failed to send log messages to Azure:", err)
	}
	o.batches[logType] = make([]*logEntry, 0, len(entries))
}
