package oms

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
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

func (o *OmsLogger) run() {
	tick := time.Tick(updatePeriod)
	for {
		select {
		case <-tick:
			for logType, entries := range o.batches {
				if len(entries) == 0 {
					continue
				}
				if err := o.sendLogs(logType, entries); err != nil {
					log.Println("[OMS] Failed to send log messages to Azure:", err)
					continue
				}
				o.batches[logType] = make([]*logEntry, 0, len(entries))
			}
		case log := <-o.queue:
			o.batches[log.LogType] = append(o.batches[log.LogType], &log)
		}
	}
}

// sendLogs should be only called by run()
func (o *OmsLogger) sendLogs(logType LogType, entries []*logEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()

	req, err := o.newPostRequest(ctx, data, logType)
	if err != nil {
		return err
	}

	res, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	_, _ = ioutil.ReadAll(res.Body)
	return nil
}
