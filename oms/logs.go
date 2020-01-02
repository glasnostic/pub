package oms

import (
	"time"
)

type LogType = string

type logEntry struct {
	Msg           string   `json:"log"`
	TimeGenerated string   `json:"time_generated"`
	Latency       *float64 `json:"latency,omitempty"`
	Status        *int     `json:"http_status,omitempty"`
	Method        *string  `json:"http_method,omitempty"`
	Path          *string  `jsno:"http_path,omitempty"`
	LogType       LogType  `json:"-"`
}

func (o *OmsLogger) writeLogs(p []byte, logType LogType, options ...option) (n int, err error) {
	// By default, time.Time MarshalJSON use RFC3339Nano format and Azure expect
	// the format to be the ISO 8601 format YYYY-MM-DDThh:mm:ssZ, so we have to
	// format this `time_generated` field by ourselves.
	now := time.Now().UTC().Format(time.RFC3339)
	l := logEntry{Msg: string(p), TimeGenerated: now, LogType: logType}
	for _, setter := range options {
		setter(&l)
	}
	o.queue <- l
	return len(p), nil
}
