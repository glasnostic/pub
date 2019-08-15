package oms

import (
	"strconv"
	"time"
)

const ginPattern = `\[GIN\]\s+\d{4}\/\d{2}\/\d{2}\s+-\s+\d{2}:\d{2}:\d{2}\s+\|([[:cntrl:]]?\[\d+;\d+m)?\s+(\d{3})\s+([[:cntrl:]]?\[0m)?\|\s+([\d\.]{1,13})(\p{L}?s)`

type LogType = string

type logEntry struct {
	Msg           string    `json:"log"`
	TimeGenerated time.Time `json:"time_generated"`
	Latency       *float64  `json:"latency,omitempty"`
	Status        *int      `json:"http_status,omitempty"`
	LogType       LogType   `json:"-"`
}

func (o *OmsLogger) writeLogs(p []byte, logType LogType, options ...option) (n int, err error) {
	l := logEntry{Msg: string(p), TimeGenerated: time.Now(), LogType: logType}
	for _, setter := range options {
		setter(&l)
	}
	o.queue <- l
	return len(p), nil
}

func parseFromGinLog(matches []string) (int, float64) {
	httpStatus := 200
	if hs, err := strconv.Atoi(matches[2]); err == nil {
		httpStatus = hs
	}

	latency := 0.0
	if l, err := strconv.ParseFloat(matches[4], 64); err == nil {
		latency = l
		// convert time unit to ms
		switch matches[5] {
		case "ns":
			latency = latency / 1000 / 1000
		case "µs":
			latency = latency / 1000
		case "s":
			latency = latency * 1000
		}
	}

	return httpStatus, latency
}
