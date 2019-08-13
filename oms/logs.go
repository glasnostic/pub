package oms

import (
	"encoding/json"
	"strconv"
	"time"
)

const ginPattern = `\[GIN\]\s+\d{4}\/\d{2}\/\d{2}\s+-\s+\d{2}:\d{2}:\d{2}\s+\|([[:cntrl:]]?\[\d+;\d+m)?\s+(\d{3})\s+([[:cntrl:]]?\[0m)?\|\s+([\d\.]{1,13})(\p{L}?s)`

type logEntry struct {
	Msg     string   `json:"log"`
	Latency *float64 `json:"latency,omitempty"`
	Status  *int     `json:"http_status,omitempty"`
}

func (o *OmsLogger) writeHTTP(now time.Time, p []byte, httpStatus int, latency float64) (n int, err error) {
	l := logEntry{Msg: string(p), Latency: &latency, Status: &httpStatus}
	data, err := json.Marshal(l)
	if err != nil {
		return 0, err
	}
	return o.postData(now, data, o.LogTypes[1])
}

func (o *OmsLogger) writeLogs(now time.Time, p []byte) (n int, err error) {
	l := logEntry{Msg: string(p)}
	data, err := json.Marshal(l)
	if err != nil {
		return 0, err
	}
	// We don't want to block the running services by sending logs to OMS
	go o.postData(now, data, o.LogTypes[0])
	return len(p), nil
}

func parseFromGinLog(matches []string) (int, float64) {
	httpStatus := 200
	if hs, err := strconv.Atoi(matches[2]); err == nil {
		httpStatus = hs
	}

	latency := 0.0
	if l, err := strconv.ParseFloat(matches[3], 64); err == nil {
		latency = l
		// convert time unit to ms
		switch matches[3] {
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
