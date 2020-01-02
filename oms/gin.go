package oms

import (
	"fmt"
	"regexp"
	"strconv"
)

const (
	ginPatternPrefix    = `\[GIN\]`
	ginPatternTimestamp = `\s+\d{4}\/\d{2}\/\d{2}\s+-\s+\d{2}:\d{2}:\d{2}\s+`
	ginPatternStatus    = `([[:cntrl:]]?\[\d+;\d+m)?\s+(\d{3})\s+([[:cntrl:]]?\[0m)?`
	ginPatternLatency   = `\s+([\d\.]{1,13})(\p{L}?s)`
)

var (
	ginPattern    = fmt.Sprintf(`%s%s\|%s\|%s`, ginPatternPrefix, ginPatternTimestamp, ginPatternStatus, ginPatternLatency)
	ginLogMatcher = regexp.MustCompile(ginPattern)
)

type GinLog struct {
	HttpStatus int
	Latency    float64
}

func NewGinLog(b []byte) (*GinLog, error) {
	matches := ginLogMatcher.FindStringSubmatch(string(b))
	if len(matches) <= 0 {
		return nil, ErrInvalidGinLog
	}
	return newGinLog(matches), nil
}

func newGinLog(matches []string) *GinLog {
	return &GinLog{
		HttpStatus: parseHttpStatus(matches[2]),
		Latency:    parseLatency(matches[4], matches[5]),
	}
}

func parseHttpStatus(s string) int {
	httpStatus := 200
	if hs, err := strconv.Atoi(s); err == nil {
		httpStatus = hs
	}
	return httpStatus
}

func parseLatency(value, unit string) float64 {
	var latency, factor float64
	if l, err := strconv.ParseFloat(value, 64); err == nil {
		latency = l
	}
	switch unit {
	case "ns":
		factor = 1.0 / 1000 / 1000
	case "µs":
		factor = 1.0 / 1000
	case "s":
		factor = 1000
	default:
		factor = 1
	}
	return latency * factor
}
