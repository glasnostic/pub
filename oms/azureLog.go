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
	"strconv"
	"strings"
	"time"
)

const ginPattern = `\[GIN\]\s+\d{4}\/\d{2}\/\d{2}\s+-\s+\d{2}:\d{2}:\d{2}\s+\|([[:cntrl:]]?\[\d+;\d+m)?\s+(\d{3})\s+[[:cntrl:]]?\[0m\|\s+([\d\.]{1,13})(\p{L}?s)`

type OmsLogger struct {
	CustomerId string
	SharedKey  string
	LogTypes   []string
	Matcher    *regexp.Regexp
}

func NewOmsLogger(customerId, sharedKey, logType string) *OmsLogger {
	return &OmsLogger{
		CustomerId: customerId,
		SharedKey:  sharedKey,
		LogTypes:   []string{fmt.Sprintf("%s_LOGS", logType), fmt.Sprintf("%s_HTTP", logType)},
		Matcher:    regexp.MustCompile(ginPattern),
	}
}

type httpLogEntry struct {
	Msg     string  `json:"log"`
	Latency float64 `json:"latency"`
	Status  int     `json:"http_status"`
}

type logEntry struct {
	Msg string `json:"log"`
}

func (o *OmsLogger) Write(p []byte) (n int, err error) {
	founds := o.Matcher.FindStringSubmatch(string(p))
	if len(founds) > 0 {
		httpStatus := 200
		latency := 0.0
		if hs, err := strconv.Atoi(founds[2]); err == nil {
			httpStatus = hs
		}
		if l, err := strconv.ParseFloat(founds[3], 64); err == nil {
			latency = l
			// convert time unit to ms
			switch founds[3] {
			case "ns":
				latency = latency / 1000 / 1000
			case "µs":
				latency = latency / 1000
			case "s":
				latency = latency * 1000
			}
		}
		l := httpLogEntry{Msg: string(p), Latency: latency, Status: httpStatus}
		data, _ := json.Marshal(l)
		return postData(o.CustomerId, o.SharedKey, data, o.LogTypes[1])
	}
	l := logEntry{Msg: string(p)}
	data, _ := json.Marshal(l)
	go postData(o.CustomerId, o.SharedKey, data, o.LogTypes[0])
	return len(p), nil
}

func buildSignature(id string, key string, date string, length int, method string, contentType string, resource string) string {
	xHeaders := fmt.Sprintf("x-ms-date:%s", date)
	stringToHash := fmt.Sprintf("%s\n%d\n%s\n%s\n%s", method, length, contentType, xHeaders, resource)
	bytesToHash := []byte(stringToHash)
	decodeKey, _ := base64.StdEncoding.DecodeString(key)
	mac := hmac.New(sha256.New, decodeKey)
	mac.Write(bytesToHash)
	encodedHash := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	authorization := fmt.Sprintf("SharedKey %s:%s", id, encodedHash)
	return authorization
}

func postData(customerId string, sharedKey string, body []byte, logType string) (n int, err error) {
	method := "POST"
	contentType := "application/json"
	resource := "/api/logs"
	contentLength := len(body)

	rfc1123date := strings.Replace(time.Now().UTC().Format(time.RFC1123), "UTC", "GMT", 1)

	signature := buildSignature(customerId, sharedKey, rfc1123date, contentLength, method, contentType, resource)

	uri := fmt.Sprintf("https://%s.ods.opinsights.azure.com%s?api-version=2016-04-01", customerId, resource)

	client := &http.Client{}
	req, err := http.NewRequest(method, uri, bytes.NewBuffer(body))

	req.Header.Add("content-type", contentType)
	req.Header.Add("Authorization", signature)
	req.Header.Add("Log-Type", logType)
	req.Header.Add("x-ms-date", rfc1123date)

	_, err = client.Do(req)
	if err != nil {
		return 0, err
	}
	return contentLength, nil
}
