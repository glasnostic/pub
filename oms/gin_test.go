package oms_test

import (
	"testing"

	"github.com/glasnostic/pub/oms"
	"github.com/stretchr/testify/require"
)

func TestNewGinLog(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
		want *oms.GinLog
	}{
		{
			data: []byte("[GIN] 2019/08/15 - 02:02:09 | 200 |     485.408µs | 10.244.1.1 |   GET     /_/test-without-utc"),
			want: &oms.GinLog{HttpStatus: 200, Latency: 0.485408, Client: "10.244.1.1", Method: "GET", Path: "/_/test-without-utc"},
		}, {
			data: []byte(`[GIN] 2019/11/30 - 03:42:32 | 404 [0m|    3.607119ms | 74.125.209.18 |  [0m GET     /blog/image.jpg`),
			want: &oms.GinLog{HttpStatus: 404, Latency: 3.607119, Client: "74.125.209.18", Method: "GET", Path: "/blog/image.jpg"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := oms.NewGinLog(tc.data)
			require.NoError(t, err, "NewGinLog() error = %v", err)
			require.Equalf(t, tc.want, got, "NewGinLog() got = %v, want %v", got, tc.want)
		})
	}
}

func TestInvalidGinLog(t *testing.T) {
	testCases := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{
			data:    []byte("[GIN] testing: yoooooooooooooooooooooo"),
			wantErr: oms.ErrInvalidGinLog,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := oms.NewGinLog(tc.data)
			require.EqualErrorf(t, err, tc.wantErr.Error(), "NewGinLog() error = %v, wantErr %v", err, tc.wantErr)
		})
	}
}
