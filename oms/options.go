package oms

type option func(l *logEntry)

func WithHttpStatus(status int) option {
	return func(l *logEntry) {
		l.Status = &status
	}
}

func WithLatency(latency float64) option {
	return func(l *logEntry) {
		l.Latency = &latency
	}
}

func WithHttpMethod(method string) option {
	return func(l *logEntry) {
		l.Method = &method
	}
}

func WithHttpPath(path string) option {
	return func(l *logEntry) {
		l.Path = &path
	}
}
