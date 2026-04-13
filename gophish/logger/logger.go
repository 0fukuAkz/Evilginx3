package logger

import (
	"fmt"
	"io"
	"os"
	"strings"

	elog "github.com/kgretzky/evilginx2/log"
)

// Fields is a map of key-value pairs for structured logging.
type Fields map[string]interface{}

// Config represents configuration details for logging.
type Config struct {
	Filename string `json:"filename"`
	Level    string `json:"level"`
}

// gormLogger satisfies GORM's logger interface (Print(...interface{})).
type gormLogger struct{}

func (g *gormLogger) Print(v ...interface{}) {
	elog.Debug(fmt.Sprint(v...))
}

// Logger is exported for use with GORM's SetLogger.
var Logger = &gormLogger{}

// Setup is kept for configuration compatibility but is a no-op
// since all output now flows through the evilginx3 logger.
func Setup(config *Config) error {
	return nil
}

func formatFields(fields Fields) string {
	if len(fields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(fields))
	for k, v := range fields {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return "[" + strings.Join(parts, ", ") + "] "
}

// Entry holds fields for a single structured log call.
type Entry struct {
	fields Fields
}

func (e *Entry) Debug(args ...interface{}) {
	elog.Debug("%s%s", formatFields(e.fields), fmt.Sprint(args...))
}

func (e *Entry) Debugf(format string, args ...interface{}) {
	elog.Debug("%s%s", formatFields(e.fields), fmt.Sprintf(format, args...))
}

func (e *Entry) Info(args ...interface{}) {
	elog.Info("%s%s", formatFields(e.fields), fmt.Sprint(args...))
}

func (e *Entry) Infof(format string, args ...interface{}) {
	elog.Info("%s%s", formatFields(e.fields), fmt.Sprintf(format, args...))
}

func (e *Entry) Warn(args ...interface{}) {
	elog.Warning("%s%s", formatFields(e.fields), fmt.Sprint(args...))
}

func (e *Entry) Warnf(format string, args ...interface{}) {
	elog.Warning("%s%s", formatFields(e.fields), fmt.Sprintf(format, args...))
}

func (e *Entry) Error(args ...interface{}) {
	elog.Error("%s%s", formatFields(e.fields), fmt.Sprint(args...))
}

func (e *Entry) Errorf(format string, args ...interface{}) {
	elog.Error("%s%s", formatFields(e.fields), fmt.Sprintf(format, args...))
}

func (e *Entry) Fatal(args ...interface{}) {
	elog.Fatal("%s%s", formatFields(e.fields), fmt.Sprint(args...))
	os.Exit(1)
}

func (e *Entry) Fatalf(format string, args ...interface{}) {
	elog.Fatal("%s%s", formatFields(e.fields), fmt.Sprintf(format, args...))
	os.Exit(1)
}

// WithFields returns a new Entry with the provided fields.
func WithFields(fields Fields) *Entry {
	return &Entry{fields: fields}
}

// Debug logs a debug message.
func Debug(args ...interface{}) {
	elog.Debug("%s", fmt.Sprint(args...))
}

// Debugf logs a formatted debug message.
func Debugf(format string, args ...interface{}) {
	elog.Debug(format, args...)
}

// Info logs an informational message.
func Info(args ...interface{}) {
	elog.Info("%s", fmt.Sprint(args...))
}

// Infof logs a formatted informational message.
func Infof(format string, args ...interface{}) {
	elog.Info(format, args...)
}

// Warn logs a warning message.
func Warn(args ...interface{}) {
	elog.Warning("%s", fmt.Sprint(args...))
}

// Warnf logs a formatted warning message.
func Warnf(format string, args ...interface{}) {
	elog.Warning(format, args...)
}

// Error logs an error message.
func Error(args ...interface{}) {
	elog.Error("%s", fmt.Sprint(args...))
}

// Errorf logs a formatted error message.
func Errorf(format string, args ...interface{}) {
	elog.Error(format, args...)
}

// Fatal logs a fatal error message and exits.
func Fatal(args ...interface{}) {
	elog.Fatal("%s", fmt.Sprint(args...))
	os.Exit(1)
}

// Fatalf logs a formatted fatal error message and exits.
func Fatalf(format string, args ...interface{}) {
	elog.Fatal(format, args...)
	os.Exit(1)
}

// Writer returns a PipeWriter that writes through the evilginx3 logger.
func Writer() *io.PipeWriter {
	r, w := io.Pipe()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				elog.Info("%s", strings.TrimSpace(string(buf[:n])))
			}
			if err != nil {
				break
			}
		}
	}()
	return w
}
