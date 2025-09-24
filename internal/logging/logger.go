// Package logging provides structured logging for sniffl
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Logger wraps slog.Logger with additional convenience methods
type Logger struct {
	*slog.Logger
	level slog.Level
}

// New creates a new structured logger
func New(level, format string, output io.Writer) *Logger {
	if output == nil {
		output = os.Stderr
	}
	
	logLevel := parseLevel(level)
	
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	
	switch strings.ToLower(format) {
	case "json":
		handler = slog.NewJSONHandler(output, opts)
	default:
		handler = slog.NewTextHandler(output, opts)
	}
	
	return &Logger{
		Logger: slog.New(handler),
		level:  logLevel,
	}
}

// parseLevel converts string level to slog.Level
func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// IsDebugEnabled returns true if debug logging is enabled
func (l *Logger) IsDebugEnabled() bool {
	return l.level <= slog.LevelDebug
}

// Progress logs a progress message (info level with progress context)
func (l *Logger) Progress(msg string, args ...any) {
	l.Info(msg, append([]any{"type", "progress"}, args...)...)
}

// Success logs a success message (info level with success context)
func (l *Logger) Success(msg string, args ...any) {
	l.Info(msg, append([]any{"type", "success"}, args...)...)
}

// Failure logs a failure message (error level with failure context)
func (l *Logger) Failure(msg string, args ...any) {
	l.Error(msg, append([]any{"type", "failure"}, args...)...)
}

// Network logs a network-related message
func (l *Logger) Network(msg string, args ...any) {
	l.Debug(msg, append([]any{"category", "network"}, args...)...)
}

// TLS logs a TLS-related message
func (l *Logger) TLS(msg string, args ...any) {
	l.Debug(msg, append([]any{"category", "tls"}, args...)...)
}

// CT logs a Certificate Transparency related message
func (l *Logger) CT(msg string, args ...any) {
	l.Debug(msg, append([]any{"category", "ct"}, args...)...)
}

// WithTarget returns a logger with target context
func (l *Logger) WithTarget(target string) *Logger {
	return &Logger{
		Logger: l.With("target", target),
		level:  l.level,
	}
}

// WithProtocol returns a logger with protocol context
func (l *Logger) WithProtocol(protocol string) *Logger {
	return &Logger{
		Logger: l.With("protocol", protocol),
		level:  l.level,
	}
}
