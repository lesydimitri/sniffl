package errors

import (
	"fmt"
	"net"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	// ValidationError represents input validation failures
	ValidationError ErrorType = "validation"
	// NetworkError represents network-related failures
	NetworkError ErrorType = "network"
	// TLSError represents TLS handshake or certificate errors
	TLSError ErrorType = "tls"
	// FileError represents file system operation errors
	FileError ErrorType = "file"
	// ConfigError represents configuration-related errors
	ConfigError ErrorType = "config"
	// CTError represents Certificate Transparency query errors
	CTError ErrorType = "ct"
)

// SnifflError is the base error type for all sniffl errors
type SnifflError struct {
	Type    ErrorType
	Message string
	Cause   error
	Context map[string]interface{}
}

func (e *SnifflError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s error: %s: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s error: %s", e.Type, e.Message)
}

func (e *SnifflError) Unwrap() error {
	return e.Cause
}

// WithContext adds context information to the error
func (e *SnifflError) WithContext(key string, value interface{}) *SnifflError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// New creates a new SnifflError
func New(errorType ErrorType, message string) *SnifflError {
	return &SnifflError{
		Type:    errorType,
		Message: message,
	}
}

// Wrap creates a new SnifflError that wraps another error
func Wrap(errorType ErrorType, message string, cause error) *SnifflError {
	return &SnifflError{
		Type:    errorType,
		Message: message,
		Cause:   cause,
	}
}

// Convenience constructors for common error types

func NewValidationError(message string) *SnifflError {
	return New(ValidationError, message)
}

func WrapValidationError(message string, cause error) *SnifflError {
	return Wrap(ValidationError, message, cause)
}

func NewNetworkError(message string) *SnifflError {
	return New(NetworkError, message)
}

func WrapNetworkError(message string, cause error) *SnifflError {
	return Wrap(NetworkError, message, cause)
}

func NewTLSError(message string) *SnifflError {
	return New(TLSError, message)
}

func WrapTLSError(message string, cause error) *SnifflError {
	return Wrap(TLSError, message, cause)
}

func NewFileError(message string) *SnifflError {
	return New(FileError, message)
}

func WrapFileError(message string, cause error) *SnifflError {
	return Wrap(FileError, message, cause)
}

func NewConfigError(message string) *SnifflError {
	return New(ConfigError, message)
}

func WrapConfigError(message string, cause error) *SnifflError {
	return Wrap(ConfigError, message, cause)
}

func NewCTError(message string) *SnifflError {
	return New(CTError, message)
}

func WrapCTError(message string, cause error) *SnifflError {
	return Wrap(CTError, message, cause)
}

// IsNetworkTimeout checks if an error is a network timeout
func IsNetworkTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// IsConnectionRefused checks if an error is a connection refused error
func IsConnectionRefused(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		return opErr.Op == "dial"
	}
	return false
}
