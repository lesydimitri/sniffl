package shared

import (
	"fmt"
	"io"

	"github.com/lesydimitri/sniffl/internal/errors"
	"github.com/lesydimitri/sniffl/internal/logging"
)

type ErrorHandler struct {
	logger *logging.Logger
	out    io.Writer
}

func NewErrorHandler(logger *logging.Logger, out io.Writer) *ErrorHandler {
	return &ErrorHandler{
		logger: logger,
		out:    out,
	}
}

func (eh *ErrorHandler) HandleNetworkError(operation, target string, err error) error {
	errorMsg := FormatError(operation, target, err)
	wrappedErr := errors.WrapNetworkError(errorMsg, err)
	eh.logger.Failure(operation+" failed", "target", target, "error", err)
	
	if eh.out != nil {
		if _, writeErr := fmt.Fprintf(eh.out, "[-] %s\n", errorMsg); writeErr != nil {
			eh.logger.Warn("Failed to write error output", "error", writeErr)
		}
	}
	
	return wrappedErr
}

func (eh *ErrorHandler) HandleTLSError(operation, target string, err error) error {
	errorMsg := FormatError(operation, target, err)
	wrappedErr := errors.WrapTLSError(errorMsg, err)
	eh.logger.Failure(operation+" failed", "target", target, "error", err)
	
	if eh.out != nil {
		if _, writeErr := fmt.Fprintf(eh.out, "[-] %s\n", errorMsg); writeErr != nil {
			eh.logger.Warn("Failed to write error output", "error", writeErr)
		}
	}
	
	return wrappedErr
}

// HandleValidationError handles validation errors with consistent logging
func (eh *ErrorHandler) HandleValidationError(message string, target string) error {
	err := errors.NewValidationError(message)
	eh.logger.Warn("Validation error", "target", target, "message", message)
	
	if eh.out != nil {
		if _, writeErr := fmt.Fprintf(eh.out, "[-] %s: %s (skipped)\n", message, target); writeErr != nil {
			eh.logger.Warn("Failed to write validation error output", "error", writeErr)
		}
	}
	
	return err
}

// HandleFileError handles file operation errors with consistent logging
func (eh *ErrorHandler) HandleFileError(operation, path string, err error) error {
	errorMsg := FormatError(operation, path, err)
	wrappedErr := errors.WrapFileError(errorMsg, err)
	eh.logger.Failure(operation+" failed", "path", path, "error", err)
	return wrappedErr
}

// LogSuccess logs successful operations consistently
func (eh *ErrorHandler) LogSuccess(operation, target string, details map[string]interface{}) {
	args := []interface{}{"target", target}
	for k, v := range details {
		args = append(args, k, v)
	}
	eh.logger.Success(operation+" completed successfully", args...)
}
