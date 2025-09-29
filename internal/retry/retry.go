// Package retry provides retry logic with exponential backoff
package retry

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/lesydimitri/sniffl/internal/errors"
	"github.com/lesydimitri/sniffl/internal/logging"
)

// Config holds retry configuration
type Config struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	Multiplier  float64
	Jitter      bool
}

// DefaultConfig returns sensible retry defaults
func DefaultConfig() Config {
	return Config{
		MaxAttempts: 3,
		BaseDelay:   time.Second,
		MaxDelay:    30 * time.Second,
		Multiplier:  2.0,
		Jitter:      true,
	}
}

// Operation represents a retryable operation
type Operation func() error

// Do executes an operation with retry logic
func Do(ctx context.Context, config Config, logger *logging.Logger, operation Operation) error {
	var lastErr error

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		// Check if context is cancelled
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err := operation()
		if err == nil {
			if attempt > 1 {
				logger.Success("Operation succeeded after retry",
					"attempt", attempt,
					"total_attempts", config.MaxAttempts)
			}
			return nil
		}

		lastErr = err

		// Don't retry validation errors or other non-retryable errors
		if !isRetryable(err) {
			logger.Debug("Error is not retryable, giving up",
				"error", err,
				"attempt", attempt)
			return err
		}

		// Don't sleep after the last attempt
		if attempt == config.MaxAttempts {
			break
		}

		delay := calculateDelay(config, attempt)
		logger.Debug("Operation failed, retrying",
			"error", err,
			"attempt", attempt,
			"max_attempts", config.MaxAttempts,
			"delay", delay)

		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	logger.Failure("Operation failed after all retry attempts",
		"error", lastErr,
		"attempts", config.MaxAttempts)

	return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

// calculateDelay calculates the delay for the next retry attempt with jitter
// It implements exponential backoff with jitter to prevent thundering herd problems
func calculateDelay(config Config, attempt int) time.Duration {
	// Calculate exponential backoff
	delay := float64(config.BaseDelay) * math.Pow(config.Multiplier, float64(attempt-1))

	// Apply maximum delay limit
	if delay > float64(config.MaxDelay) {
		delay = float64(config.MaxDelay)
	}

	// Add jitter to prevent thundering herd (up to 10% randomization)
	if config.Jitter {
		jitterRange := big.NewInt(int64(delay * 0.1))
		if jitterRange.Int64() > 0 {
			jitter, err := rand.Int(rand.Reader, jitterRange)
			if err == nil {
				delay += float64(jitter.Int64())
			}
			// If random generation fails, add a small fixed jitter as fallback
			// to still provide some randomization and prevent thundering herd
			if err != nil {
				delay += delay * 0.05 // 5% fixed jitter as fallback
			}
		}
	}

	return time.Duration(delay)
}

// isRetryable determines if an error should be retried based on its type
// Network errors, TLS errors, and CT errors are retryable, while validation
// and configuration errors are not
func isRetryable(err error) bool {
	// Don't retry validation errors
	if snifflErr, ok := err.(*errors.SnifflError); ok {
		switch snifflErr.Type {
		case errors.ValidationError, errors.ConfigError:
			return false
		case errors.NetworkError, errors.TLSError, errors.CTError:
			return true
		default:
			return false
		}
	}

	// Check for specific network errors that are worth retrying
	if errors.IsNetworkTimeout(err) || errors.IsConnectionRefused(err) {
		return true
	}

	// Default to not retrying unknown errors (conservative approach)
	return false
}

// WithRetry is a convenience function that uses default config
func WithRetry(ctx context.Context, logger *logging.Logger, operation Operation) error {
	return Do(ctx, DefaultConfig(), logger, operation)
}
