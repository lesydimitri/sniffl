package retry

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lesydimitri/sniffl/internal/errors"
	"github.com/lesydimitri/sniffl/internal/logging"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	if cfg.MaxAttempts != 3 {
		t.Errorf("Expected MaxAttempts to be 3, got %d", cfg.MaxAttempts)
	}
	
	if cfg.BaseDelay != time.Second {
		t.Errorf("Expected BaseDelay to be 1s, got %v", cfg.BaseDelay)
	}
	
	if cfg.MaxDelay != 30*time.Second {
		t.Errorf("Expected MaxDelay to be 30s, got %v", cfg.MaxDelay)
	}
	
	if cfg.Multiplier != 2.0 {
		t.Errorf("Expected Multiplier to be 2.0, got %f", cfg.Multiplier)
	}
	
	if !cfg.Jitter {
		t.Error("Expected Jitter to be true")
	}
}

func TestDo_Success(t *testing.T) {
	logger := logging.New("info", "text", nil)
	ctx := context.Background()
	config := DefaultConfig()
	
	callCount := 0
	operation := func() error {
		callCount++
		return nil // Success on first try
	}
	
	err := Do(ctx, config, logger, operation)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	
	if callCount != 1 {
		t.Errorf("Expected operation to be called once, got %d", callCount)
	}
}

func TestDo_SuccessAfterRetry(t *testing.T) {
	logger := logging.New("info", "text", nil)
	ctx := context.Background()
	config := Config{
		MaxAttempts: 3,
		BaseDelay:   time.Millisecond, // Very short delay for testing
		MaxDelay:    time.Millisecond * 10,
		Multiplier:  2.0,
		Jitter:      false, // Disable jitter for predictable testing
	}
	
	callCount := 0
	operation := func() error {
		callCount++
		if callCount < 3 {
			return errors.NewNetworkError("temporary failure")
		}
		return nil // Success on third try
	}
	
	err := Do(ctx, config, logger, operation)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	
	if callCount != 3 {
		t.Errorf("Expected operation to be called 3 times, got %d", callCount)
	}
}

func TestDo_MaxAttemptsExceeded(t *testing.T) {
	logger := logging.New("info", "text", nil)
	ctx := context.Background()
	config := Config{
		MaxAttempts: 2,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond * 10,
		Multiplier:  2.0,
		Jitter:      false,
	}
	
	callCount := 0
	operation := func() error {
		callCount++
		return errors.NewNetworkError("persistent failure")
	}
	
	err := Do(ctx, config, logger, operation)
	if err == nil {
		t.Error("Expected error after max attempts exceeded")
	}
	
	if callCount != 2 {
		t.Errorf("Expected operation to be called 2 times, got %d", callCount)
	}
	
	expectedMsg := "operation failed after 2 attempts"
	if err.Error()[:len(expectedMsg)] != expectedMsg {
		t.Errorf("Expected error message to start with '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestDo_NonRetryableError(t *testing.T) {
	logger := logging.New("info", "text", nil)
	ctx := context.Background()
	config := DefaultConfig()
	
	callCount := 0
	operation := func() error {
		callCount++
		return errors.NewValidationError("invalid input") // Non-retryable
	}
	
	err := Do(ctx, config, logger, operation)
	if err == nil {
		t.Error("Expected error for non-retryable operation")
	}
	
	if callCount != 1 {
		t.Errorf("Expected operation to be called once (no retry), got %d", callCount)
	}
}

func TestDo_ContextCancellation(t *testing.T) {
	logger := logging.New("info", "text", nil)
	ctx, cancel := context.WithCancel(context.Background())
	config := DefaultConfig()
	
	callCount := 0
	operation := func() error {
		callCount++
		if callCount == 1 {
			cancel() // Cancel context after first call
		}
		return errors.NewNetworkError("network error")
	}
	
	err := Do(ctx, config, logger, operation)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
	
	if callCount != 1 {
		t.Errorf("Expected operation to be called once before cancellation, got %d", callCount)
	}
}

func TestCalculateDelay(t *testing.T) {
	config := Config{
		BaseDelay:  time.Second,
		MaxDelay:   time.Second * 10,
		Multiplier: 2.0,
		Jitter:     false, // Disable jitter for predictable testing
	}
	
	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, time.Second},     // 1 * 2^0 = 1
		{2, time.Second * 2}, // 1 * 2^1 = 2
		{3, time.Second * 4}, // 1 * 2^2 = 4
		{4, time.Second * 8}, // 1 * 2^3 = 8
		{5, time.Second * 10}, // 1 * 2^4 = 16, but capped at MaxDelay (10)
	}
	
	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			delay := calculateDelay(config, tt.attempt)
			if delay != tt.expected {
				t.Errorf("Expected delay %v for attempt %d, got %v", tt.expected, tt.attempt, delay)
			}
		})
	}
}

func TestCalculateDelay_WithJitter(t *testing.T) {
	config := Config{
		BaseDelay:  time.Second,
		MaxDelay:   time.Second * 10,
		Multiplier: 2.0,
		Jitter:     true,
	}
	
	// With jitter enabled, delay should be within expected range
	delay := calculateDelay(config, 1)
	
	// Base delay is 1 second, jitter adds up to 10% (100ms)
	minExpected := time.Second
	maxExpected := time.Second + time.Millisecond*100
	
	if delay < minExpected || delay > maxExpected {
		t.Errorf("Expected delay between %v and %v, got %v", minExpected, maxExpected, delay)
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "validation error - not retryable",
			err:       errors.NewValidationError("invalid input"),
			retryable: false,
		},
		{
			name:      "config error - not retryable",
			err:       errors.NewConfigError("bad config"),
			retryable: false,
		},
		{
			name:      "network error - retryable",
			err:       errors.NewNetworkError("connection failed"),
			retryable: true,
		},
		{
			name:      "tls error - retryable",
			err:       errors.NewTLSError("handshake failed"),
			retryable: true,
		},
		{
			name:      "ct error - retryable",
			err:       errors.NewCTError("query failed"),
			retryable: true,
		},
		{
			name:      "unknown error - not retryable",
			err:       fmt.Errorf("unknown error"),
			retryable: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetryable(tt.err); got != tt.retryable {
				t.Errorf("isRetryable() = %v, want %v", got, tt.retryable)
			}
		})
	}
}

func TestWithRetry(t *testing.T) {
	logger := logging.New("info", "text", nil)
	ctx := context.Background()
	
	callCount := 0
	operation := func() error {
		callCount++
		if callCount < 2 {
			return errors.NewNetworkError("temporary failure")
		}
		return nil
	}
	
	err := WithRetry(ctx, logger, operation)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	
	if callCount != 2 {
		t.Errorf("Expected operation to be called 2 times, got %d", callCount)
	}
}
