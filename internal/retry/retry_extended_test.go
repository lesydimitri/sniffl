package retry

import (
	"context"
	"testing"
	"time"

	"github.com/lesydimitri/sniffl/internal/errors"
	"github.com/lesydimitri/sniffl/internal/logging"
)

func TestConfig_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name: "zero_max_attempts",
			config: Config{
				MaxAttempts: 0,
				BaseDelay:   time.Second,
				MaxDelay:    30 * time.Second,
				Multiplier:  2.0,
				Jitter:      true,
			},
			valid: false,
		},
		{
			name: "negative_base_delay",
			config: Config{
				MaxAttempts: 3,
				BaseDelay:   -time.Second,
				MaxDelay:    30 * time.Second,
				Multiplier:  2.0,
				Jitter:      true,
			},
			valid: false,
		},
		{
			name: "max_delay_less_than_base",
			config: Config{
				MaxAttempts: 3,
				BaseDelay:   30 * time.Second,
				MaxDelay:    time.Second,
				Multiplier:  2.0,
				Jitter:      true,
			},
			valid: false,
		},
		{
			name: "valid_config",
			config: Config{
				MaxAttempts: 5,
				BaseDelay:   500 * time.Millisecond,
				MaxDelay:    10 * time.Second,
				Multiplier:  1.5,
				Jitter:      false,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := validateConfig(tt.config)
			if isValid != tt.valid {
				t.Errorf("Expected config validation %v, got %v", tt.valid, isValid)
			}
		})
	}
}

func TestCalculateDelay_EdgeCases(t *testing.T) {
	config := Config{
		MaxAttempts: 10,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Second,
		Multiplier:  10.0, // High multiplier to test max delay capping
		Jitter:      false,
	}

	// Test that delay is capped at MaxDelay
	delay := calculateDelay(config, 10) // High attempt number
	if delay > config.MaxDelay {
		t.Errorf("Delay %v exceeds MaxDelay %v", delay, config.MaxDelay)
	}

	// Test with jitter enabled
	config.Jitter = true
	delay1 := calculateDelay(config, 3)
	delay2 := calculateDelay(config, 3)
	
	// With jitter, delays for same attempt might be different
	// But both should be reasonable
	if delay1 < 0 || delay2 < 0 {
		t.Error("Delay should not be negative")
	}
	
	if delay1 > config.MaxDelay || delay2 > config.MaxDelay {
		t.Error("Delay should not exceed MaxDelay")
	}
}

func TestDo_ZeroMaxAttempts(t *testing.T) {
	config := Config{
		MaxAttempts: 0,
		BaseDelay:   time.Second,
		MaxDelay:    30 * time.Second,
		Multiplier:  2.0,
		Jitter:      true,
	}

	logger := logging.New("info", "text", &testWriter{})
	
	callCount := 0
	operation := func() error {
		callCount++
		return errors.NewNetworkError("test error")
	}

	ctx := context.Background()
	err := Do(ctx, config, logger, operation)

	// Should not call operation with zero max attempts
	if callCount != 0 {
		t.Errorf("Expected 0 operation calls, got %d", callCount)
	}

	// Should return an error indicating no attempts
	if err == nil {
		t.Error("Expected error for zero max attempts")
	}
}

func TestWithRetry_ContextTimeout(t *testing.T) {
	// Create a context with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	logger := logging.New("info", "text", &testWriter{})

	callCount := 0
	operation := func() error {
		callCount++
		time.Sleep(50 * time.Millisecond) // Simulate slow operation
		return errors.NewNetworkError("test error")
	}

	err := WithRetry(ctx, logger, operation)

	// Should fail due to context timeout
	if err == nil {
		t.Error("Expected context timeout error")
	}

	// Should have made at least one call before timeout
	if callCount == 0 {
		t.Error("Expected at least one operation call before timeout")
	}
}

// Helper functions
func validateConfig(config Config) bool {
	if config.MaxAttempts <= 0 {
		return false
	}
	if config.BaseDelay < 0 {
		return false
	}
	if config.MaxDelay < config.BaseDelay {
		return false
	}
	return true
}

type testWriter struct{}

func (tw *testWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

// Benchmark tests
func BenchmarkCalculateDelay(b *testing.B) {
	config := DefaultConfig()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calculateDelay(config, i%10+1)
	}
}

func BenchmarkIsRetryable(b *testing.B) {
	networkErr := errors.NewNetworkError("test")
	validationErr := errors.NewValidationError("test")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			_ = isRetryable(networkErr)
		} else {
			_ = isRetryable(validationErr)
		}
	}
}
