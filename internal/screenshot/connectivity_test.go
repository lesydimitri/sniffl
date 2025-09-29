package screenshot

import (
"context"
"testing"
)
// MockConnectivityChecker for testing
type MockConnectivityChecker struct {
	reachableTargets map[ScreenshotTarget]bool
}

// NewMockConnectivityChecker creates a new mock connectivity checker
func NewMockConnectivityChecker(reachableTargets map[ScreenshotTarget]bool) *MockConnectivityChecker {
	return &MockConnectivityChecker{
		reachableTargets: reachableTargets,
	}
}

// CheckBatch returns predetermined connectivity results for testing
func (m *MockConnectivityChecker) CheckBatch(ctx context.Context, targets []ScreenshotTarget) map[ScreenshotTarget]bool {
	results := make(map[ScreenshotTarget]bool)
	for _, target := range targets {
		if reachable, exists := m.reachableTargets[target]; exists {
			results[target] = reachable
		} else {
			results[target] = false // Default to unreachable
		}
	}
	return results
}

func TestFilterReachableTargets(t *testing.T) {
	// Define test targets
	targets := []ScreenshotTarget{
		{
			Host:     "127.0.0.1",
			Port:     80,
			Protocol: "http",
			URL:      "http://127.0.0.1:80",
		},
		{
			Host:     "192.0.2.1", // TEST-NET-1, should be unreachable
			Port:     443,
			Protocol: "https",
			URL:      "https://192.0.2.1:443",
		},
		{
			Host:     "example.com",
			Port:     80,
			Protocol: "http",
			URL:      "http://example.com:80",
		},
	}

	// Test case 1: Mixed reachable/unreachable
	t.Run("Mixed reachability", func(t *testing.T) {
		mockResults := map[ScreenshotTarget]bool{
			targets[0]: true,  // localhost:80 reachable
			targets[1]: false, // test-net:443 unreachable
			targets[2]: true,  // example.com:80 reachable
		}

		mockChecker := NewMockConnectivityChecker(mockResults)
		reachable := FilterReachableTargetsWithChecker(context.Background(), targets, mockChecker)

		if len(reachable) != 2 {
			t.Errorf("Expected 2 reachable targets, got %d", len(reachable))
		}

		// Verify correct targets are reachable
		expectedHosts := map[string]bool{"127.0.0.1": true, "example.com": true}
		for _, target := range reachable {
			if !expectedHosts[target.Host] {
				t.Errorf("Unexpected reachable target: %s", target.Host)
			}
		}
	})

	// Test case 2: All unreachable
	t.Run("All unreachable", func(t *testing.T) {
		mockResults := map[ScreenshotTarget]bool{
			targets[0]: false,
			targets[1]: false,
			targets[2]: false,
		}

		mockChecker := NewMockConnectivityChecker(mockResults)
		reachable := FilterReachableTargetsWithChecker(context.Background(), targets, mockChecker)

		if len(reachable) != 0 {
			t.Errorf("Expected 0 reachable targets, got %d", len(reachable))
		}
	})

	// Test case 3: All reachable
	t.Run("All reachable", func(t *testing.T) {
		mockResults := map[ScreenshotTarget]bool{
			targets[0]: true,
			targets[1]: true,
			targets[2]: true,
		}

		mockChecker := NewMockConnectivityChecker(mockResults)
		reachable := FilterReachableTargetsWithChecker(context.Background(), targets, mockChecker)

		if len(reachable) != 3 {
			t.Errorf("Expected 3 reachable targets, got %d", len(reachable))
		}
	})

	// Test case 4: Empty targets
	t.Run("Empty targets", func(t *testing.T) {
		mockResults := map[ScreenshotTarget]bool{}

		mockChecker := NewMockConnectivityChecker(mockResults)
		reachable := FilterReachableTargetsWithChecker(context.Background(), []ScreenshotTarget{}, mockChecker)

		if len(reachable) != 0 {
			t.Errorf("Expected 0 reachable targets for empty input, got %d", len(reachable))
		}
	})
}
