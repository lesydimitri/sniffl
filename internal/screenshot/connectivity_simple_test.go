package screenshot

import (
	"context"
	"testing"
)

func TestConnectivityChecker_CheckBatch(t *testing.T) {
	t.Skip("Skipping connectivity test to avoid real network connections")
}

func TestConnectivityChecker_EmptyTargets(t *testing.T) {
	checker := NewConnectivityChecker()
	ctx := context.Background()
	
	results := checker.CheckBatch(ctx, []ScreenshotTarget{})
	
	if len(results) != 0 {
		t.Errorf("Expected 0 results for empty targets, got %d", len(results))
	}
}

func TestConnectivityChecker_ContextCancellation(t *testing.T) {
	checker := NewConnectivityChecker()
	
	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	
	targets := []ScreenshotTarget{
		{URL: "http://example.com:80", Host: "example.com", Port: 80, Protocol: "http"},
	}
	
	results := checker.CheckBatch(ctx, targets)
	
	// Should still return results (goroutines might complete before cancellation)
	if len(results) > 1 {
		t.Errorf("Expected at most 1 result, got %d", len(results))
	}
}

func TestFilterReachableTargets_WithMockServer(t *testing.T) {
	t.Skip("Skipping connectivity test to avoid real network connections")
}

func TestIsLocalNetwork_Function(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{"localhost_ip", "127.0.0.1", true},
		{"private_ip_10", "10.0.0.1", true},
		{"private_ip_192", "192.168.1.1", true},
		{"private_ip_172", "172.16.0.1", true},
		{"public_ip", "8.8.8.8", false},
		{"hostname", "example.com", false},
		{"ipv6_localhost", "::1", true},
		{"empty_string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLocalNetwork(tt.host)
			if result != tt.expected {
				t.Errorf("isLocalNetwork(%q) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestConnectivityChecker_SingleTarget(t *testing.T) {
	t.Skip("Skipping connectivity test to avoid real network connections")
}

// Benchmark tests
func BenchmarkIsLocalNetwork(b *testing.B) {
	testHosts := []string{
		"127.0.0.1",
		"192.168.1.1",
		"8.8.8.8",
		"::1",
		"example.com",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host := testHosts[i%len(testHosts)]
		_ = isLocalNetwork(host)
	}
}

func BenchmarkConnectivityChecker_CheckBatch(b *testing.B) {
	b.Skip("Skipping benchmark that makes real network connections")
}
