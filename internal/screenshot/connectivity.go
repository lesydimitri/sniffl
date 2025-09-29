package screenshot

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// ConnectivityCheckerInterface defines the contract for connectivity checkers
// This allows for dependency injection and testing with mocks
type ConnectivityCheckerInterface interface {
	CheckBatch(ctx context.Context, targets []ScreenshotTarget) map[ScreenshotTarget]bool
}

// ConnectivityChecker efficiently checks multiple targets for connectivity
type ConnectivityChecker struct {
	timeout       time.Duration
	maxConcurrency int
}

// NewConnectivityChecker creates a new connectivity checker
func NewConnectivityChecker() *ConnectivityChecker {
	return &ConnectivityChecker{
		timeout:        500 * time.Millisecond, // Reasonable default
		maxConcurrency: 50,                     // Allow up to 50 concurrent checks
	}
}

// CheckBatch efficiently checks connectivity for multiple targets
func (cc *ConnectivityChecker) CheckBatch(ctx context.Context, targets []ScreenshotTarget) map[ScreenshotTarget]bool {
	results := make(map[ScreenshotTarget]bool, len(targets))

	// Use semaphore to limit concurrency
	semaphore := make(chan struct{}, cc.maxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, target := range targets {
		wg.Add(1)
		go func(tgt ScreenshotTarget) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()

			// Check connectivity
			reachable := cc.checkSingle(tgt)

			mu.Lock()
			results[tgt] = reachable
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return results
}

// checkSingle checks connectivity for a single target with optimized timeout
func (cc *ConnectivityChecker) checkSingle(target ScreenshotTarget) bool {
	// Adaptive timeout based on target type
	timeout := cc.timeout

	// Use shorter timeout for local networks
	if isLocalNetwork(target.Host) {
		timeout = 200 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), timeout)
	if err != nil {
		return false
	}
	if err := conn.Close(); err != nil {
		// Connection close error (ignored for connectivity check)
		_ = err
	}
	return true
}

// isLocalNetwork checks if the target appears to be on local network
func isLocalNetwork(host string) bool {
	ip := net.ParseIP(host)
	if ip != nil {
		// Check for private IP ranges
		return ip.IsPrivate() || ip.IsLoopback()
	}
	// For hostnames, assume remote (could be optimized with DNS timing)
	return false
}

// FilterReachableTargets filters a list of targets to only include reachable ones
func FilterReachableTargets(ctx context.Context, targets []ScreenshotTarget) []ScreenshotTarget {
	checker := NewConnectivityChecker()
	return FilterReachableTargetsWithChecker(ctx, targets, checker)
}

// FilterReachableTargetsWithChecker filters targets using a provided connectivity checker
// This allows for dependency injection and testing with mocks
func FilterReachableTargetsWithChecker(ctx context.Context, targets []ScreenshotTarget, checker ConnectivityCheckerInterface) []ScreenshotTarget {
	// Check all targets for connectivity
	connectivityResults := checker.CheckBatch(ctx, targets)

	// Filter to only reachable targets
	var reachable []ScreenshotTarget
	for target, isReachable := range connectivityResults {
		if isReachable {
			reachable = append(reachable, target)
		}
	}

	return reachable
}
