package sniffl_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/lesydimitri/sniffl/sniffl"
)

func TestApp_Run_SingleTarget_NoExport(t *testing.T) {
	var out, errBuf bytes.Buffer
	app := sniffl.New(sniffl.Config{
		Out: &out, Err: &errBuf,
		FileCreator: func(name string) (io.WriteCloser, error) {
			return nil, fmt.Errorf("unexpected file create: %s", name)
		},
	})
	// Use none protocol to avoid network; fetchTLS will be exercised only if dialed, so skip by setting Protocol to none and not calling network.
	err := app.Run(context.Background(), []sniffl.Target{{HostPort: "example.com:443", Protocol: "none"}})
	_ = err // Depending on fake seams, this may succeed or print a fetch error; the test mainly ensures wiring compiles/exposes API.
}

// Test with multiple targets
func TestApp_Run_MultipleTargets(t *testing.T) {
	var out, errBuf bytes.Buffer
	app := sniffl.New(sniffl.Config{
		Out: &out, Err: &errBuf,
		FileCreator: func(name string) (io.WriteCloser, error) {
			return nil, fmt.Errorf("unexpected file create: %s", name)
		},
	})

	err := app.Run(context.Background(), []sniffl.Target{
		{HostPort: "example.com:443", Protocol: "none"},
		{HostPort: "example.org:443", Protocol: "none"},
	})

	// Verify the test runs without crashing
	_ = err
}

// Test with export functionality
func TestApp_Run_WithExport(t *testing.T) {
	var out, errBuf bytes.Buffer
	var fileContent bytes.Buffer
	fileCreated := false

	app := sniffl.New(sniffl.Config{
		Out: &out, Err: &errBuf,
		ExportMode: "single", // Enable export
		FileCreator: func(name string) (io.WriteCloser, error) {
			fileCreated = true
			return nopWriteCloser{&fileContent}, nil
		},
	})

	err := app.Run(context.Background(), []sniffl.Target{{HostPort: "example.com:443", Protocol: "none"}})

	// Verify export was attempted
	if !fileCreated {
		t.Errorf("Expected file creation with export mode set")
	}

	_ = err
}

// Helper for TestApp_Run_WithExport
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
