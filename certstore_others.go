//go:build !windows
// +build !windows

package main

import "crypto/x509"

// For non-Windows platforms, return no certificates or a stub error.
func getWindowsCertStoreRoots() ([]*x509.Certificate, error) {
	return nil, nil
}

