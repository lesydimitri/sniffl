//go:build !windows && !darwin

package main

import (
	"crypto/x509"
	"errors"
	"fmt"
)

func getWindowsCertStoreRoots() ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("getWindowsCertStoreRoots is not implemented on this platform")
}

func getMacOSCertStoreRoots() ([]*x509.Certificate, error) {
	return nil, errors.New("not supported on this platform")
}
