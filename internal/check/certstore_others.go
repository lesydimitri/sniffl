//go:build !windows && !darwin

package check

import (
	"crypto/x509"
	"errors"
)

func (a *App) getWindowsCertStoreRoots() ([]*x509.Certificate, error) {
	return nil, errors.New("getWindowsCertStoreRoots is not implemented on this platform")
}

func (a *App) getMacOSCertStoreRoots() ([]*x509.Certificate, error) {
	return nil, errors.New("getMacOSCertStoreRoots is not implemented on this platform")
}
