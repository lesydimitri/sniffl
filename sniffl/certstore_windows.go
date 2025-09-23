// sniffl/certstore_windows.go
//go:build windows

package sniffl

import (
	"crypto/x509"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (a *App) getWindowsCertStoreRoots() ([]*x509.Certificate, error) {
	const (
		localMachineStoreName = "Root"
		currentUserStoreName  = "Root"
	)
	var certs []*x509.Certificate

	fetch := func(storeProvider uint32, storeName *uint16) {
		storeNameStr := syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(storeName))[:])
		a.debugf("Opening store %s, provider 0x%x", storeNameStr, storeProvider)

		storeHandle, err := windows.CertOpenStore(
			windows.CERT_STORE_PROV_SYSTEM,
			0, 0,
			storeProvider|windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG,
			uintptr(unsafe.Pointer(storeName)),
		)
		if err != nil {
			a.debugf("Failed to open store %s: %v", storeNameStr, err)
			return
		}
		defer windows.CertCloseStore(storeHandle, 0)

		var prevCtx *windows.CertContext
		for {
			ctx, err := windows.CertEnumCertificatesInStore(storeHandle, prevCtx)
			if ctx == nil {
				break
			}
			if err != nil {
				a.debugf("CertEnumCertificatesInStore error: %v", err)
				break
			}

			dupCtx := windows.CertDuplicateCertificateContext(ctx)
			if prevCtx != nil {
				windows.CertFreeCertificateContext(prevCtx)
			}
			prevCtx = ctx

			data := make([]byte, dupCtx.Length)
			copy(data, unsafe.Slice(dupCtx.EncodedCert, dupCtx.Length))

			cert, parseErr := x509.ParseCertificate(data)
			if parseErr != nil {
				a.debugf("Skipping cert in store %s due to parse error: %v", storeNameStr, parseErr)
				windows.CertFreeCertificateContext(dupCtx)
				continue
			}
			certs = append(certs, cert)
			windows.CertFreeCertificateContext(dupCtx)
		}
		if prevCtx != nil {
			windows.CertFreeCertificateContext(prevCtx)
		}
	}

	ptr, err := syscall.UTF16PtrFromString(localMachineStoreName)
	if err != nil {
		a.debugf("Failed to convert localMachineStoreName to UTF16: %v", err)
		return nil, err
	}
	fetch(windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, ptr)
	ptr, err = syscall.UTF16PtrFromString(currentUserStoreName)
	if err != nil {
		a.debugf("Failed to convert currentUserStoreName to UTF16: %v", err)
		return nil, err
	}
	fetch(windows.CERT_SYSTEM_STORE_CURRENT_USER, ptr)
	return certs, nil
}

// Stub so non-windows builds still compile.
func (a *App) getMacOSCertStoreRoots() ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("getMacOSCertStoreRoots is not implemented on this platform")
}
