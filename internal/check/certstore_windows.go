//go:build windows

package check

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
		a.logger.Debug("Opening Windows certificate store", "store", storeNameStr, "provider", fmt.Sprintf("0x%x", storeProvider))

		storeHandle, err := windows.CertOpenStore(
			windows.CERT_STORE_PROV_SYSTEM,
			0, 0,
			storeProvider|windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG,
			uintptr(unsafe.Pointer(storeName)),
		)
		if err != nil {
			a.logger.Debug("Failed to open Windows certificate store", "store", storeNameStr, "error", err)
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
				a.logger.Debug("Certificate enumeration error", "error", err)
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
				a.logger.Debug("Skipping certificate due to parse error", "store", storeNameStr, "error", parseErr)
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
		a.logger.Debug("Failed to convert store name to UTF16", "store", "localMachine", "error", err)
		return nil, err
	}
	fetch(windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, ptr)
	ptr, err = syscall.UTF16PtrFromString(currentUserStoreName)
	if err != nil {
		a.logger.Debug("Failed to convert store name to UTF16", "store", "currentUser", "error", err)
		return nil, err
	}
	fetch(windows.CERT_SYSTEM_STORE_CURRENT_USER, ptr)
	return certs, nil
}

// Stub for non-windows builds.
func (a *App) getMacOSCertStoreRoots() ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("getMacOSCertStoreRoots is not implemented on this platform")
}
