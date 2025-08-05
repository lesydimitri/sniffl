//go:build windows
// +build windows

package main

import (
	"crypto/x509"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getWindowsCertStoreRoots() ([]*x509.Certificate, error) {
	const (
		localMachineStoreName = "Root"
		currentUserStoreName  = "Root"
	)

	var certs []*x509.Certificate

	fetch := func(storeProvider uint32, storeName *uint16) {
		storeNameStr := syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(storeName))[:])
		log.Printf("[DEBUG] Opening store %s, provider 0x%x", storeNameStr, storeProvider)

		storeHandle, err := windows.CertOpenStore(
			windows.CERT_STORE_PROV_SYSTEM,
			0,
			0,
			storeProvider|windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG,
			uintptr(unsafe.Pointer(storeName)),
		)
		if err != nil {
			log.Printf("[DEBUG] Failed to open store %s: %v", storeNameStr, err)
			return
		}
		defer windows.CertCloseStore(storeHandle, 0)

		var prevCtx *windows.CertContext = nil
		for {
			ctx, err := windows.CertEnumCertificatesInStore(storeHandle, prevCtx)
			if ctx == nil {
				break
			}
			if err != nil {
				log.Printf("[DEBUG] CertEnumCertificatesInStore error: %v", err)
				break
			}

			// Duplicate certificate context immediately for safe usage
			dupCtx := windows.CertDuplicateCertificateContext(ctx)
			if prevCtx != nil {
				windows.CertFreeCertificateContext(prevCtx)
			}
			prevCtx = ctx

			// Defensive copy of encoded certificate bytes into Go slice
			data := make([]byte, dupCtx.Length)
			copy(data, unsafe.Slice(dupCtx.EncodedCert, dupCtx.Length))

			cert, parseErr := x509.ParseCertificate(data)
			if parseErr != nil {
				// Log and skip certificates that fail parsing (e.g., negative serial number)
				log.Printf("[DEBUG] Skipping cert in store %s due to parse error: %v", storeNameStr, parseErr)
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

	fetch(windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, syscall.StringToUTF16Ptr(localMachineStoreName))
	fetch(windows.CERT_SYSTEM_STORE_CURRENT_USER, syscall.StringToUTF16Ptr(currentUserStoreName))

	return certs, nil
}
