// sniffl/certstore_darwin.go
//go:build darwin

package sniffl

/*
#cgo LDFLAGS: -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
CFIndex getArrayCount(CFArrayRef arr) { return CFArrayGetCount(arr); }
CFTypeRef getArrayElement(CFArrayRef arr, CFIndex idx) { return CFArrayGetValueAtIndex(arr, idx); }
*/
import "C"
import (
	"crypto/x509"
	"fmt"
	"unsafe"
)

// Now a method on *App so we can use a.debugf.
func (a *App) getMacOSCertStoreRoots() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var anchorCerts C.CFArrayRef

	status := C.SecTrustCopyAnchorCertificates(&anchorCerts)
	if status != 0 {
		return nil, fmt.Errorf("SecTrustCopyAnchorCertificates failed with status: %d", status)
	}
	defer C.CFRelease(C.CFTypeRef(anchorCerts))

	count := int(C.getArrayCount(anchorCerts))
	for i := 0; i < count; i++ {
		certRef := C.getArrayElement(anchorCerts, C.CFIndex(i))
		if certRef == 0 {
			continue
		}
		certData := C.SecCertificateCopyData((C.SecCertificateRef)(certRef))
		if certData == 0 {
			continue
		}
		length := C.CFDataGetLength(certData)
		bytes := C.CFDataGetBytePtr(certData)
		der := C.GoBytes(unsafe.Pointer(bytes), C.int(length))
		C.CFRelease(C.CFTypeRef(certData))

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			a.debugf("Failed to parse macOS root certificate at index %d: %v", i, err)
			continue
		}
		a.debugf("Processed macOS system root certificate at index %d:\n%s", i, certificateSummary(cert))
		certs = append(certs, cert)
	}
	return certs, nil
}

// Stub so non-darwin builds still compile.
func (a *App) getWindowsCertStoreRoots() ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("getWindowsCertStoreRoots is not implemented on this platform")
}
