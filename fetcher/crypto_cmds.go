package fetcher

import (
	"context"
)

// Verify the signature of signedTopology
// using the CA bundle rootCertsBundlePath, and outputs the verified payload to verifiedTopology.
func cmsVerifyOutput(ctx context.Context, signedTopology, rootCertsBundlePath, verifiedTopology string) (err error) {
	if err = checkBinary("openssl"); err != nil {
		return
	}
	return opensslCMSVerifyOutput(ctx, signedTopology, rootCertsBundlePath, verifiedTopology)
}

// Detach the signature on signedTopology in the PKCS#7 format.
func smimePk7out(ctx context.Context, signedTopology, detachedSignaturePath string) (err error) {
	if err = checkBinary("openssl"); err != nil {
		return
	}
	return opensslSMIMEPk7out(ctx, signedTopology, detachedSignaturePath)
}

// Extract the certificate bundle into asCertHumanChain
// from the detached signature at detachedSignaturePath.
func pkcs7Certs(ctx context.Context, detachedSignaturePath, asCertHumanChain string) (err error) {
	if err = checkBinary("openssl"); err != nil {
		return
	}
	return opensslPKCS7Certs(ctx, detachedSignaturePath, asCertHumanChain)
}
