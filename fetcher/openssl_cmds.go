package fetcher

import (
	"context"
	"os/exec"
)

// opensslCMSVerifyOutput uses the openssl cms module to verify the signature of signedTopology
// using the CA bundle rootCertsBundlePath, and outputs the verified payload to verifiedTopology.
func opensslCMSVerifyOutput(ctx context.Context, signedTopology, rootCertsBundlePath, verifiedTopology string) error {
	return exec.CommandContext(ctx, "openssl", "cms", "-verify", "-in", signedTopology,
		"-CAfile", rootCertsBundlePath, "-purpose", "any", "-noout", "-text", "-out", verifiedTopology).Run()
}

// opensslSMIMEPk7out uses the openssl smime module to detach the signature on signedTopology in the PKCS#7 format.
func opensslSMIMEPk7out(ctx context.Context, signedTopology, detachedSignaturePath string) error {
	return exec.CommandContext(ctx, "openssl", "smime", "-pk7out",
		"-in", signedTopology, "-out", detachedSignaturePath).Run()
}

// opensslPKCS7Certs uses the openssl pkcs7 module to extract the certificate bundle into asCertHumanChain
// from the detached signature at detachedSignaturePath.
func opensslPKCS7Certs(ctx context.Context, detachedSignaturePath, asCertHumanChain string) error {
	return exec.CommandContext(ctx, "openssl", "pkcs7", "-in", detachedSignaturePath,
		"-inform", "PEM", "-print_certs", "-out", asCertHumanChain).Run()
}
