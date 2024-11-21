package fetcher

import (
	"context"
	"os/exec"
)

// opensslCMSVerifyOutput uses the openssl cms module to verify the signature of signedTopology
// using the CA bundle rootCertsBundlePath, and outputs the verified payload to verifiedTopology.
func opensslCMSVerifyOutput(ctx context.Context, signedTopo, rootCertsBundlePath, verifiedTopo string) ([]byte, error) {
	return exec.CommandContext(ctx, "openssl", "cms", "-verify", "-in", signedTopo,
		"-CAfile", rootCertsBundlePath, "-purpose", "any", "-noout", "-text", "-out", verifiedTopo).CombinedOutput()
}

// opensslSMIMEPk7out uses the openssl smime module to detach the signature on signedTopology in the PKCS#7 format.
func opensslSMIMEPk7out(ctx context.Context, signedTopo, detachedSignaturePath string) ([]byte, error) {
	return exec.CommandContext(ctx, "openssl", "smime", "-pk7out",
		"-in", signedTopo, "-out", detachedSignaturePath).CombinedOutput()
}

// opensslPKCS7Certs uses the openssl pkcs7 module to extract the certificate bundle into asCertHumanChain
// from the detached signature at detachedSignaturePath.
func opensslPKCS7Certs(ctx context.Context, detachedSignaturePath, asCertHumanChain string) ([]byte, error) {
	return exec.CommandContext(ctx, "openssl", "pkcs7", "-in", detachedSignaturePath,
		"-inform", "PEM", "-print_certs", "-out", asCertHumanChain).CombinedOutput()
}
