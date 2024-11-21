package fetcher

import (
	"context"
	"fmt"
)

// Verify the signature of signedTopology
// using the CA bundle rootCertsBundlePath, and output the verified payload to verifiedTopology.
func cmsVerifyOutput(ctx context.Context, signedTopology, rootCertsBundlePath, verifiedTopology string) (output []byte, err error) {
	if !ctx.Value("nativeCrypto").(bool) {
		if err = checkExecutable("openssl"); err != nil {
			return
		}
		return opensslCMSVerifyOutput(ctx, signedTopology, rootCertsBundlePath, verifiedTopology)
	}
	return []byte{}, fmt.Errorf("not implemented crypto engine: nativeCrypto=%t", ctx.Value("nativeCrypto"))
}

// Detach the signature on signedTopology in the PKCS#7 format.
func smimePk7out(ctx context.Context, signedTopology, detachedSignaturePath string) (output []byte, err error) {
	if !ctx.Value("nativeCrypto").(bool) {
		if err = checkExecutable("openssl"); err != nil {
			return
		}
		return opensslSMIMEPk7out(ctx, signedTopology, detachedSignaturePath)
	}
	return []byte{}, fmt.Errorf("not implemented crypto engine: nativeCrypto=%t", ctx.Value("nativeCrypto"))
}

// Extract the certificate bundle into asCertHumanChain
// from the detached signature at detachedSignaturePath.
func pkcs7Certs(ctx context.Context, detachedSignaturePath, asCertHumanChain string) (output []byte, err error) {
	if !ctx.Value("nativeCrypto").(bool) {
		if err = checkExecutable("openssl"); err != nil {
			return
		}
		return opensslPKCS7Certs(ctx, detachedSignaturePath, asCertHumanChain)
	}
	return []byte{}, fmt.Errorf("not implemented crypto engine: nativeCrypto=%t", ctx.Value("nativeCrypto"))
}
