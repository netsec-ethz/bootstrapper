package fetcher

import (
	"context"
	"os/exec"
)

// scion-pki commands

// spkiTRCExtractCerts extracts the certificates contained in the TRC trustAnchorTRC into rootCertsBundlePath.
func spkiTRCExtractCerts(ctx context.Context, trustAnchorTRC, rootCertsBundlePath string) error {
	return exec.CommandContext(ctx, "scion-pki", "trc", "extract", "certificates",
		trustAnchorTRC, "-o", rootCertsBundlePath).Run()
}

// spkiCertVerify verifies the AS certificate asCertChainPath against the sorted TRC update chain trcs.
func spkiCertVerify(ctx context.Context, trcs, asCertChainPath string) error {
	return exec.CommandContext(ctx, "scion-pki", "certificate", "verify",
		"--trc", trcs, asCertChainPath).Run()
}

// spkiTRCVerify verifies the TRC update chain for candidateTRCPath anchored in the TRCs trcUpdateChainPaths
func spkiTRCVerify(ctx context.Context, trcUpdateChainPaths []string, candidateTRCPath string) error {
	cmdArgs := []string{"trc", "-verify", "--anchor"}
	cmdArgs = append(cmdArgs, trcUpdateChainPaths...)
	cmdArgs = append(cmdArgs, candidateTRCPath)
	return exec.CommandContext(ctx, "scion-pki",  cmdArgs...).Run()
}
