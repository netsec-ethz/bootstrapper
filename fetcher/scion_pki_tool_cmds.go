package fetcher

import (
	"context"
	"os/exec"
	"strings"
)

// scion-pki commands

// spkiTRCExtractCerts extracts the certificates contained in the TRC trustAnchorTRC into rootCertsBundlePath.
func spkiTRCExtractCerts(ctx context.Context, trustAnchorTRC, rootCertsBundlePath string) error {
	return exec.CommandContext(ctx, "scion-pki", "trc", "extract", "certificates",
		trustAnchorTRC, "-o", rootCertsBundlePath).Run()
}

// spkiCertVerify verifies the AS certificate asCertChainPath
// against the sorted TRCs in the update chain trcsUpdateChain.
func spkiCertVerify(ctx context.Context, trcsUpdateChain []string, asCertChainPath string) error {
	return exec.CommandContext(ctx, "scion-pki", "certificate", "verify",
		"--trc", strings.Join(trcsUpdateChain, ","), asCertChainPath).Run()
}

// spkiTRCVerify verifies the TRC update chain for candidateTRCPath anchored in the TRCs trcUpdateChainPaths
func spkiTRCVerify(ctx context.Context, trcAnchorPath string, updateChainCandidatePaths []string) error {
	cmdArgs := []string{"trc", "verify", "--anchor"}
	cmdArgs = append(cmdArgs, trcAnchorPath)
	cmdArgs = append(cmdArgs, updateChainCandidatePaths...)
	return exec.CommandContext(ctx, "scion-pki", cmdArgs...).Run()
}
