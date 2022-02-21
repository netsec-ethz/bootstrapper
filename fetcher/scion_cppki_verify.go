// Copyright 2022 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fetcher

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"sort"
	"time"
)

func verifyTopologySignature(outputPath, signedTopologyPath, trustAnchorTRCPath string) error {
	// The signature is of the type:
	// openssl cms -sign -text -in topology -out topology.signed -inkey as.key -signer as.cert.pem -certfile ca.cert.pem

	// Low-code implementation, verify the signature only using standard tools
	// and the existing functionality of the `scion-pki` tool to verify a two level certificate chain
	// consisting of (as_cert, ca_cert) back to a TRC (chain) with included root_certs.

	// Signature verification should complete in a timely manner since it is a local operation
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := exec.CommandContext(ctx, "which", "openssl", "scion-pki").Run()
	if err != nil {
		return fmt.Errorf("signature verification failed:"+
			"standard tools `openssl`, or `scion-pki` not found: %w", err)
	}

	_, trcFileName := path.Split(trustAnchorTRCPath)
	rootCertsBundleName := trcFileName + ".certs.pem"
	rootCertsBundlePath := path.Join(outputPath, rootCertsBundleName)
	// extract TRC certificates:
	err = exec.CommandContext(ctx, "scion-pki", "trc", "extract", "certificates",
		trustAnchorTRCPath, "-o", rootCertsBundlePath).Run()
	if err != nil {
		return fmt.Errorf("signature verification failed: unable to extract root certificates from TRC %s: %w",
			trustAnchorTRCPath, err)
	}

	// verify signature:
	err = exec.CommandContext(ctx, "openssl", "cms", "-verify",
		"-in", signedTopologyPath, "-CAfile", rootCertsBundlePath, "-purpose", "any",).Run()
	if err != nil {
		return fmt.Errorf("signature verification failed: signature verification failed: %w", err)
	}

	detachedSignaturePath := path.Join(outputPath, "detached_signature.p7s")
	// detach signature for further validation:
	err = exec.CommandContext(ctx, "openssl", "smime", "-pk7out",
		"-in", signedTopologyPath, "-out", detachedSignaturePath).Run()
	if err != nil {
		return fmt.Errorf("certificate validation failed: unable to detach signature: %w", err)
	}

	asCertChain := path.Join(outputPath, "as_cert_chain.pem")
	// collect included certificates from detached signature:
	shellCommand := fmt.Sprintf(
		"openssl pkcs7 -in %s -inform PEM -print_certs | grep -v \"issuer\\|subject\" | grep . > %s",
		detachedSignaturePath, asCertChain)
	err = exec.CommandContext(ctx, "bash", "-c", shellCommand).Run()
	if err != nil {
		return fmt.Errorf("certificate validation failed: "+
			"unable to gather included certificates from signature: %w", err)
	}

	// verify AS certificate chain back to TRC:
	err = exec.CommandContext(ctx, "scion-pki", "certificate", "verify",
		"--trc", trustAnchorTRCPath, asCertChain).Run()
	if err != nil {
		return fmt.Errorf("certificate validation failed: unable to validate certificate chain: %w", err)
	}

	topologyPath := path.Join(outputPath, topologyJSONFileName)
	// We now have a signed topology with a valid signature and a certificate chain back to a TRC, write out the payload
	err = exec.CommandContext(ctx, "openssl", "cms", "-verify", "-in", signedTopologyPath,
		"-CAfile", rootCertsBundlePath, "-purpose", "any", "-noout", "-text", "-out", topologyPath).Run()
	if err != nil {
		return fmt.Errorf("extracting signed payload failed: %w", err)
	}
	return nil
}

func verifySignature(outputPath string) error {
	files, err := os.ReadDir(path.Join(outputPath, "certs"))
	if err != nil {
		return err
	}
	var trcs sortedFiles
	for _, file := range files {
		fileInfo, err := file.Info()
		if err != nil {
			continue
		}
		if fileInfo.Mode().IsRegular() {
			trcs = append(trcs, fileInfo)
		}
	}
	signedTopologyPath := path.Join(outputPath, signedTopologyFileName)
	// Check against most recently fetched TRC first
	sort.Sort(sort.Reverse(trcs))
	for _, trc := range trcs {
		trustAnchorTRCPath := path.Join(outputPath, "certs", trc.Name())
		// Try to verify signature against all available TRCs
		err = verifyTopologySignature(outputPath, signedTopologyPath, trustAnchorTRCPath)
		if err == nil {
			break
		}
	}
	return err
}

type sortedFiles []fs.FileInfo

func (f sortedFiles) Len() int {
	return len(f)
}

func (f sortedFiles) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
	return
}

func (f sortedFiles) Less(i, j int) bool {
	return f[i].ModTime().Before(f[j].ModTime())
}
