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
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"sort"
	"time"
)

type topoIA struct {
	IA string `json:"isd_as"`
}

func verifyTopologySignature(bootstrapperPath, signedTopology, trustAnchorTRC, verifiedTopology string) error {
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

	// Verify signed payload
	_, trcFileName := path.Split(trustAnchorTRC)
	rootCertsBundleName := trcFileName + ".certs.pem"
	rootCertsBundlePath := path.Join(bootstrapperPath, rootCertsBundleName)
	// extract TRC certificates:
	err = exec.CommandContext(ctx, "scion-pki", "trc", "extract", "certificates",
		trustAnchorTRC, "-o", rootCertsBundlePath).Run()
	if err != nil {
		return fmt.Errorf("signature verification failed: unable to extract root certificates from TRC %s: %w",
			trustAnchorTRC, err)
	}

	// verify signature:
	err = exec.CommandContext(ctx, "openssl", "cms", "-verify",
		"-in", signedTopology, "-CAfile", rootCertsBundlePath, "-purpose", "any").Run()
	if err != nil {
		return fmt.Errorf("signature verification failed: signature verification failed: %w", err)
	}

	detachedSignaturePath := path.Join(bootstrapperPath, "detached_signature.p7s")
	// detach signature for further validation:
	err = exec.CommandContext(ctx, "openssl", "smime", "-pk7out",
		"-in", signedTopology, "-out", detachedSignaturePath).Run()
	if err != nil {
		return fmt.Errorf("certificate validation failed: unable to detach signature: %w", err)
	}

	asCertChain := path.Join(bootstrapperPath, "as_cert_chain.pem")
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
		"--trc", trustAnchorTRC, asCertChain).Run()
	if err != nil {
		return fmt.Errorf("certificate validation failed: unable to validate certificate chain: %w", err)
	}

	// We now have a signed topology with a valid signature and a certificate chain back to a TRC, write out the payload
	err = exec.CommandContext(ctx, "openssl", "cms", "-verify", "-in", signedTopology,
		"-CAfile", rootCertsBundlePath, "-purpose", "any", "-noout", "-text", "-out", verifiedTopology).Run()
	if err != nil {
		return fmt.Errorf("extracting signed payload failed: %w", err)
	}
	return nil
}

func verifySignature(outputPath string) error {
	signedTopologyPath := path.Join(outputPath, signedTopologyFileName)

	bootstrapperPath := path.Join(outputPath, "bootstrapper")
	err := os.Mkdir(bootstrapperPath, 0777)
	if err != nil {
		return fmt.Errorf("Failed to create bootstrapper intermediate directory", "dir", bootstrapperPath, "err", err)
	}
	timestamp := time.Now().Unix()
	bootstrapperPath = path.Join(outputPath, "bootstrapper", fmt.Sprintf("verify-%d", timestamp))
	err = os.Mkdir(bootstrapperPath, 0777)
	if err != nil {
		return fmt.Errorf("Failed to create verify directory", "dir", bootstrapperPath, "err", err)
	}

	// extract unverified payload
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unverifiedTopologyPath := path.Join(bootstrapperPath, topologyJSONFileName)
	err = exec.CommandContext(ctx, "openssl", "cms", "-verify", "-noverify",
		"-in", signedTopologyPath, "-text", "-noout", "-out", unverifiedTopologyPath).Run()
	if err != nil {
		return fmt.Errorf("extracting unverified payload failed: %w", err)
	}

	unverifiedTopo, err := os.ReadFile(unverifiedTopologyPath)
	if err != nil {
		return fmt.Errorf("Reading unverified payload failed: %w", err)
	}
	topoIA := topoIA{}
	err = json.Unmarshal(unverifiedTopo, &topoIA)
	if err != nil {
		return fmt.Errorf("Parsing unverified payload failed: %w", err)
	}

	// Check if ISD ID in topology matches TRC
	// TODO: extract ISD ID from TRC

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

	verifiedTopologyPath := path.Join(outputPath, topologyJSONFileName)
	// Check against most recently fetched TRC first
	sort.Sort(sort.Reverse(trcs))
	for _, trc := range trcs {
		trustAnchorTRCPath := path.Join(outputPath, "certs", trc.Name())
		// Try to verify signature against all available TRCs
		err = verifyTopologySignature(outputPath, signedTopologyPath, trustAnchorTRCPath, verifiedTopologyPath)
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
