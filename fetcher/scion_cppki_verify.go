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
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

type topoIA struct {
	IA string `json:"isd_as"`
}

func verifyTopologySignature(bootstrapperPath, unverifiedIA,
	signedTopology, trustAnchorTRC, verifiedTopology string) error {

	// TODO: change stringly typed function parameters

	// The signature is of the type:
	// openssl cms -sign -text -in topology -out topology.signed -inkey as.key -signer as.cert.pem -certfile ca.cert.pem

	// Verify the signature using openssl, and do some additional checks between the payload and the signer cert.
	// Use the existing functionality of the `scion-pki` tool to verify a two level certificate chain
	// consisting of (as_cert, ca_cert) back to a TRC (chain) with included root_certs.

	// Signature verification should complete in a timely manner since it is a local operation
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	for _, tool := range []string{"openssl", "scion-pki"} {
		_, err := exec.LookPath(tool)
		if err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	// Verify signed payload
	_, trcFileName := path.Split(trustAnchorTRC)
	rootCertsBundleName := trcFileName + ".certs.pem"
	rootCertsBundlePath := path.Join(bootstrapperPath, rootCertsBundleName)
	// extract TRC certificates:
	err := exec.CommandContext(ctx, "scion-pki", "trc", "extract", "certificates",
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

	asCertHumanChain := path.Join(bootstrapperPath, "as_cert_chain.human.pem")
	// collect included certificates from detached signature:
	err = exec.CommandContext(ctx, "openssl", "pkcs7", "-in", detachedSignaturePath,
		"-inform", "PEM", "-print_certs", "-out", asCertHumanChain).Run()
	if err != nil {
		return fmt.Errorf("certificate validation failed: "+
			"unable to gather included certificates from signature: %w", err)
	}

	// Split signer and ca certificate
	rawASCertHumanChain, _ := os.ReadFile(asCertHumanChain)
	re := regexp.MustCompile("-*?BEGIN CERTIFICATE-*?\\n[\\s\\S]*-*?END CERTIFICATE-*?\\n")
	matches := re.FindAllString(string(rawASCertHumanChain), -1)

	asCertRaw := []byte(matches[0])
	rawASCertPem, _ := pem.Decode(asCertRaw)
	if rawASCertPem != nil {
		asCertRaw = rawASCertPem.Bytes
	}
	cert, err := x509.ParseCertificate(asCertRaw)
	if err != nil {
		return fmt.Errorf("certificate validation failed: "+
			"unable to parse signer certificates from signature: %w", err)
	}

	// Check signer AS ID matches unverifiedIA
	certSubjectASID := ""
	OIDNameIA := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 2, 1}
	for _, dn := range cert.Subject.Names {
		if dn.Type.Equal(OIDNameIA) {
			certSubjectASID = dn.Value.(string)
			break
		}
	}
	if certSubjectASID != unverifiedIA {
		return fmt.Errorf("certificate validation failed: "+
			"signer AS certificate subject does not match AS ID included in topology: "+
			"expected: %s, actual: %s", unverifiedIA, certSubjectASID)
	}

	// Store certificate chain extracted from signature
	asCertChainPath := path.Join(bootstrapperPath, "as_cert_chain.pem")
	rawASCertChain := strings.Join(matches, "\n")
	_ = os.WriteFile(asCertChainPath, []byte(rawASCertChain), 0666)

	// verify AS certificate chain back to TRC:
	err = exec.CommandContext(ctx, "scion-pki", "certificate", "verify",
		"--trc", trustAnchorTRC, asCertChainPath).Run()
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

func verifyTRCUpdateChain(outputPath, candidateTRCPath string, strict bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	v, _ := os.ReadFile(candidateTRCPath)
	var trc trcSummary
	_, err := asn1.Unmarshal(v, &trc)
	if err != nil {
		return fmt.Errorf("validating TRC update chain failed: %w", err)
	}
	candidateTRCid := trc.ID.ISD
	trcs, err := os.ReadDir(path.Join(outputPath, "certs"))
	if err != nil {
		return err
	}
	var trcUpdateChain []string
	for _, trc := range trcs {
		if strings.HasPrefix(trc.Name(), fmt.Sprintf("%d-", candidateTRCid)) {
			// TODO: sort TRCs in the update chain, possibly sanitize trc.Name()
			trcUpdateChain = append(trcUpdateChain, trc.Name())
		}
	}
	if len(trcUpdateChain) == 0 {
		if strict {
			return fmt.Errorf("validating TRC update chain failed: strict mode requires TRC anchor")
		}
		return nil
	}
	cmdArgs := []string{"trc", "-verify", "--anchor"}
	cmdArgs = append(cmdArgs, trcUpdateChain...)
	cmdArgs = append(cmdArgs, candidateTRCPath)
	err = exec.CommandContext(ctx, "scion-pki", cmdArgs...).Run()
	if err != nil {
		return fmt.Errorf("validating TRC update chain failed: %w", err)
	}
	return nil
}

func verifySignature(outputPath, workingDir string) error {
	signedTopologyPath := path.Join(workingDir, signedTopologyFileName)

	timestamp := time.Now().Unix()
	bootstrapperPath := path.Join(workingDir, fmt.Sprintf("verify-%d", timestamp))
	err := os.Mkdir(bootstrapperPath, 0775)
	if err != nil {
		return fmt.Errorf("Failed to create verify directory: dir: %s, err: %w", bootstrapperPath, err)
	}

	// extract unverified payload
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unverifiedTopologyPath := path.Join(bootstrapperPath, topologyJSONFileName+".unverified")
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
	ids := strings.Split(topoIA.IA, "-")
	trcID := ids[0]

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
		v, _ := os.ReadFile(trustAnchorTRCPath)
		var trc trcSummary
		_, err = asn1.Unmarshal(v, &trc)
		if err!= nil || fmt.Sprint(trc.ID.ISD) != trcID {
			continue
		}
		// Try to verify signature against all available TRCs matching the ISD claimed by the topology
		// TRC validity (expiration and grace period is checked by the call to `scion-pki`
		// The signer AS needs to match the unverifiedASid claimed by the topology.
		unverifiedIA := topoIA.IA
		err = verifyTopologySignature(outputPath, unverifiedIA,
			signedTopologyPath, trustAnchorTRCPath, verifiedTopologyPath)
		if err == nil {
			break
		}
	}
	return err
}

// asn1ID is used to encode and decode the TRC ID.
type asn1ID struct {
	ISD int64 `asn1:"iSD"`
}

type trcSummary struct {
	ID asn1ID `asn1:"iD"`
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
