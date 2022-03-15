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
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
)

type topoIA struct {
	IA string `json:"isd_as"`
}

func verifyTopologySignature(bootstrapperPath, unverifiedIA,
	signedTopology, verifiedTopology string, trcPaths []string) error {

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

	// Verify signed payload:
	if len(trcPaths) < 1 {
		return fmt.Errorf("signature verification failed: TRC trust anchor required, none provided")
	}
	trustAnchorTRC := trcPaths[0]
	_, trcFileName := path.Split(trustAnchorTRC)
	rootCertsBundleName := trcFileName + ".certs.pem"
	rootCertsBundlePath := path.Join(bootstrapperPath, rootCertsBundleName)
	// extract TRC certificates:
	err := spkiTRCExtractCerts(ctx, trustAnchorTRC, rootCertsBundlePath)
	if err != nil {
		return fmt.Errorf("signature verification failed: unable to extract root certificates from TRC %s: %w",
			trustAnchorTRC, err)
	}

	// verify signature:
	err = opensslCMSVerify(ctx, signedTopology, rootCertsBundlePath)
	if err != nil {
		return fmt.Errorf("signature verification failed: signature verification failed: %w", err)
	}

	detachedSignaturePath := path.Join(bootstrapperPath, "detached_signature.p7s")
	// detach signature for further validation:
	err = opensslSMIMEPk7out(ctx, signedTopology, detachedSignaturePath)
	if err != nil {
		return fmt.Errorf("certificate validation failed: unable to detach signature: %w", err)
	}

	asCertHumanChain := path.Join(bootstrapperPath, "as_cert_chain.human.pem")
	// collect included certificates from detached signature:
	err = opensslPKCS7Certs(ctx, detachedSignaturePath, asCertHumanChain)
	if err != nil {
		return fmt.Errorf("certificate validation failed: "+
			"unable to gather included certificates from signature: %w", err)
	}

	// Split signer and ca certificate
	certs, rawCerts, err := getCertsFromBundle(asCertHumanChain)
	if err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}
	asCert := certs[0]

	// Check signer AS ID matches unverifiedIA
	certSubjectASID := ""
	OIDNameIA := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 2, 1}
	for _, dn := range asCert.Subject.Names {
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
	rawASCertChain := strings.Join(rawCerts, "\n")
	_ = os.WriteFile(asCertChainPath, []byte(rawASCertChain), 0666)

	// verify AS certificate chain back to TRC(s):
	err = spkiCertVerify(ctx, strings.Join(trcPaths, ","), asCertChainPath)
	if err != nil {
		return fmt.Errorf("certificate validation failed: unable to validate certificate chain: %w", err)
	}

	// We now have a signed topology with a valid signature and a certificate chain back to a TRC, write out the payload
	err = opensslCMSVerifyOutput(ctx, signedTopology, rootCertsBundlePath, verifiedTopology)
	if err != nil {
		return fmt.Errorf("extracting signed payload failed: %w", err)
	}
	return nil
}

func getCertsFromBundle(asCertHumanChain string) ([]*x509.Certificate, []string, error) {
	rawASCertHumanChain, _ := os.ReadFile(asCertHumanChain)
	// Split signer and ca certificate
	re := regexp.MustCompile("-*?BEGIN CERTIFICATE-*?\\n[\\s\\S]*-*?END CERTIFICATE-*?\\n")
	matches := re.FindAllString(string(rawASCertHumanChain), -1)
	if len(matches) != 2 {
		return nil, nil, fmt.Errorf("unable to split certificate bundle: certificates included: %d",
			len(matches))
	}

	asCertRaw := []byte(matches[0])
	rawASCertPem, _ := pem.Decode(asCertRaw)
	if rawASCertPem != nil {
		asCertRaw = rawASCertPem.Bytes
	}
	cert, err := x509.ParseCertificate(asCertRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse signer certificates from signature: %w", err)
	}
	caCertRaw := []byte(matches[1])
	rawCACertPem, _ := pem.Decode(caCertRaw)
	if rawCACertPem != nil {
		caCertRaw = rawCACertPem.Bytes
	}
	caCert, err := x509.ParseCertificate(caCertRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse signer certificates from signature: %w", err)
	}
	return []*x509.Certificate{cert, caCert}, matches, err
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
	trcs, err := getTRCsByISDid(outputPath, candidateTRCid)
	if err != nil {
		return err
	}
	if len(trcs) == 0 {
		if strict {
			return fmt.Errorf("validating TRC update chain failed: strict mode requires TRC anchor")
		}
		return nil
	}
	trcUpdateChainPaths := sortTRCsFiles(trcs).Paths()
	err = spkiTRCVerify(ctx, trcUpdateChainPaths, candidateTRCPath)
	if err != nil {
		return fmt.Errorf("validating TRC update chain failed: %w", err)
	}
	return nil
}

func getTRCsByISDid(outputPath string, isdID int64) ([]trcFileSummary, error) {
	trcs, err := os.ReadDir(path.Join(outputPath, "certs"))
	if err != nil {
		return nil, err
	}
	var isdTRCs []trcFileSummary
	for _, trcName := range trcs {
		if !strings.HasSuffix(trcName.Name(), ".trc") {
			continue
		}
		filePath := path.Join(outputPath, "certs", trcName.Name())
		v, err := os.ReadFile(filePath)
		if err != nil {
			log.Error("reading TRC file %s failed: %w", filePath, err)
			continue
		}
		var trc trcSummary
		_, err = asn1.Unmarshal(v, &trc)
		if err != nil {
			log.Error("parsing TRC file %s failed: %w", filePath, err)
			continue
		}
		if trc.ID.ISD == isdID {
			isdTRCs = append(isdTRCs, trcFileSummary{trc: trc, path: filePath})
		}
	}
	return isdTRCs, nil
}

func sortTRCsFiles(trcFileSummaries []trcFileSummary) (trcUpdateChain sortedTRCFileSummaries) {
	// sort from lowest TRC ISD ID, base number and serial number to highest, in that order
	sort.Sort(sortedTRCFileSummaries(trcFileSummaries))
	return trcFileSummaries
}

func verifySignature(outputPath, workingDir string) error {
	signedTopologyPath := path.Join(workingDir, signedTopologyFileName)

	timestamp := time.Now().Unix()
	// Wipe old temporary directories, except last 10
	err := cleanupVerifyDirs(workingDir)
	if err != nil {
		log.Info("Unable to remove old verify directories", "err", err)
	}
	// Create verify directory
	bootstrapperPath := path.Join(workingDir, fmt.Sprintf("verify-%d", timestamp))
	err = os.Mkdir(bootstrapperPath, 0775)
	if err != nil {
		return fmt.Errorf("failed to create verify directory: dir: %s, err: %w", bootstrapperPath, err)
	}

	// extract unverified payload
	unverifiedTopologyPath := path.Join(bootstrapperPath, topologyJSONFileName+".unverified")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = opensslCMSNoVerifyOutput(ctx, signedTopologyPath, unverifiedTopologyPath)
	if err != nil {
		return fmt.Errorf("extracting unverified payload failed: %w", err)
	}

	unverifiedTopo, err := os.ReadFile(unverifiedTopologyPath)
	if err != nil {
		return fmt.Errorf("reading unverified payload failed: %w", err)
	}
	topoIA := topoIA{}
	err = json.Unmarshal(unverifiedTopo, &topoIA)
	if err != nil {
		return fmt.Errorf("parsing unverified payload failed: %w", err)
	}
	ids := strings.Split(topoIA.IA, "-")
	trcID, err := strconv.ParseInt(ids[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid ISD id: topology: %s, err: %w", unverifiedTopologyPath, err)
	}

	trcs, err := getTRCsByISDid(outputPath, trcID)
	if err != nil {
		return err
	}
	if len(trcs) == 0 {
		return fmt.Errorf("unable to verify signature, no valid TRC found in %s,  ISD id: %d", outputPath, trcID)
	}

	verifiedTopologyPath := path.Join(outputPath, topologyJSONFileName)
	unverifiedIA := topoIA.IA
	// Check against TRC with highest base and serial number,
	// as well the second highest serial number (while in the grace period)
	sortedTRCsPaths := sortTRCsFiles(trcs).Paths()
	for i := len(sortedTRCsPaths) - 1; i > 0 && i > len(sortedTRCsPaths)-1-2; i-- {
		// Try to verify signature against the two latest TRCs matching the ISD claimed by the topology.
		// TRC validity (expiration and grace period) is checked by the call to `scion-pki`.
		// The signer AS needs to match the unverifiedIA claimed by the topology.
		err = verifyTopologySignature(outputPath, unverifiedIA,
			signedTopologyPath, verifiedTopologyPath, sortedTRCsPaths[i:])
		if err == nil {
			break
		}
	}
	return err
}

func cleanupVerifyDirs(workingDir string) error {
	oldVerifyDirs, err := os.ReadDir(workingDir)
	if err != nil {
		return err
	}
	// Sort alpha-numerically, delete all except last 10
	var deleteCandidates []string
	for _, d := range oldVerifyDirs {
		if d.IsDir() && strings.HasPrefix(d.Name(), "verify-") {
			deleteCandidates = append(deleteCandidates, d.Name())
		}
	}
	sort.Strings(deleteCandidates)
	for i, d := range deleteCandidates {
		if i >= len(deleteCandidates)-10 {
			break
		}
		err = os.Remove(path.Join(workingDir, d))
		if err != nil {
			log.Info("Unable to remove old verify directory", "err", err)
		}
	}
	return nil
}

type trcFileSummary struct {
	trc  trcSummary
	path string
}

type sortedTRCFileSummaries []trcFileSummary

func (s sortedTRCFileSummaries) Len() int {
	return len(s)
}

func (s sortedTRCFileSummaries) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
	return
}

func (s sortedTRCFileSummaries) Less(i, j int) bool {
	// compare TRC ISD ID, base number and serial number, in that order
	if s[i].trc.ID.ISD < s[j].trc.ID.ISD {
		return true
	} else if s[i].trc.ID.ISD > s[j].trc.ID.ISD {
		return false
	}
	if s[i].trc.ID.Base < s[j].trc.ID.Base {
		return true
	} else if s[i].trc.ID.Base > s[j].trc.ID.Base {
		return false
	}
	return s[i].trc.ID.Serial < s[j].trc.ID.Serial
}

func (s sortedTRCFileSummaries) Paths() []string {
	var trcPaths []string
	for _, trcSummary := range s {
		trcPaths = append(trcPaths, trcSummary.path)
	}
	return trcPaths
}

// asn1ID is used to encode and decode the TRC ID.
type asn1ID struct {
	ISD    int64 `asn1:"iSD"`
	Serial int64 `asn1:"serialNumber"`
	Base   int64 `asn1:"baseNumber"`
}

type trcSummary struct {
	ID asn1ID `asn1:"iD"`
}
