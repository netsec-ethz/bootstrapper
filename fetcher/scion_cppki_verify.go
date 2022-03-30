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
	"crypto/x509/pkix"
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

// verifyTopologySignature verifies the signature of the signed topology in workingDir
// and stores the verified topology the in outputPath.
func verifyTopologySignature(outputPath, workingDir string) error {
	// The signature is of the type `ecdsa-with-SHA256`:
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
			return err
		}
	}

	// Create verify directory
	timestamp := time.Now().Unix()
	verifyPath := path.Join(workingDir, fmt.Sprintf("verify-%d", timestamp))
	err := os.Mkdir(verifyPath, 0775)
	if err != nil {
		return fmt.Errorf("failed to create verify directory: dir: %s, err: %w", verifyPath, err)
	}

	signedTopology := path.Join(workingDir, signedTopologyFileName)
	detachedSignaturePath := path.Join(verifyPath, "detached_signature.p7s")
	// detach signature for further validation:
	err = opensslSMIMEPk7out(ctx, signedTopology, detachedSignaturePath)
	if err != nil {
		return fmt.Errorf("unable to detach signature: %w", err)
	}

	asCertHumanChain := path.Join(verifyPath, "as_cert_chain.human.pem")
	// collect included certificates from detached signature:
	err = opensslPKCS7Certs(ctx, detachedSignaturePath, asCertHumanChain)
	if err != nil {
		return fmt.Errorf("unable to gather included certificates from signature: %w", err)
	}

	// Split signer and ca certificate
	certs, rawCerts, err := getCertsFromBundle(asCertHumanChain)
	if err != nil {
		return err
	}
	asCert := certs[0]

	// Store certificate chain extracted from signature
	asCertChainPath := path.Join(verifyPath, "as_cert_chain.pem")
	rawASCertChain := strings.Join(rawCerts, "\n")
	_ = os.WriteFile(asCertChainPath, []byte(rawASCertChain), 0666)

	// Get TRCs corresponding to signer IA
	signerIA, signerTRCid, err := getCertIA(asCert)
	if err != nil {
		return err
	}

	trcs, err := getTRCsByISDid(outputPath, signerTRCid)
	if err != nil {
		return err
	}
	if len(trcs) == 0 {
		return fmt.Errorf("unable to verify signature, no valid TRC found in %s,  ISD id: %d",
			verifyPath, signerTRCid)
	}
	sortedTRCsPaths := sortTRCsFiles(trcs).Paths()

	for i := len(sortedTRCsPaths) - 1; i > 0 && i > len(sortedTRCsPaths)-1-2; i-- {
		// Try to verify signature against the two latest TRCs matching the ISD claimed by the signer.
		// TRC validity (expiration and grace period) is checked by the call to `scion-pki`.
		// The signer IA needs to match the IA in the topology of the payload.
		trustAnchorTRC := sortedTRCsPaths[i]
		_, trcFileName := path.Split(trustAnchorTRC)
		rootCertsBundleName := trcFileName + ".certs.pem"
		rootCertsBundlePath := path.Join(verifyPath, rootCertsBundleName)
		// extract TRC certificates:
		err = spkiTRCExtractCerts(ctx, trustAnchorTRC, rootCertsBundlePath)
		if err != nil {
			err = fmt.Errorf("unable to extract root certificates from TRC %s: %w",
				trustAnchorTRC, err)
			continue
		}
		// verify the AS certificate chain (but not the payload signature) back to TRC(s) follows the SCION CP PKI rules
		// about cert type, key usage:
		err = spkiCertVerify(ctx, strings.Join(sortedTRCsPaths[i:], ","), asCertChainPath)
		if err != nil {
			err = fmt.Errorf("unable to validate certificate chain: %w", err)
			continue
		}

		unvalidatedTopologyPath := path.Join(verifyPath, topologyJSONFileName+".unvalidated")
		// verify the signature and certificate chain back to a root certs bundle, write out the payload:
		err = opensslCMSVerifyOutput(ctx, signedTopology, rootCertsBundlePath, unvalidatedTopologyPath)
		if err != nil {
			err = fmt.Errorf("verifying and extracting signed payload failed: %w", err)
			continue
		}

		// Validate signer IA matches payload IA
		err = checkTopoIA(unvalidatedTopologyPath, signerIA)
		if err != nil {
			rerr := os.Remove(unvalidatedTopologyPath)
			log.Error("removing mismatching topology failed", "err", rerr)
			continue
		}
		verifiedTopology := path.Join(outputPath, topologyJSONFileName)
		err = os.Rename(unvalidatedTopologyPath, verifiedTopology)
		if err != nil {
			continue
		}
		break
	}
	return err
}

// getCertsFromBundle splits a certificate bundle consisting of an AS certificate and a CA certificate
// into individual certificates and parses them.
func getCertsFromBundle(asCertHumanChain string) ([]*x509.Certificate, []string, error) {
	rawASCertHumanChain, _ := os.ReadFile(asCertHumanChain)
	// Split signer and ca certificate
	re := regexp.MustCompile("-*?BEGIN CERTIFICATE-*?\\n[\\s\\S]*?-*?END CERTIFICATE-*?\\n")
	matches := re.FindAllString(string(rawASCertHumanChain), -1)
	if len(matches) != 2 {
		return nil, nil, fmt.Errorf("unable to split certificate bundle %s: certificates included: %d",
			asCertHumanChain, len(matches))
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

// verifyTRCUpdateChain verifies the TRC at candidateTRCPath has a valid update chain to the other TRCs of the same ISD.
func verifyTRCUpdateChain(outputPath, candidateTRCPath string, strict bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	v, _ := os.ReadFile(candidateTRCPath)
	trc, err := getTRCSummary(v)
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

// checkTopoIA checks that the expectedIA matches the IA in the topology file at topologyPath.
func checkTopoIA(topologyPath, expectedIA string) error {
	unverifiedTopo, err := os.ReadFile(topologyPath)
	if err != nil {
		return fmt.Errorf("reading unverified payload failed: %w", err)
	}
	topoIA := topoIA{}
	err = json.Unmarshal(unverifiedTopo, &topoIA)
	if err != nil {
		return fmt.Errorf("parsing unverified payload failed: %w", err)
	}
	payloadIA := topoIA.IA

	if expectedIA != payloadIA {
		return fmt.Errorf("signer AS certificate subject does not match AS ID included in topology: "+
			"expected: %s, actual: %s", expectedIA, payloadIA)
	}
	return nil
}

// getCertIA returns the IA property of subject of the certificate and the TRCid.
func getCertIA(cert *x509.Certificate) (IA string, TRCid int64, err error) {
	OIDNameIA := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 2, 1}
	for _, dn := range cert.Subject.Names {
		if dn.Type.Equal(OIDNameIA) {
			IA = dn.Value.(string)
			break
		}
	}

	subjectISDAS := strings.Split(IA, "-")
	TRCid, err = strconv.ParseInt(subjectISDAS[0], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("certificate subject does not have a valid IA: "+
			"expected: %s, actual: %s, err=%w", "ISD-AS", IA, err)
	}
	return
}

// getTRCsByISDid returns all the TRCs for a specific ISD ID.
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
			log.Error("reading TRC file failed", "path", filePath, "err", err)
			continue
		}
		trc, err := getTRCSummary(v)
		if err != nil {
			log.Error("parsing TRC file failed", "path", filePath, "err", err)
			continue
		}
		if trc.ID.ISD == isdID {
			isdTRCs = append(isdTRCs, trcFileSummary{trc: *trc, path: filePath})
		}
	}
	return isdTRCs, err
}

// sortTRCsFiles sorts the TRC summaries according to their update chain order.
func sortTRCsFiles(trcFileSummaries []trcFileSummary) (trcUpdateChain sortedTRCFileSummaries) {
	// sort from lowest TRC ISD ID, base number and serial number to highest, in that order
	sort.Sort(sortedTRCFileSummaries(trcFileSummaries))
	return trcFileSummaries
}

func verifySignature(outputPath, workingDir string) error {
	// Wipe old temporary directories, except last 10
	err := cleanupVerifyDirs(workingDir)
	if err != nil {
		log.Info("Unable to remove old verify directories", "err", err)
	}

	err = verifyTopologySignature(outputPath, workingDir)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
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

// getTRCSummary returns the trcSummary with ISD, serial and base number information for a pem encoded or TRC blob.
func getTRCSummary(rawTRC []byte) (*trcSummary, error) {
	trcPem, _ := pem.Decode(rawTRC)
	if trcPem != nil && trcPem.Type == "TRC" {
		rawTRC = trcPem.Bytes
	}
	var rawTRCSigned trcContainer
	_, err := asn1.Unmarshal(rawTRC, &rawTRCSigned)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trc container: %w", err)
	}

	if !rawTRCSigned.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return nil, fmt.Errorf("wrong trc signed data content type")
	}
	var trcSignedData trcSignedData
	_, err = asn1.Unmarshal(rawTRCSigned.Content.Bytes, &trcSignedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trc signed data: %w", err)
	}
	var trcContent asn1.RawValue
	_, err = asn1.Unmarshal(trcSignedData.EncapContentInfo.EContent.Bytes, &trcContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trc encap content data: %w", err)
	}

	var trcSummary trcSummary
	_, err = asn1.Unmarshal(trcContent.Bytes, &trcSummary)
	if err != nil {
		return nil, fmt.Errorf("parsing TRC ID failed: %w", err)
	}
	return &trcSummary, nil
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
	Version int64  `asn1:"version"`
	ID      asn1ID `asn1:"iD"`
}

type trcEncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type trcSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo trcEncapsulatedContentInfo
}

type trcContainer struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}
