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
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/bootstrapper/config"
)

const (
	verifyTimeout      = 3 * time.Second
	updateChainTimeout = 1 * time.Second
)

// verifyTopologySignature verifies the signature of the signed topology in workingDir
// and stores the verified topology in outputPath.
func verifyTopologySignature(cfg *config.Config) error {
	// The signature is of the type `ecdsa-with-SHA256`:
	// openssl cms -sign -text -in topology -out topology.signed -inkey as.key -signer as.cert.pem -certfile ca.cert.pem

	// Verify the signature using openssl, and do some additional checks between the payload and the signer cert.
	// Use the existing functionality of the `scion-pki` tool to verify a two level certificate chain
	// consisting of (as_cert, ca_cert) back to a TRC (chain) with included root_certs.

	ctx, cancel, verifyPath, err := setupVerifyEnv(cfg)
	if err != nil {
		return err
	}
	defer cancel()

	signedTopology := filepath.Join(cfg.WorkingDir(), signedTopologyFileName)
	signerTRCid, signerIA, asCertChainPath, err := extractSignerInfo(ctx, signedTopology, verifyPath)
	if err != nil {
		return err
	}

	sortedTRCsPaths, err := sortedTRCsPathsByISD(cfg.SciondConfigDir, signerTRCid)
	if err != nil {
		return err
	}

	// verify the AS certificate chain (but not the payload signature) back to the TRCs of the ISD follows the
	// SCION CP PKI rules about cert type, key usage:
	if err = spkiCertVerify(ctx, sortedTRCsPaths, asCertChainPath); err != nil {
		return fmt.Errorf("unable to validate certificate chain: %w", err)
	}

	var unvalidatedTopologyPath string
	for i := len(sortedTRCsPaths) - 1; i >= 0 && i > len(sortedTRCsPaths)-1-2; i-- {
		// Try to verify the signature against the root certificates included in the two latest TRCs
		// matching the ISD claimed by the signer.
		// The root certificates included in the two latest TRCs might be different.
		// TRC validity (expiration and grace period) has already been checked in spkiCertVerify through `scion-pki`.
		trustAnchorTRC := sortedTRCsPaths[i]
		unvalidatedTopologyPath = filepath.Join(verifyPath, fmt.Sprintf(topologyJSONFileName+".unvalidated%d", i))
		err = verifyWithRootBundle(ctx, signedTopology, unvalidatedTopologyPath, trustAnchorTRC, verifyPath)
		if err == nil {
			break
		}
	}
	if err != nil {
		return err
	}
	// Validate signer IA matches payload IA
	if err = checkTopoIA(unvalidatedTopologyPath, signerIA); err != nil {
		return err
	}
	verifiedTopology := filepath.Join(cfg.SciondConfigDir, topologyJSONFileName)
	err = os.Rename(unvalidatedTopologyPath, verifiedTopology)
	return err
}

func setupVerifyEnv(cfg *config.Config) (ctx context.Context, cancel context.CancelFunc, verifyPath string, err error) {
	// Signature verification should complete in a timely manner since it is a local operation
	ctx, cancel = context.WithTimeout(context.Background(), verifyTimeout)

	// check 'scion-pki' tool is on path and executable
	if err = checkBinary("scion-pki"); err != nil {
		return
	}

	// Create verify directory
	timestamp := time.Now().Unix()
	verifyPath = filepath.Join(cfg.WorkingDir(), fmt.Sprintf("verify-%d", timestamp))
	err = os.Mkdir(verifyPath, 0775)
	if err != nil {
		err = fmt.Errorf("failed to create verify directory: dir: %s, err: %w", verifyPath, err)
		return
	}
	return
}

func checkBinary(execName string) (err error){
	_, err = exec.LookPath(execName)
	return
}

func sortedTRCsPathsByISD(outputPath string, signerTRCid int64) (sortedTRCsPaths []string, err error) {
	trcs, err := getTRCsByISDid(outputPath, signerTRCid)
	if err != nil {
		return
	}
	if len(trcs) == 0 {
		err = fmt.Errorf("unable to verify signature, no valid TRC found in %s,  ISD id: %d",
			outputPath, signerTRCid)
		return
	}
	sortedTRCsPaths = sortTRCsFiles(trcs).Paths()
	return
}

// verifyWithRootBundle verifies the signature of signedTopology, by extracting the root certificates in trustAnchorTRC
// into the verifyPath directory, and write the payload to unvalidatedTopologyPath
func verifyWithRootBundle(ctx context.Context,
	signedTopology, unvalidatedTopologyPath, trustAnchorTRC, verifyPath string) (err error) {

	_, trcFileName := filepath.Split(trustAnchorTRC)
	rootCertsBundlePath := filepath.Join(verifyPath, trcFileName+".certs.pem")
	// extract TRC certificates:
	if err = spkiTRCExtractCerts(ctx, trustAnchorTRC, rootCertsBundlePath); err != nil {
		return fmt.Errorf("unable to extract root certificates from TRC %s: %w",
			trustAnchorTRC, err)
	}
	// verify the signature and certificate chain back to a root certs bundle, write out the payload:
	if err = cmsVerifyOutput(ctx, signedTopology, rootCertsBundlePath, unvalidatedTopologyPath); err != nil {
		return fmt.Errorf("verifying and extracting signed payload failed: %w", err)
	}
	return
}

// extractSignerInfo detaches the signature from signedTopology into the verifyPath directory and
// returns the signerTRCid, signerIA and the path asCertChainPath to a bundle containing the signer and ca certificate.
func extractSignerInfo(ctx context.Context, signedTopology, verifyPath string) (signerTRCid int64,
	signerIA, asCertChainPath string, err error) {

	detachedSignaturePath := filepath.Join(verifyPath, "detached_signature.p7s")
	// detach signature for further validation:
	err = smimePk7out(ctx, signedTopology, detachedSignaturePath)
	if err != nil {
		err = fmt.Errorf("unable to detach signature: %w", err)
		return
	}

	asCertHumanChain := filepath.Join(verifyPath, "as_cert_chain.human.pem")
	// collect included certificates from detached signature:
	err = pkcs7Certs(ctx, detachedSignaturePath, asCertHumanChain)
	if err != nil {
		err = fmt.Errorf("unable to gather included certificates from signature: %w", err)
		return
	}

	// Split signer and CA certificate
	certs, rawCerts, err := getCertsFromBundle(asCertHumanChain)
	if err != nil {
		return
	}
	asCert := certs[0]

	// Store certificate chain extracted from signature
	asCertChainPath = filepath.Join(verifyPath, "as_cert_chain.pem")
	rawASCertChain := strings.Join(rawCerts, "\n")
	_ = os.WriteFile(asCertChainPath, []byte(rawASCertChain), 0666)

	// Get signer information from AS certificate
	signerIA, signerTRCid, err = getCertIA(asCert)
	if err != nil {
		return
	}
	return
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

	var asCert, caCert *x509.Certificate
	var rawCerts []string
	for _, rawCertStr := range matches {
		rawCert := []byte(rawCertStr)
		rawCertPem, _ := pem.Decode(rawCert)
		if rawCertPem != nil {
			rawCert = rawCertPem.Bytes
		}
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse certificates from detached signature: %w", err)
		}
		if cert.IsCA {
			caCert = cert
			rawCerts = append(rawCerts, rawCertStr)
		} else {
			asCert = cert
			rawCerts = append([]string{rawCertStr}, rawCerts...)
		}
	}
	return []*x509.Certificate{asCert, caCert}, rawCerts, nil
}

// verifyTRCUpdateChain verifies the TRC at candidateTRCPath has a valid update chain to the other TRCs of the same ISD.
func verifyTRCUpdateChain(outputPath, candidateTRCPath string, strict bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateChainTimeout)
	defer cancel()
	trc, err := readTRCSummary(candidateTRCPath)
	if err != nil {
		return fmt.Errorf("validating TRC update chain failed: %w", err)
	}
	trcs, err := getTRCsByISDid(outputPath, trc.ID.ISD)
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
	trcUpdateChainPaths = append(trcUpdateChainPaths, candidateTRCPath)
	err = spkiTRCVerify(ctx, trcUpdateChainPaths[0], trcUpdateChainPaths[1:])
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
	trcs, err := filepath.Glob(filepath.Join(outputPath, "certs") + string(os.PathSeparator) + "*.trc")
	if err != nil {
		return nil, err
	}
	var isdTRCs []trcFileSummary
	for _, trcPath := range trcs {
		trc, err := readTRCSummary(trcPath)
		if err != nil {
			log.Error("reading TRC file failed", "path", trcPath, "err", err)
			continue
		}
		if trc.ID.ISD == isdID {
			isdTRCs = append(isdTRCs, trcFileSummary{trc: trc, path: trcPath})
		}
	}
	return isdTRCs, err
}

// sortTRCsFiles sorts the TRC summaries according to their update chain order.
func sortTRCsFiles(trcFileSummaries []trcFileSummary) sortedTRCFileSummaries {
	// sort from lowest TRC ISD ID, base number and serial number to highest, in that order
	sort.Sort(sortedTRCFileSummaries(trcFileSummaries))
	return trcFileSummaries
}

func verifySignature(cfg *config.Config) error {
	// Wipe old temporary directories, except last 10
	err := cleanupVerifyDirs(cfg.WorkingDir())
	if err != nil {
		log.Info("Unable to remove old verify directories", "err", err)
	}

	err = verifyTopologySignature(cfg)
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
		err = os.Remove(filepath.Join(workingDir, d))
		if err != nil {
			log.Info("Unable to remove old verify directory", "err", err)
		}
	}
	return nil
}

// readTRCSummary returns the trcSummary with ISD, serial and base number information for a pem encoded or TRC blob.
func readTRCSummary(filePath string) (trcSummary, error) {
	rawTRC, err := os.ReadFile(filePath)
	if err != nil {
		return trcSummary{}, fmt.Errorf("reading TRC file failed: %w", err)
	}
	trcPem, _ := pem.Decode(rawTRC)
	if trcPem != nil && trcPem.Type == "TRC" {
		rawTRC = trcPem.Bytes
	}
	var rawTRCSigned trcContainer
	_, err = asn1.Unmarshal(rawTRC, &rawTRCSigned)
	if err != nil {
		return trcSummary{}, fmt.Errorf("failed to parse trc container: %w", err)
	}

	if !rawTRCSigned.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return trcSummary{}, fmt.Errorf("wrong trc signed data content type")
	}
	var trcSignedData trcSignedData
	_, err = asn1.Unmarshal(rawTRCSigned.Content.Bytes, &trcSignedData)
	if err != nil {
		return trcSummary{}, fmt.Errorf("failed to parse trc signed data: %w", err)
	}
	var trcContent asn1.RawValue
	_, err = asn1.Unmarshal(trcSignedData.EncapContentInfo.EContent.Bytes, &trcContent)
	if err != nil {
		return trcSummary{}, fmt.Errorf("failed to parse trc encap content data: %w", err)
	}

	var trcSummary trcSummary
	_, err = asn1.Unmarshal(trcContent.Bytes, &trcSummary)
	if err != nil {
		return trcSummary, fmt.Errorf("parsing TRC ID failed: %w", err)
	}
	return trcSummary, nil
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

type topoIA struct {
	IA string `json:"isd_as"`
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
