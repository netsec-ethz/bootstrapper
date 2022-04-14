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
	log "github.com/inconshreveable/log15"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// reuse test vectors from SCIONLab:
// https://github.com/netsec-ethz/scionlab/blob/develop/scionlab/tests/data/test_config_tar/

var isd17B1S1trc = `-----BEGIN TRC-----
MIIMDwYJKoZIhvcNAQcCoIIMADCCC/wCAQExDzANBglghkgBZQMEAgMFADCCCHMG
CSqGSIb3DQEHAaCCCGQEgghgMIIIXAIBADAJAgERAgEBAgEBMCIYDzIwMjExMDA2
MTIyNTUyWhgPMjAyMzEwMDYxMjI1NTFaAgEAAQEAMAACAQEwDRMLZmZhYTowOjEx
MDEwDRMLZmZhYTowOjExMDEMF1NDSU9OTGFiIFRSQyBmb3IgSVNEIDE3MIIH5DCC
ApEwggI3oAMCAQICFGZKDbQBJIsSYPrCclG8NkMH13qoMAoGCCqGSM49BAMEMIGl
MQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgxEDAOBgNVBAcMB1rDvHJpY2gxDzAN
BgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0c2VjMTQwMgYDVQQDDCsxNy1mZmFh
OjA6MTEwMSBTZW5zaXRpdmUgVm90aW5nIENlcnRpZmljYXRlMR8wHQYLKwYBBAGD
sBwBAgEMDjE3LWZmYWE6MDoxMTAxMB4XDTIxMTAwNjEyMjU1MloXDTIzMTAwNjEy
MjU1MlowgaUxCzAJBgNVBAYTAkNIMQswCQYDVQQIDAJaSDEQMA4GA1UEBwwHWsO8
cmljaDEPMA0GA1UECgwGTmV0c2VjMQ8wDQYDVQQLDAZOZXRzZWMxNDAyBgNVBAMM
KzE3LWZmYWE6MDoxMTAxIFNlbnNpdGl2ZSBWb3RpbmcgQ2VydGlmaWNhdGUxHzAd
BgsrBgEEAYOwHAECAQwOMTctZmZhYTowOjExMDEwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATfYQ9Emz/hyjygE9Ijayr17V+cEakXPYeId0kaiMgSKoQ/9m3rF1Ql
JaVumtrCiEsZSuPUyw7tVpewcvY+USi4o0MwQTAdBgNVHQ4EFgQUvt/0bWH4pg6W
ywbu4ZvqIlOFaXgwIAYDVR0lBBkwFwYLKwYBBAGDsBwBAwEGCCsGAQUFBwMIMAoG
CCqGSM49BAMEA0gAMEUCIQCB9H0vy4yChfuuKwWAg5l4JerJDzzp7HKjjSEKgyWQ
BAIgXQKpYOQsalkxq5y3irO6UdbDZUnGhI3PtSwZwZ8fMc4wggKNMIICM6ADAgEC
AhQsPo1qERfbrI4Zp40yJFV4qNxvMjAKBggqhkjOPQQDBDCBozELMAkGA1UEBhMC
Q0gxCzAJBgNVBAgMAlpIMRAwDgYDVQQHDAdaw7xyaWNoMQ8wDQYDVQQKDAZOZXRz
ZWMxDzANBgNVBAsMBk5ldHNlYzEyMDAGA1UEAwwpMTctZmZhYTowOjExMDEgUmVn
dWxhciBWb3RpbmcgQ2VydGlmaWNhdGUxHzAdBgsrBgEEAYOwHAECAQwOMTctZmZh
YTowOjExMDEwHhcNMjExMDA2MTIyNTUyWhcNMjMxMDA2MTIyNTUyWjCBozELMAkG
A1UEBhMCQ0gxCzAJBgNVBAgMAlpIMRAwDgYDVQQHDAdaw7xyaWNoMQ8wDQYDVQQK
DAZOZXRzZWMxDzANBgNVBAsMBk5ldHNlYzEyMDAGA1UEAwwpMTctZmZhYTowOjEx
MDEgUmVndWxhciBWb3RpbmcgQ2VydGlmaWNhdGUxHzAdBgsrBgEEAYOwHAECAQwO
MTctZmZhYTowOjExMDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASc/1eDIL/m
redZbfXIhh2sTnzYJz00SF717wi5Jwf+vr5ljqtbbbIeVAyWJ8koV1ZbcSRqCLXy
wYdLbEKHf65Do0MwQTAdBgNVHQ4EFgQU1RaF8vMPCZNRmsdF8LZOo7w6VwwwIAYD
VR0lBBkwFwYLKwYBBAGDsBwBAwIGCCsGAQUFBwMIMAoGCCqGSM49BAMEA0gAMEUC
IGqVOT/djhHdVvwnCU1hiHFEQwJsK+xxDDrJyC20+eqUAiEA/H+Fjc4j3FpB/67Q
2UetL3pln4lLNV6Ddr3UfrGTipkwggK6MIICX6ADAgECAhQGPF2Qb3JrKsLtTv/O
tnsQNL+BtjAKBggqhkjOPQQDBDCBpzELMAkGA1UEBhMCQ0gxCzAJBgNVBAgMAlpI
MRAwDgYDVQQHDAdaw7xyaWNoMQ8wDQYDVQQKDAZOZXRzZWMxDzANBgNVBAsMBk5l
dHNlYzE2MDQGA1UEAwwtMTctZmZhYTowOjExMDEgSGlnaCBTZWN1cml0eSBSb290
IENlcnRpZmljYXRlMR8wHQYLKwYBBAGDsBwBAgEMDjE3LWZmYWE6MDoxMTAxMB4X
DTIxMTAwNjEyMjU1MloXDTIzMTAwNjEyMjU1MlowgacxCzAJBgNVBAYTAkNIMQsw
CQYDVQQIDAJaSDEQMA4GA1UEBwwHWsO8cmljaDEPMA0GA1UECgwGTmV0c2VjMQ8w
DQYDVQQLDAZOZXRzZWMxNjA0BgNVBAMMLTE3LWZmYWE6MDoxMTAxIEhpZ2ggU2Vj
dXJpdHkgUm9vdCBDZXJ0aWZpY2F0ZTEfMB0GCysGAQQBg7AcAQIBDA4xNy1mZmFh
OjA6MTEwMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAWnZwUPtgWMWN+4+pyP
lOj6lQxO3mwG4kId7OR6JivhzXhGrr0i5mu/Pk/OURbiE6tFtsQiiU1p3y3+6FvR
1QyjZzBlMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMB0GA1Ud
DgQWBBTgw3sBAs4Pv6enakjeGGtTbtRF0TAgBgNVHSUEGTAXBgsrBgEEAYOwHAED
AwYIKwYBBQUHAwgwCgYIKoZIzj0EAwQDSQAwRgIhAIAcsrtsfkmmbdShQ9rC6hkC
R6wXdhwbv8VaaN/e6P0CAiEAisapnWgBEnrMVKMORtHHsL5V2UgKGetHjn7ThPBQ
M/0xggNtMIIBsQIBATCBvDCBozELMAkGA1UEBhMCQ0gxCzAJBgNVBAgMAlpIMRAw
DgYDVQQHDAdaw7xyaWNoMQ8wDQYDVQQKDAZOZXRzZWMxDzANBgNVBAsMBk5ldHNl
YzEyMDAGA1UEAwwpMTctZmZhYTowOjExMDEgUmVndWxhciBWb3RpbmcgQ2VydGlm
aWNhdGUxHzAdBgsrBgEEAYOwHAECAQwOMTctZmZhYTowOjExMDECFCw+jWoRF9us
jhmnjTIkVXio3G8yMA0GCWCGSAFlAwQCAwUAoIGJMBgGCSqGSIb3DQEJAzELBgkq
hkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMTAwNjEyMjU1MlowTwYJKoZIhvcN
AQkEMUIEQLqNciXLnXoglyCNndLw76BIAxyk5ERzykDVtfHu86AOeR0q+ium9edf
RUv5BQkSBvdj9AJf7X8PMBSqiA3mgHAwCgYIKoZIzj0EAwQERjBEAiAOAXF2nU9z
rlh6t6ARiwvC1xjRjOD7GvF+4rZjzp3mNQIgKu/3Kp7mDkRF5fvgMU9/6AKxi9ba
w8SOi8RtJOPL+aowggG0AgEBMIG+MIGlMQswCQYDVQQGEwJDSDELMAkGA1UECAwC
WkgxEDAOBgNVBAcMB1rDvHJpY2gxDzANBgNVBAoMBk5ldHNlYzEPMA0GA1UECwwG
TmV0c2VjMTQwMgYDVQQDDCsxNy1mZmFhOjA6MTEwMSBTZW5zaXRpdmUgVm90aW5n
IENlcnRpZmljYXRlMR8wHQYLKwYBBAGDsBwBAgEMDjE3LWZmYWE6MDoxMTAxAhRm
Sg20ASSLEmD6wnJRvDZDB9d6qDANBglghkgBZQMEAgMFAKCBiTAYBgkqhkiG9w0B
CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMTEwMDYxMjI1NTJaME8G
CSqGSIb3DQEJBDFCBEC6jXIly516IJcgjZ3S8O+gSAMcpOREc8pA1bXx7vOgDnkd
KvorpvXnX0VL+QUJEgb3Y/QCX+1/DzAUqogN5oBwMAoGCCqGSM49BAMEBEcwRQIh
AId+90b54IZxMPxKvJVRzN+wDz6l92Rq6IfotDF7blAnAiAs8/ZNlxymdSehL/Sp
VqSiHiMvXCXTvPPXPAys1b0EFw==
-----END TRC-----`

var isd17ASffaa_0_1101CAcrt = `-----BEGIN CERTIFICATE-----
MIICsDCCAlWgAwIBAgIUT9QuzhrVR+1POaK2wWizNABrEGUwCgYIKoZIzj0EAwQw
gacxCzAJBgNVBAYTAkNIMQswCQYDVQQIDAJaSDEQMA4GA1UEBwwHWsO8cmljaDEP
MA0GA1UECgwGTmV0c2VjMQ8wDQYDVQQLDAZOZXRzZWMxNjA0BgNVBAMMLTE3LWZm
YWE6MDoxMTAxIEhpZ2ggU2VjdXJpdHkgUm9vdCBDZXJ0aWZpY2F0ZTEfMB0GCysG
AQQBg7AcAQIBDA4xNy1mZmFhOjA6MTEwMTAeFw0yMTEwMDYxMjI1NTJaFw0yMzEw
MDYxMjI1NTJaMIGeMQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgxEDAOBgNVBAcM
B1rDvHJpY2gxDzANBgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0c2VjMS0wKwYD
VQQDDCQxNy1mZmFhOjA6MTEwMSBTZWN1cmUgQ0EgQ2VydGlmaWNhdGUxHzAdBgsr
BgEEAYOwHAECAQwOMTctZmZhYTowOjExMDEwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAASKLMjlvW15Q5MHamAEQZ/EtbDKV6N58IkBvBPGJ2faCCGr4h+sW8iUW3tw
ie6J+y84O+1sL2uZAbsTVRYCtUL3o2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4G
A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUNNYmuhhGSEw+qIDlgMMEGQ5P7i4wHwYD
VR0jBBgwFoAU4MN7AQLOD7+np2pI3hhrU27URdEwCgYIKoZIzj0EAwQDSQAwRgIh
AIyt8UTBKTWCQZciUWqUhZfJsJrXKeuPtIjFt8lQGPGjAiEAtJpFS3b3Czyn3FN8
3RxiFr644HOEhrsTA5tcBnTM5Fg=
-----END CERTIFICATE-----`

var isd17ASffaa_1_1aspem = `-----BEGIN CERTIFICATE-----
MIICrjCCAlSgAwIBAgIUQD+itCyOkKJwAPTOY6Zh8GpruQ0wCgYIKoZIzj0EAwQw
gZ4xCzAJBgNVBAYTAkNIMQswCQYDVQQIDAJaSDEQMA4GA1UEBwwHWsO8cmljaDEP
MA0GA1UECgwGTmV0c2VjMQ8wDQYDVQQLDAZOZXRzZWMxLTArBgNVBAMMJDE3LWZm
YWE6MDoxMTAxIFNlY3VyZSBDQSBDZXJ0aWZpY2F0ZTEfMB0GCysGAQQBg7AcAQIB
DA4xNy1mZmFhOjA6MTEwMTAeFw0yMTEwMDYxMjI1NTRaFw0yMjEwMDYxMjI1NTRa
MIGRMQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgxEDAOBgNVBAcMB1rDvHJpY2gx
DzANBgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0c2VjMSMwIQYDVQQDDBoxNy1m
ZmFhOjE6MSBBUyBDZXJ0aWZpY2F0ZTEcMBoGCysGAQQBg7AcAQIBDAsxNy1mZmFh
OjE6MTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABH9Ai13zQwdebPFEPoVxuRJ2
A8s9Q/oM+K0nBmUPjFPhPRjGExUIZS146b/wkDPfOrH6WgMmjBAjrAS+Tif88lCj
ezB5MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUOpKlpPIl37u4sXKLzXH+OteO
ovYwHwYDVR0jBBgwFoAUNNYmuhhGSEw+qIDlgMMEGQ5P7i4wJwYDVR0lBCAwHgYI
KwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDCDAKBggqhkjOPQQDBANIADBFAiEA
1YErvCqXixVjcERpummNCZhwVeta8hYhIpdJNqctgqgCIEQdyQeZmYWFIBC30dV3
x/qeYi8mVb5pxB/E2LRrBDE0
-----END CERTIFICATE-----
`

var isd17ASffaa_1_1cpASkey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXxoGe3zZJinUpIlu
BoOsiiIP6du8N9hEQNeKckjLVw6hRANCAAR/QItd80MHXmzxRD6FcbkSdgPLPUP6
DPitJwZlD4xT4T0YxhMVCGUteOm/8JAz3zqx+loDJowQI6wEvk4n/PJQ
-----END PRIVATE KEY-----`

var payload = `{
  "attributes": [],
  "border_routers": {
    "br-1": {
      "interfaces": {
        "1": {
          "isd_as": "17-ffaa:0:1107",
          "link_to": "PARENT",
          "mtu": 1472,
          "underlay": {
            "public": "10.0.0.1:54321",
            "remote": "10.0.8.1:50001"
          }
        }
      },
      "internal_addr": "127.0.0.1:30001"
    }
  },
  "colibri_service": {
    "co-1": {
      "addr": "127.0.0.1:30257"
    }
  },
  "control_service": {
    "cs-1": {
      "addr": "127.0.0.1:30254"
    }
  },
  "discovery_service": {
    "ds-1": {
      "addr": "127.0.0.1:30254"
    }
  },
  "isd_as": "17-ffaa:1:1",
  "mtu": 1472,
  "sigs": {
    "sig-1": {
      "ctrl_addr": "127.0.0.1:30256",
      "data_addr": "127.0.0.1:30056"
    }
  }
}`

func TestVerify(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bootstrapper-cppki-tests_*")
	if err != nil {
		log.Error("Failed to create test directory for testrun", "dir", tmpDir, "err", err)
	}

	// Generate signed payload
	signPath := filepath.Join(tmpDir, "sign")
	err = os.MkdirAll(signPath, 0775)
	if err != nil {
		log.Error("Failed to create sign test directory for testrun", "dir", signPath, "err", err)
	}
	// Dump files payload, isd17ASffaa_0_1101CAcrt, isd17ASffaa_1_1aspem, isd17ASffaa_1_1cpASkey to directory sign
	files := map[string]string{
		"payload":                    payload,
		"ISD17-ASffaa_0_1101.ca.crt": isd17ASffaa_0_1101CAcrt,
		"ISD17-ASffaa_1_1.as.pem":    isd17ASffaa_1_1aspem,
		"ISD17-ASffaa_1_1.cp.as.key": isd17ASffaa_1_1cpASkey}
	for fileName, fileContent := range files {
		filePath := filepath.Join(signPath, fileName)
		err = os.WriteFile(filePath, []byte(fileContent), 0666)
		if err != nil {
			log.Error("Failed writing files required for signing", "signPath", signPath, "err", err)
		}
	}
	payloadPath := filepath.Join(signPath, "payload")
	signedPayloadPath := filepath.Join(signPath, "payload.signed")
	asKeyPath := filepath.Join(signPath, "ISD17-ASffaa_1_1.cp.as.key")
	asCertPath := filepath.Join(signPath, "ISD17-ASffaa_1_1.as.pem")
	caCertPath := filepath.Join(signPath, "ISD17-ASffaa_0_1101.ca.crt")
	err = exec.Command("openssl", "cms", "-sign", "-text",
		"-in", payloadPath, "-out", signedPayloadPath, "-inkey", asKeyPath,
		"-signer", asCertPath, "-certfile", caCertPath).Run()
	if err != nil {
		log.Error("Failed create signed file", "signedPayloadPath", signedPayloadPath, "err", err)
	}

	// Verify signed payload
	bootstrapperPath := filepath.Join(tmpDir, "bootstrapper")
	err = os.MkdirAll(bootstrapperPath, 0775)
	if err != nil {
		log.Error("Failed to create bootstrapper test directory for testrun",
			"dir", bootstrapperPath, "err", err)
	}
	// copy payload.signed and dump isd17sB1S1trc to output directory
	signedPayload, err := os.Open(signedPayloadPath)
	if err != nil {
		log.Error("Failed copying signed payload", "err", err)
	}
	defer signedPayload.Close()
	payloadPath = filepath.Join(bootstrapperPath, "topology.signed")
	payloadFile, err := os.Create(payloadPath)
	if err != nil {
		log.Error("Failed copying signed payload", "err", err)
	}
	defer payloadFile.Close()
	_, err = io.Copy(payloadFile, signedPayload)
	if err != nil {
		log.Error("Failed copying signed payload", "err", err)
	}
	err = payloadFile.Sync()
	if err != nil {
		log.Error("Failed copying signed payload", "err", err)
	}
	trcsPath := filepath.Join(tmpDir, "certs")
	err = os.MkdirAll(trcsPath, 0775)
	if err != nil {
		log.Error("Failed to create certs test directory for testrun", "dir", tmpDir, "err", err)
	}
	trcPath := filepath.Join(trcsPath, "ISD17-B1-S1.trc")
	err = os.WriteFile(trcPath, []byte(isd17B1S1trc), 0666)
	if err != nil {
		log.Error("Failed writing TRC file", "err", err)
	}

	// run the actual test, verifying the signature using the signed topology
	if err := verifyTopologySignature(tmpDir, bootstrapperPath); err != nil {
		log.Error("Signature verification failed: verifyTopologySignature", "err", err)
		t.FailNow()
	}
}

func TestExtractSignerInfo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bootstrapper-cppki-tests_*")
	if err != nil {
		log.Error("Failed to create test directory for testrun", "dir", tmpDir, "err", err)
	}
	// Dump files payload, isd17ASffaa_0_1101CAcrt, isd17ASffaa_1_1aspem, isd17ASffaa_1_1cpASkey to directory sign
	files := map[string]string{
		"payload":                    payload,
		"ISD17-ASffaa_0_1101.ca.crt": isd17ASffaa_0_1101CAcrt,
		"ISD17-ASffaa_1_1.as.pem":    isd17ASffaa_1_1aspem,
		"ISD17-ASffaa_1_1.cp.as.key": isd17ASffaa_1_1cpASkey}
	for fileName, fileContent := range files {
		filePath := filepath.Join(tmpDir, fileName)
		err = os.WriteFile(filePath, []byte(fileContent), 0666)
		if err != nil {
			log.Error("Failed writing files required for signing", "signPath", tmpDir, "err", err)
		}
	}
	payloadPath := filepath.Join(tmpDir, "payload")
	signedPayloadPath := filepath.Join(tmpDir, "payload.signed")
	asKeyPath := filepath.Join(tmpDir, "ISD17-ASffaa_1_1.cp.as.key")
	asCertPath := filepath.Join(tmpDir, "ISD17-ASffaa_1_1.as.pem")
	caCertPath := filepath.Join(tmpDir, "ISD17-ASffaa_0_1101.ca.crt")
	err = exec.Command("openssl", "cms", "-sign", "-text",
		"-in", payloadPath, "-out", signedPayloadPath, "-inkey", asKeyPath,
		"-signer", asCertPath, "-certfile", caCertPath).Run()
	if err != nil {
		log.Error("Failed to create signed file", "signedPayloadPath", signedPayloadPath, "err", err)
	}
	signerTRCid, signerIA, asCertChainPath, err := extractSignerInfo(context.TODO(), signedPayloadPath, tmpDir)
	if err != nil {
		log.Error("Getting signer info failed: extractSignerInfo", "err", err)
		t.FailNow()
	}
	if signerTRCid != 17 {
		log.Error("signerTRCid mismatch", "expected", 1, "actual", signerTRCid)
		t.FailNow()
	}
	if signerIA != "17-ffaa:1:1" {
		log.Error("signerTRCid mismatch", "expected", "", "actual", signerIA)
		t.FailNow()
	}
	if asCertChainPath != filepath.Join(tmpDir, "as_cert_chain.pem") {
		log.Error("signerTRCid mismatch",
			"expected",  filepath.Join(tmpDir, "as_cert_chain.pem"), "actual", asCertChainPath)
		t.FailNow()
	}
	return
}
