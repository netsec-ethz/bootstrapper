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

	"github.com/netsec-ethz/bootstrapper/config"
)

// reuse test vectors from SCIONLab:
// https://github.com/netsec-ethz/scionlab/blob/develop/scionlab/tests/data/test_config_tar/

var isd17B1S1trc = `-----BEGIN TRC-----
MIIMDgYJKoZIhvcNAQcCoIIL/zCCC/sCAQExDzANBglghkgBZQMEAgMFADCCCHAG
CSqGSIb3DQEHAaCCCGEEgghdMIIIWQIBADAJAgERAgEBAgEBMCIYDzIwMjQwNzIy
MTE0ODQyWhgPMjAyNjA3MjIxMTQ4NDFaAgEAAQEAMAACAQEwDRMLZmZhYTowOjEx
MDEwDRMLZmZhYTowOjExMDEMF1NDSU9OTGFiIFRSQyBmb3IgSVNEIDE3MIIH4TCC
ApEwggI3oAMCAQICFD/uqgmbefTm3rDU6n/cAZBz0BahMAoGCCqGSM49BAMEMIGl
MQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgxEDAOBgNVBAcMB1rDvHJpY2gxDzAN
BgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0c2VjMTQwMgYDVQQDDCsxNy1mZmFh
OjA6MTEwMSBTZW5zaXRpdmUgVm90aW5nIENlcnRpZmljYXRlMR8wHQYLKwYBBAGD
sBwBAgEMDjE3LWZmYWE6MDoxMTAxMB4XDTI0MDcyMjExNDg0MloXDTI2MDcyMjEx
NDg0MlowgaUxCzAJBgNVBAYTAkNIMQswCQYDVQQIDAJaSDEQMA4GA1UEBwwHWsO8
cmljaDEPMA0GA1UECgwGTmV0c2VjMQ8wDQYDVQQLDAZOZXRzZWMxNDAyBgNVBAMM
KzE3LWZmYWE6MDoxMTAxIFNlbnNpdGl2ZSBWb3RpbmcgQ2VydGlmaWNhdGUxHzAd
BgsrBgEEAYOwHAECAQwOMTctZmZhYTowOjExMDEwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATEslNjz8+I7EQHKM1o9ynDzwJ/wAbxBxKNK4HmFxcFCIB4DMpNVQUe
wWH9MNwpDas34Dxi+hhIi2yhgs92TAUSo0MwQTAdBgNVHQ4EFgQUHgkGE9ipB5tV
kM4b+EsOGdpq0sAwIAYDVR0lBBkwFwYLKwYBBAGDsBwBAwEGCCsGAQUFBwMIMAoG
CCqGSM49BAMEA0gAMEUCIF7gmxlMGuTy/nCwh0OYwodo/m0soyTL4+lzIJg34EcF
AiEA7vSOy5pC4mlJvx3ylw9Ufjz5i1RTsX6n7uN9t4yDQEMwggKMMIICM6ADAgEC
AhR/+zvWBOCGn/dj2sxtAke00F6EwzAKBggqhkjOPQQDBDCBozELMAkGA1UEBhMC
Q0gxCzAJBgNVBAgMAlpIMRAwDgYDVQQHDAdaw7xyaWNoMQ8wDQYDVQQKDAZOZXRz
ZWMxDzANBgNVBAsMBk5ldHNlYzEyMDAGA1UEAwwpMTctZmZhYTowOjExMDEgUmVn
dWxhciBWb3RpbmcgQ2VydGlmaWNhdGUxHzAdBgsrBgEEAYOwHAECAQwOMTctZmZh
YTowOjExMDEwHhcNMjQwNzIyMTE0ODQyWhcNMjYwNzIyMTE0ODQyWjCBozELMAkG
A1UEBhMCQ0gxCzAJBgNVBAgMAlpIMRAwDgYDVQQHDAdaw7xyaWNoMQ8wDQYDVQQK
DAZOZXRzZWMxDzANBgNVBAsMBk5ldHNlYzEyMDAGA1UEAwwpMTctZmZhYTowOjEx
MDEgUmVndWxhciBWb3RpbmcgQ2VydGlmaWNhdGUxHzAdBgsrBgEEAYOwHAECAQwO
MTctZmZhYTowOjExMDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATIllIQkrsB
I7uTANbKCcADgARoR4TNdGad0k7mPI/SOkqausJbqFb+GECFnl6SHzQCY6PWKF+8
7Jk9DbWZppQBo0MwQTAdBgNVHQ4EFgQUCgjYDnQesw9VXyn4gtdeJ6q1br0wIAYD
VR0lBBkwFwYLKwYBBAGDsBwBAwIGCCsGAQUFBwMIMAoGCCqGSM49BAMEA0cAMEQC
ICTFZiY8F70Tvqv9CZJBC5qFnZ5TBHbyK4Yle5CmHLJDAiAJHGe66iMLbBGWYTG0
s0Wh9gl6mHD9PQO2tCHJ4peBWDCCArgwggJfoAMCAQICFHzBGsi9zM4v2Xchm3f1
NehBBj4aMAoGCCqGSM49BAMEMIGnMQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgx
EDAOBgNVBAcMB1rDvHJpY2gxDzANBgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0
c2VjMTYwNAYDVQQDDC0xNy1mZmFhOjA6MTEwMSBIaWdoIFNlY3VyaXR5IFJvb3Qg
Q2VydGlmaWNhdGUxHzAdBgsrBgEEAYOwHAECAQwOMTctZmZhYTowOjExMDEwHhcN
MjQwNzIyMTE0ODQyWhcNMjYwNzIyMTE0ODQyWjCBpzELMAkGA1UEBhMCQ0gxCzAJ
BgNVBAgMAlpIMRAwDgYDVQQHDAdaw7xyaWNoMQ8wDQYDVQQKDAZOZXRzZWMxDzAN
BgNVBAsMBk5ldHNlYzE2MDQGA1UEAwwtMTctZmZhYTowOjExMDEgSGlnaCBTZWN1
cml0eSBSb290IENlcnRpZmljYXRlMR8wHQYLKwYBBAGDsBwBAgEMDjE3LWZmYWE6
MDoxMTAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWfsOTofp8w50kcmctdEB
viMxyWxRF8srSORFWHvj82sZKIhAszNb9V7l1t0PXyii93rX/PjPMJYI+fJiXCZB
x6NnMGUwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0O
BBYEFB5joICvEb/gRBbLvdAOvl9xMC0MMCAGA1UdJQQZMBcGCysGAQQBg7AcAQMD
BggrBgEFBQcDCDAKBggqhkjOPQQDBANHADBEAiAnDYoEvokvrFnusIOJ726VPazg
3dG7Eh9DNjkLPQ5/QQIgT34EY+b6zaFowChsVNYApAYvb8wIAsErjUf7lKEKL2cx
ggNvMIIBsgIBATCBvDCBozELMAkGA1UEBhMCQ0gxCzAJBgNVBAgMAlpIMRAwDgYD
VQQHDAdaw7xyaWNoMQ8wDQYDVQQKDAZOZXRzZWMxDzANBgNVBAsMBk5ldHNlYzEy
MDAGA1UEAwwpMTctZmZhYTowOjExMDEgUmVndWxhciBWb3RpbmcgQ2VydGlmaWNh
dGUxHzAdBgsrBgEEAYOwHAECAQwOMTctZmZhYTowOjExMDECFH/7O9YE4Iaf92Pa
zG0CR7TQXoTDMA0GCWCGSAFlAwQCAwUAoIGJMBgGCSqGSIb3DQEJAzELBgkqhkiG
9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI0MDcyMjExNDg0MlowTwYJKoZIhvcNAQkE
MUIEQL9c/KH+dti9iUPhyYH12CTTFSvy2kKDNS3+AlfhwzmoNlef0krV04/qQXaF
ax4IERuwh/VnseBEKeZTUf/diYEwCgYIKoZIzj0EAwQERzBFAiEApwJf+lE3zvJv
ty98jgMHpygiZDAIjXKmDJT0jZo4H1ICIEtou8HXZtpS1WJR24lqqNWNjoLUt5nj
6Equpiu8sp7cMIIBtQIBATCBvjCBpTELMAkGA1UEBhMCQ0gxCzAJBgNVBAgMAlpI
MRAwDgYDVQQHDAdaw7xyaWNoMQ8wDQYDVQQKDAZOZXRzZWMxDzANBgNVBAsMBk5l
dHNlYzE0MDIGA1UEAwwrMTctZmZhYTowOjExMDEgU2Vuc2l0aXZlIFZvdGluZyBD
ZXJ0aWZpY2F0ZTEfMB0GCysGAQQBg7AcAQIBDA4xNy1mZmFhOjA6MTEwMQIUP+6q
CZt59ObesNTqf9wBkHPQFqEwDQYJYIZIAWUDBAIDBQCggYkwGAYJKoZIhvcNAQkD
MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjQwNzIyMTE0ODQyWjBPBgkq
hkiG9w0BCQQxQgRAv1z8of522L2JQ+HJgfXYJNMVK/LaQoM1Lf4CV+HDOag2V5/S
StXTj+pBdoVrHggRG7CH9Wex4EQp5lNR/92JgTAKBggqhkjOPQQDBARIMEYCIQCw
S9WE48jwNLqW06cFzhOPpRBhGAeyp6bX0+iTO8yjbwIhALYTnkLzmEjk5sWl0jSf
VgVqDErwS+kG7NSSQ4iYzgxM
-----END TRC-----`

var isd17ASffaa_0_1101CAcrt = `-----BEGIN CERTIFICATE-----
MIICrzCCAlWgAwIBAgIUTdevyKSS1VO3LrNZrJ7oJ+QgrmgwCgYIKoZIzj0EAwQw
gacxCzAJBgNVBAYTAkNIMQswCQYDVQQIDAJaSDEQMA4GA1UEBwwHWsO8cmljaDEP
MA0GA1UECgwGTmV0c2VjMQ8wDQYDVQQLDAZOZXRzZWMxNjA0BgNVBAMMLTE3LWZm
YWE6MDoxMTAxIEhpZ2ggU2VjdXJpdHkgUm9vdCBDZXJ0aWZpY2F0ZTEfMB0GCysG
AQQBg7AcAQIBDA4xNy1mZmFhOjA6MTEwMTAeFw0yNDA3MjIxMTQ4NDJaFw0yNjA3
MjIxMTQ4NDJaMIGeMQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgxEDAOBgNVBAcM
B1rDvHJpY2gxDzANBgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0c2VjMS0wKwYD
VQQDDCQxNy1mZmFhOjA6MTEwMSBTZWN1cmUgQ0EgQ2VydGlmaWNhdGUxHzAdBgsr
BgEEAYOwHAECAQwOMTctZmZhYTowOjExMDEwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARhVXWu18dA+MgaZTCx/VM7vaeLYYjOyOxFTZdb7l4dAYYc5LZkXENoJ8pU
jmZCKXCpHhkhgnIpWqCwIt0FeLz9o2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4G
A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUu1K5rwKbsos1r3rvRl/G3NXVmLcwHwYD
VR0jBBgwFoAUHmOggK8Rv+BEFsu90A6+X3EwLQwwCgYIKoZIzj0EAwQDSAAwRQIh
AKTEUa4imwBZ+CBzfEqeL1ZJv5NWujGgVASBHXE+mEr4AiAaebLtTX7+rLgj81aS
13br6BlaEnQlsiZnxibTuPAd7A==
-----END CERTIFICATE-----`

var isd17ASffaa_0_1101aspem = `-----BEGIN CERTIFICATE-----
MIICtTCCAlqgAwIBAgIUOVv660twJ/eYaKOsOg2RzitpHc4wCgYIKoZIzj0EAwQw
gZ4xCzAJBgNVBAYTAkNIMQswCQYDVQQIDAJaSDEQMA4GA1UEBwwHWsO8cmljaDEP
MA0GA1UECgwGTmV0c2VjMQ8wDQYDVQQLDAZOZXRzZWMxLTArBgNVBAMMJDE3LWZm
YWE6MDoxMTAxIFNlY3VyZSBDQSBDZXJ0aWZpY2F0ZTEfMB0GCysGAQQBg7AcAQIB
DA4xNy1mZmFhOjA6MTEwMTAeFw0yNDA3MjIxMTQ4NDJaFw0yNTA3MjIxMTQ4NDJa
MIGXMQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgxEDAOBgNVBAcMB1rDvHJpY2gx
DzANBgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0c2VjMSYwJAYDVQQDDB0xNy1m
ZmFhOjA6MTEwMSBBUyBDZXJ0aWZpY2F0ZTEfMB0GCysGAQQBg7AcAQIBDA4xNy1m
ZmFhOjA6MTEwMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDIMOw7O/PgoJtXY
JwBop/NYrnqIDfTPKj3E6G5uOnBxhvY4mo+1GB6VgI1boBvVliXAVSfM7RMS2763
iwiMys+jezB5MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUyRyKkoeOfA6+JLHd
skjJ2RSOPucwHwYDVR0jBBgwFoAUu1K5rwKbsos1r3rvRl/G3NXVmLcwJwYDVR0l
BCAwHgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDCDAKBggqhkjOPQQDBANJ
ADBGAiEAwqKO0vU3f+pq3PfH3t2DwZACgnMLIxAe2XLNMy12lIsCIQCMdSg78v9O
961vFunX4kWAqiaVNGe5vQV5Pz2AWM+FMw==
-----END CERTIFICATE-----
`

var isd17ASffaa_0_1101cpASkey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkd1/PwHX8+P8Crr4
vS/xUhH2K4nt9l4xFAuwzrZ6aIehRANCAAQyDDsOzvz4KCbV2CcAaKfzWK56iA30
zyo9xOhubjpwcYb2OJqPtRgelYCNW6Ab1ZYlwFUnzO0TEtu+t4sIjMrP
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
  "isd_as": "17-ffaa:0:1101",
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
	// Dump files payload, isd17ASffaa_0_1101CAcrt, isd17ASffaa_0_1101aspem, isd17ASffaa_0_1101cpASkey to directory sign
	files := map[string]string{
		"payload":                    payload,
		"ISD17-ASffaa_0_1101.ca.crt": isd17ASffaa_0_1101CAcrt,
		"ISD17-ASffaa_0_1101.as.pem":    isd17ASffaa_0_1101aspem,
		"ISD17-ASffaa_0_1101.cp.as.key": isd17ASffaa_0_1101cpASkey}
	for fileName, fileContent := range files {
		filePath := filepath.Join(signPath, fileName)
		err = os.WriteFile(filePath, []byte(fileContent), 0666)
		if err != nil {
			log.Error("Failed writing files required for signing", "signPath", signPath, "err", err)
		}
	}
	payloadPath := filepath.Join(signPath, "payload")
	signedPayloadPath := filepath.Join(signPath, "payload.signed")
	asKeyPath := filepath.Join(signPath, "ISD17-ASffaa_0_1101.cp.as.key")
	asCertPath := filepath.Join(signPath, "ISD17-ASffaa_0_1101.as.pem")
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
	if err := verifyTopologySignature(&config.Config{SciondConfigDir: tmpDir, CryptoEngine: "openssl"}); err != nil {
		log.Error("Signature verification failed: verifyTopologySignature", "err", err)
		t.FailNow()
	}
}

func TestExtractSignerInfo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bootstrapper-cppki-tests_*")
	if err != nil {
		log.Error("Failed to create test directory for testrun", "dir", tmpDir, "err", err)
	}
	// Dump files payload, isd17ASffaa_0_1101CAcrt, isd17ASffaa_0_1101aspem, isd17ASffaa_0_1101cpASkey to directory sign
	files := map[string]string{
		"payload":                    payload,
		"ISD17-ASffaa_0_1101.ca.crt": isd17ASffaa_0_1101CAcrt,
		"ISD17-ASffaa_0_1101.as.pem":    isd17ASffaa_0_1101aspem,
		"ISD17-ASffaa_0_1101.cp.as.key": isd17ASffaa_0_1101cpASkey}
	for fileName, fileContent := range files {
		filePath := filepath.Join(tmpDir, fileName)
		err = os.WriteFile(filePath, []byte(fileContent), 0666)
		if err != nil {
			log.Error("Failed writing files required for signing", "signPath", tmpDir, "err", err)
		}
	}
	payloadPath := filepath.Join(tmpDir, "payload")
	signedPayloadPath := filepath.Join(tmpDir, "payload.signed")
	asKeyPath := filepath.Join(tmpDir, "ISD17-ASffaa_0_1101.cp.as.key")
	asCertPath := filepath.Join(tmpDir, "ISD17-ASffaa_0_1101.as.pem")
	caCertPath := filepath.Join(tmpDir, "ISD17-ASffaa_0_1101.ca.crt")
	err = exec.Command("openssl", "cms", "-sign", "-text",
		"-in", payloadPath, "-out", signedPayloadPath, "-inkey", asKeyPath,
		"-signer", asCertPath, "-certfile", caCertPath).Run()
	if err != nil {
		log.Error("Failed to create signed file", "signedPayloadPath", signedPayloadPath, "err", err)
	}
	signerTRCid, signerIA, asCertChainPath, err := extractSignerInfo(context.WithValue(context.TODO(), "nativeCrypto", false), signedPayloadPath, tmpDir)
	if err != nil {
		log.Error("Getting signer info failed: extractSignerInfo", "err", err)
		t.FailNow()
	}
	if signerTRCid != 17 {
		log.Error("signerTRCid mismatch", "expected", 1, "actual", signerTRCid)
		t.FailNow()
	}
	if signerIA != "17-ffaa:0:1101" {
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
