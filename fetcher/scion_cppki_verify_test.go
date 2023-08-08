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
MIIMEAYJKoZIhvcNAQcCoIIMATCCC/0CAQExDzANBglghkgBZQMEAgMFADCCCHIG
CSqGSIb3DQEHAaCCCGMEgghfMIIIWwIBADAJAgERAgEBAgEBMCIYDzIwMjMwMjE1
MTQ0MzU4WhgPMjAyNTAyMTQxNDQzNTdaAgEAAQEAMAACAQEwDRMLZmZhYTowOjEx
MDEwDRMLZmZhYTowOjExMDEMF1NDSU9OTGFiIFRSQyBmb3IgSVNEIDE3MIIH4zCC
ApEwggI3oAMCAQICFBuNETHZYM/xYgcjlx5VOWDmoO5rMAoGCCqGSM49BAMEMIGl
MQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgxEDAOBgNVBAcMB1rDvHJpY2gxDzAN
BgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0c2VjMTQwMgYDVQQDDCsxNy1mZmFh
OjA6MTEwMSBTZW5zaXRpdmUgVm90aW5nIENlcnRpZmljYXRlMR8wHQYLKwYBBAGD
sBwBAgEMDjE3LWZmYWE6MDoxMTAxMB4XDTIzMDIxNTE0NDM1OFoXDTI1MDIxNDE0
NDM1OFowgaUxCzAJBgNVBAYTAkNIMQswCQYDVQQIDAJaSDEQMA4GA1UEBwwHWsO8
cmljaDEPMA0GA1UECgwGTmV0c2VjMQ8wDQYDVQQLDAZOZXRzZWMxNDAyBgNVBAMM
KzE3LWZmYWE6MDoxMTAxIFNlbnNpdGl2ZSBWb3RpbmcgQ2VydGlmaWNhdGUxHzAd
BgsrBgEEAYOwHAECAQwOMTctZmZhYTowOjExMDEwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQVuvuVgOSE7nTTU2DZzYV5IAplOfQuqLgeJ3Ke93+2Jbzep111EQnF
1RpHjpbn62ixwb8DHyeoAMqGfMd8IHcxo0MwQTAdBgNVHQ4EFgQUv1ty4iBG1nVP
4/MYqsjYrKNKopEwIAYDVR0lBBkwFwYLKwYBBAGDsBwBAwEGCCsGAQUFBwMIMAoG
CCqGSM49BAMEA0gAMEUCIQCMDubP2C/5OAbmVzo1cEpYwPdwAfbit8dMgKAYv8Dl
8AIgEd+tFr71Rb76hA9Wd88peYX8BnFRNgr4Ojcu63tV9UMwggKMMIICM6ADAgEC
AhR5yQd162TrH3aC1LTvh2mDCkdV/zAKBggqhkjOPQQDBDCBozELMAkGA1UEBhMC
Q0gxCzAJBgNVBAgMAlpIMRAwDgYDVQQHDAdaw7xyaWNoMQ8wDQYDVQQKDAZOZXRz
ZWMxDzANBgNVBAsMBk5ldHNlYzEyMDAGA1UEAwwpMTctZmZhYTowOjExMDEgUmVn
dWxhciBWb3RpbmcgQ2VydGlmaWNhdGUxHzAdBgsrBgEEAYOwHAECAQwOMTctZmZh
YTowOjExMDEwHhcNMjMwMjE1MTQ0MzU4WhcNMjUwMjE0MTQ0MzU4WjCBozELMAkG
A1UEBhMCQ0gxCzAJBgNVBAgMAlpIMRAwDgYDVQQHDAdaw7xyaWNoMQ8wDQYDVQQK
DAZOZXRzZWMxDzANBgNVBAsMBk5ldHNlYzEyMDAGA1UEAwwpMTctZmZhYTowOjEx
MDEgUmVndWxhciBWb3RpbmcgQ2VydGlmaWNhdGUxHzAdBgsrBgEEAYOwHAECAQwO
MTctZmZhYTowOjExMDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATBkUClItZK
+PH7VIvREGHEP4M85D4Xfzk7JmRcesdYvCYG7ePaBT9Dv4FE+XfRk0G7oqmzXW+q
gJ2PLw8jJ613o0MwQTAdBgNVHQ4EFgQUUgj/QRcLSs6Rdrf0/Nd68UuhNdIwIAYD
VR0lBBkwFwYLKwYBBAGDsBwBAwIGCCsGAQUFBwMIMAoGCCqGSM49BAMEA0cAMEQC
IE0x61V1o9mhMViC0X5wGhQbs4DIqyVgIqh+nOOYZfPYAiBpPcGJYXkRH81KGBLc
SJNNehOOzSVIO5gsMuvifgCnBjCCArowggJfoAMCAQICFEESxUOqYKAzvIwPWigx
SlzvGIr/MAoGCCqGSM49BAMEMIGnMQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgx
EDAOBgNVBAcMB1rDvHJpY2gxDzANBgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0
c2VjMTYwNAYDVQQDDC0xNy1mZmFhOjA6MTEwMSBIaWdoIFNlY3VyaXR5IFJvb3Qg
Q2VydGlmaWNhdGUxHzAdBgsrBgEEAYOwHAECAQwOMTctZmZhYTowOjExMDEwHhcN
MjMwMjE1MTQ0MzU4WhcNMjUwMjE0MTQ0MzU4WjCBpzELMAkGA1UEBhMCQ0gxCzAJ
BgNVBAgMAlpIMRAwDgYDVQQHDAdaw7xyaWNoMQ8wDQYDVQQKDAZOZXRzZWMxDzAN
BgNVBAsMBk5ldHNlYzE2MDQGA1UEAwwtMTctZmZhYTowOjExMDEgSGlnaCBTZWN1
cml0eSBSb290IENlcnRpZmljYXRlMR8wHQYLKwYBBAGDsBwBAgEMDjE3LWZmYWE6
MDoxMTAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaJhWyZh97ANYKMr9PnkQ
EGEAJjQIHiaPDweTcRx2JETXT3AQX019+7IjI+c4qgUg5I0sMh4zRZQVmOJi/SCG
O6NnMGUwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0O
BBYEFPDJcfY8dggKFPq1Q4HDX/2mbN3/MCAGA1UdJQQZMBcGCysGAQQBg7AcAQMD
BggrBgEFBQcDCDAKBggqhkjOPQQDBANJADBGAiEAqpEg+Fxg3qdNwkhJHKSdDQuf
MdouXWKMPDbD5Gb0EdQCIQDp7upCx0QhnHGNfb6hgS7SgIWRDkosvovDlrGoWJcK
1jGCA28wggGyAgEBMIG8MIGjMQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgxEDAO
BgNVBAcMB1rDvHJpY2gxDzANBgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0c2Vj
MTIwMAYDVQQDDCkxNy1mZmFhOjA6MTEwMSBSZWd1bGFyIFZvdGluZyBDZXJ0aWZp
Y2F0ZTEfMB0GCysGAQQBg7AcAQIBDA4xNy1mZmFhOjA6MTEwMQIUeckHdetk6x92
gtS074dpgwpHVf8wDQYJYIZIAWUDBAIDBQCggYkwGAYJKoZIhvcNAQkDMQsGCSqG
SIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwMjE1MTQ0MzU5WjBPBgkqhkiG9w0B
CQQxQgRASTesPZKyy6R7WPMLJJdWdawgz6QtEHpxVVtHVFrz7uSTQXNftqHXjUT0
yD7LLiXoiEe0c9Ihr6Fy6J9Ofo+/GDAKBggqhkjOPQQDBARHMEUCIGSVS/h8fZL2
yMvAMQYeIc+fr3dwZKbgFvS48wyBPMz7AiEAmbgKv3+UUczZNr7FYMPmpg0wwBUh
qf8QrA6aQHQ3G80wggG1AgEBMIG+MIGlMQswCQYDVQQGEwJDSDELMAkGA1UECAwC
WkgxEDAOBgNVBAcMB1rDvHJpY2gxDzANBgNVBAoMBk5ldHNlYzEPMA0GA1UECwwG
TmV0c2VjMTQwMgYDVQQDDCsxNy1mZmFhOjA6MTEwMSBTZW5zaXRpdmUgVm90aW5n
IENlcnRpZmljYXRlMR8wHQYLKwYBBAGDsBwBAgEMDjE3LWZmYWE6MDoxMTAxAhQb
jREx2WDP8WIHI5ceVTlg5qDuazANBglghkgBZQMEAgMFAKCBiTAYBgkqhkiG9w0B
CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzAyMTUxNDQzNTlaME8G
CSqGSIb3DQEJBDFCBEBJN6w9krLLpHtY8wskl1Z1rCDPpC0QenFVW0dUWvPu5JNB
c1+2odeNRPTIPssuJeiIR7Rz0iGvoXLon05+j78YMAoGCCqGSM49BAMEBEgwRgIh
AJSRtv19MnigUbdYJwqZrIK+EOfqZypjLm/pw4O0E5/yAiEA8FMVcvlxwWFjqySz
KZVd5ErwYR3A6zIVGydZL4o1UnA=
-----END TRC-----`

var isd17ASffaa_0_1101CAcrt = `-----BEGIN CERTIFICATE-----
MIICsDCCAlWgAwIBAgIUCk2LCWPJmH+HTnzejH23ufp3KrEwCgYIKoZIzj0EAwQw
gacxCzAJBgNVBAYTAkNIMQswCQYDVQQIDAJaSDEQMA4GA1UEBwwHWsO8cmljaDEP
MA0GA1UECgwGTmV0c2VjMQ8wDQYDVQQLDAZOZXRzZWMxNjA0BgNVBAMMLTE3LWZm
YWE6MDoxMTAxIEhpZ2ggU2VjdXJpdHkgUm9vdCBDZXJ0aWZpY2F0ZTEfMB0GCysG
AQQBg7AcAQIBDA4xNy1mZmFhOjA6MTEwMTAeFw0yMzAyMTUxNDQzNThaFw0yNTAy
MTQxNDQzNThaMIGeMQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgxEDAOBgNVBAcM
B1rDvHJpY2gxDzANBgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0c2VjMS0wKwYD
VQQDDCQxNy1mZmFhOjA6MTEwMSBTZWN1cmUgQ0EgQ2VydGlmaWNhdGUxHzAdBgsr
BgEEAYOwHAECAQwOMTctZmZhYTowOjExMDEwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAASBOUu7asgUTJ4R0qeYm77sm4TVx3go766Yw6fCtYPJtLay8daJFkVg0WhS
FD5pLDFs7tgE5Pu3nzi5FkjBGxBpo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4G
A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUWwjNBu9ss2/1br0cHz7bagsqSMowHwYD
VR0jBBgwFoAU8Mlx9jx2CAoU+rVDgcNf/aZs3f8wCgYIKoZIzj0EAwQDSQAwRgIh
AKkTwJJp0XDjxuAh1O2kxLXXpsd5XXTuLgasZNxOe8hbAiEAlrJAcVvMKXrtlYYj
fUDNUANFjcVS5s1s6A08JQKcstw=
-----END CERTIFICATE-----`

var isd17ASffaa_1_1aspem = `-----BEGIN CERTIFICATE-----
MIICrzCCAlSgAwIBAgIUd8MdryawbWzwMTUQLKElZEDQWOYwCgYIKoZIzj0EAwQw
gZ4xCzAJBgNVBAYTAkNIMQswCQYDVQQIDAJaSDEQMA4GA1UEBwwHWsO8cmljaDEP
MA0GA1UECgwGTmV0c2VjMQ8wDQYDVQQLDAZOZXRzZWMxLTArBgNVBAMMJDE3LWZm
YWE6MDoxMTAxIFNlY3VyZSBDQSBDZXJ0aWZpY2F0ZTEfMB0GCysGAQQBg7AcAQIB
DA4xNy1mZmFhOjA6MTEwMTAeFw0yMzAyMTUxNDQ0MDNaFw0yNDAyMTUxNDQ0MDNa
MIGRMQswCQYDVQQGEwJDSDELMAkGA1UECAwCWkgxEDAOBgNVBAcMB1rDvHJpY2gx
DzANBgNVBAoMBk5ldHNlYzEPMA0GA1UECwwGTmV0c2VjMSMwIQYDVQQDDBoxNy1m
ZmFhOjE6MSBBUyBDZXJ0aWZpY2F0ZTEcMBoGCysGAQQBg7AcAQIBDAsxNy1mZmFh
OjE6MTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIAFFOt094DKoITkHskSxXZ8
3z2VtcusVCdNbklQjVBgwLp+BuTxRwMJ0fWRpFakAhzmK6JfEUw3g0Xi4JJ4Onej
ezB5MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU1JsM6Yeenp5IYhgzKFF7yqBc
ac8wHwYDVR0jBBgwFoAUWwjNBu9ss2/1br0cHz7bagsqSMowJwYDVR0lBCAwHgYI
KwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDCDAKBggqhkjOPQQDBANJADBGAiEA
tiLJjcqwtG37/cGJS6o4OoqxdbFhtUjaebGmOpZOh10CIQCWDErkumcjRCHnKHU8
CgzgjvtU06dNQ5tABcjOBFX4rA==
-----END CERTIFICATE-----
`

var isd17ASffaa_1_1cpASkey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8SUQUUkU+AD4LtTj
Wxan3smVVLh57gz+hm/6T2Xv+nGhRANCAASABRTrdPeAyqCE5B7JEsV2fN89lbXL
rFQnTW5JUI1QYMC6fgbk8UcDCdH1kaRWpAIc5iuiXxFMN4NF4uCSeDp3
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
