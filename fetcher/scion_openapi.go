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
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"golang.org/x/net/context/ctxhttp"

	log "github.com/inconshreveable/log15"
	// "github.com/scionproto/scion/go/lib/topology"
	// "github.com/scionproto/scion/go/pkg/cs/api"
)

const (
	baseURL                   = ""
	topologyEndpoint          = "topology"
	signedTopologyEndpoint    = "topology.signed"
	trcsEndpoint              = "trcs"
	trcBlobEndpoint           = "trcs/isd%d-b%d-s%d/blob"
	topologyJSONFileName      = "topology.json"
	signedTopologyFileName    = "topology.signed"
	httpRequestTimeout        = 2 * time.Second
)

func FetchConfiguration(outputPath string, insecure bool, addr *net.TCPAddr) error {
	err := PullTRCs(outputPath, addr)
	if err != nil {
		return err
	}
	if insecure {
		err = PullTopology(outputPath, addr)
	} else {
		err = PullSignedTopology(outputPath, addr)
		if err != nil {
			return err
		}
		err = verifySignature(outputPath)
	}
	return err
}

func PullTopology(outputPath string, addr *net.TCPAddr) error {
	url := buildTopologyURL(addr.IP, addr.Port)
	raw, err := fetchRawBytes("topology", url)
	if err != nil {
		return err
	}
	// Check that the topology is valid json
	if !json.Valid(raw) {
		return fmt.Errorf("unable to parse raw bytes to JSON")
	}
	// Check that the topology is a valid SCION topology, this check is done by the topology consumer
	/*_, err = topology.RWTopologyFromJSONBytes(raw)
	if err != nil {
		return fmt.Errorf("unable to parse RWTopology from JSON bytes: %w", err)
	}*/
	topologyPath := path.Join(outputPath, topologyJSONFileName)
	err = ioutil.WriteFile(topologyPath, raw, 0644)
	if err != nil {
		return fmt.Errorf("bootstrapper could not store topology: %w", err)
	}
	return nil
}

func buildTopologyURL(ip net.IP, port int) string {
	urlPath := baseURL + topologyEndpoint
	return fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)
}

func PullSignedTopology(outputPath string, addr *net.TCPAddr) error {
	url := buildSignedTopologyURL(addr.IP, addr.Port)
	raw, err := fetchRawBytes("signed topology", url)
	if err != nil {
		return err
	}
	signedTopologyPath := path.Join(outputPath, signedTopologyFileName)
	err = ioutil.WriteFile(signedTopologyPath, raw, 0644)
	if err != nil {
		return fmt.Errorf("bootstrapper could not store topology signature: %w", err)
	}
	return nil
}

func buildSignedTopologyURL(ip net.IP, port int) string {
	urlPath := baseURL + signedTopologyEndpoint
	return fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)
}

// API definition
// github.com/scionproto/scion/spec/control/trust.yml

// TRCBrief defines model for TRCBrief.
type TRCBrief struct {
	Id TRCID `json:"id"`
}

// TRCID defines model for TRCID.
type TRCID struct {
	BaseNumber   int `json:"base_number"`
	Isd          int `json:"isd"`
	SerialNumber int `json:"serial_number"`
}

func PullTRCs(outputPath string, addr *net.TCPAddr) error {
	url := buildTRCsURL(addr.IP, addr.Port)
	raw, err := fetchRawBytes("TRCs index", url)
	if err != nil {
		return err
	}
	// Get TRC identifiers
	trcs := []TRCBrief{}
	err = json.Unmarshal(raw, &trcs)
	if err != nil {
		return fmt.Errorf("unable to parse TRCs listing from JSON bytes: %w", err)
	}
	for _, trc := range trcs {
		err = PullTRC(outputPath, addr, trc.Id)
		if err != nil {
			log.Error("Failed to retrieve TRC", "trc", trc, "err", err)
		}
	}
	return nil
}

func buildTRCsURL(ip net.IP, port int) string {
	urlPath := baseURL + trcsEndpoint
	return fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)
}

func PullTRC(outputPath string, addr *net.TCPAddr, trcID TRCID) error {
	url := buildTRCURL(addr.IP, addr.Port, trcID)
	raw, err := fetchRawBytes("TRC", url)
	if err != nil {
		return err
	}
	trcPath := path.Join(outputPath, "certs",
		fmt.Sprintf("ISD%d-B%d-S%d.trc", trcID.Isd, trcID.BaseNumber, trcID.SerialNumber))
	if _, err := os.Stat("trcPath"); os.IsNotExist(err) {
		err = ioutil.WriteFile(trcPath, raw, 0644)
		if err != nil {
			return fmt.Errorf("bootstrapper could not store TRC: %w", err)
		}
	} else {
		log.Debug("Identical TRC version already exists, not overwritting.", "trcPath", trcPath)
	}
	return nil
}

func buildTRCURL(ip net.IP, port int, trc TRCID) string {
	urlPath := baseURL + trcBlobEndpoint
	uri := fmt.Sprintf("http://%s:%d/", ip, port) + urlPath
	return fmt.Sprintf(uri, trc.Isd, trc.BaseNumber, trc.SerialNumber)
}

func fetchHTTP(ctx context.Context, url string) (io.ReadCloser, error) {
	res, err := ctxhttp.Get(ctx, nil, url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		if err != res.Body.Close() {
			log.Error("Error closing response body", "err", err)
		}
		return nil, fmt.Errorf("status not OK: %w", fmt.Errorf("status: %s", res.Status))
	}
	return res.Body, nil
}

func fetchRawBytes(fileName string, url string) ([]byte, error) {
	log.Info(fmt.Sprintf("Fetching %s", fileName), "url", url)
	ctx, cancelF := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancelF()
	r, err := fetchHTTP(ctx, url)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to fetch %s from %s", fileName, url), "err", err)
		return nil, err
	}
	// Close response reader and handle errors
	defer func() {
		if err := r.Close(); err != nil {
			log.Error(fmt.Sprintf("Error closing the body of the %s response", fileName), "err", err)
		}
	}()
	raw, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("unable to read from response body: %w", err)
	}
	return raw, nil
}