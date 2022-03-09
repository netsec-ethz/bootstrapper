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
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/context/ctxhttp"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/bootstrapper/config"
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

func FetchConfiguration(outputPath string, workingDir string, securityMode config.SecurityMode, addr *net.TCPAddr) error {
	err := PullTRCs(outputPath, workingDir, addr, securityMode)
	if err != nil {
		return err
	}
	if securityMode == config.Insecure {
		err = PullTopology(outputPath, addr)
	} else {
		err = PullSignedTopology(workingDir, addr)
		if err != nil {
			return err
		}
		err = verifySignature(outputPath, workingDir)
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
	err = os.WriteFile(topologyPath, raw, 0644)
	if err != nil {
		return fmt.Errorf("bootstrapper could not store topology: %w", err)
	}
	return nil
}

func buildTopologyURL(ip net.IP, port int) string {
	urlPath := baseURL + topologyEndpoint
	return fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)
}

func PullSignedTopology(workingDir string, addr *net.TCPAddr) error {
	url := buildSignedTopologyURL(addr.IP, addr.Port)
	raw, err := fetchRawBytes("signed topology", url)
	if err != nil {
		return err
	}
	signedTopologyPath := path.Join(workingDir, signedTopologyFileName)
	err = os.WriteFile(signedTopologyPath, raw, 0644)
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

func PullTRCs(outputPath, workingDir string, addr *net.TCPAddr, securityMode config.SecurityMode) error {
	url := buildTRCsURL(addr.IP, addr.Port)
	raw, err := fetchRawBytes("TRCs index", url)
	if err != nil {
		return err
	}
	// Get TRC identifiers
	var trcs = new(sortedTRCBriefs)
	err = json.Unmarshal(raw, trcs)
	if err != nil {
		return fmt.Errorf("unable to parse TRCs listing from JSON bytes: %w", err)
	}

	if securityMode != config.Insecure {
		// Wipe symlinks to TRCs fetched in insecure mode, if we are not using the insecure mode
		err = wipeInsecureSymlinks(outputPath)
		if err != nil {
			log.Warn("Unable to remove symlinks to insecure TRCs", "err", err)
		}
	}

	// Sort TRCBriefs by ISD, serial and BaseNumber, to enable verifying the TRC update chain after each pull
	sort.Sort(trcs)
	for _, trc := range *trcs {
		err = PullTRC(outputPath, workingDir, addr, securityMode, trc.Id)
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

func wipeInsecureSymlinks(outputPath string) error {
	// do a lstat on the directory
	trcs, err := os.ReadDir(path.Join(outputPath, "certs"))
	if err != nil {
		return err
	}
	for _, trc := range trcs {
		// ignore directories
		if trc.IsDir() {
			continue
		}
		// get file info
		fInfo, err := trc.Info()
		if err != nil {
			return err
		}
		// ignore non-symlinks
		if fInfo.Mode() & os.ModeSymlink != 1 {
			continue
		}
		// stat the symlink, check if it links to a TRC from the insecure mode
		fInfo, err = os.Stat(trc.Name())
		if err != nil {
			return err
		}
		if strings.HasSuffix(fInfo.Name(), ".insecure") {
			// unlink
			err = os.Remove(fInfo.Name())
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func PullTRC(outputPath, workingDir string, addr *net.TCPAddr, securityMode config.SecurityMode, trcID TRCID) error {
	url := buildTRCURL(addr.IP, addr.Port, trcID)
	raw, err := fetchRawBytes("TRC", url)
	if err != nil {
		return err
	}
	// Mark TRCs downloaded in the insecure mode as such
	tmpTRCpath := path.Join(workingDir,
		fmt.Sprintf("ISD%d-B%d-S%d.trc.insecure", trcID.Isd, trcID.BaseNumber, trcID.SerialNumber))
	trcPath := path.Join(outputPath, "certs",
		fmt.Sprintf("ISD%d-B%d-S%d.trc", trcID.Isd, trcID.BaseNumber, trcID.SerialNumber))
	if _, err := os.Stat(trcPath); !os.IsNotExist(err) {
		log.Info("identical TRC version already exists, not overwritting: path: %s : %w", trcPath, err)
		return nil
	}
	err = os.WriteFile(tmpTRCpath, raw, 0644)
	if err != nil {
		return fmt.Errorf("bootstrapper could not store TRC: %w", err)
	}
	// Do additional checks for security_mode permissive and strict to check the TRC update chain
	switch securityMode {
	case config.Permissive:
		err = verifyTRCUpdateChain(outputPath, tmpTRCpath, false)
	case config.Strict:
		err = verifyTRCUpdateChain(outputPath, tmpTRCpath, true)
	default:
		return fmt.Errorf("invalid security mode: %v", securityMode)
	}
	if err != nil {
		// remove the TRC failing the update chain check
		rerr := os.Remove(tmpTRCpath)
		if rerr != nil {
			return rerr
		}
		return err
	}
	if securityMode == config.Insecure {
		// symlink the TRC fetched in insecure mode into the standard directory
		err = os.Symlink(trcPath,  tmpTRCpath)
		if err != nil {
			return fmt.Errorf("symlinking insecure TRC failed: %w", err)
		}
	} else {
		// move the TRC to the standard directory
		err = os.Rename(tmpTRCpath, trcPath)
		if err != nil {
			return fmt.Errorf("moving validated TRC failed: %w", err)
		}
	}
	return err
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
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("unable to read from response body: %w", err)
	}
	return raw, nil
}

type sortedTRCBriefs []TRCBrief

func (t sortedTRCBriefs) Len() int {
	return len(t)
}

func (t sortedTRCBriefs) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
	return
}

func (t sortedTRCBriefs) Less(i, j int) bool {
	if t[i].Id.Isd != t[j].Id.Isd {
		return t[i].Id.Isd < t[j].Id.Isd
	}
	if t[i].Id.SerialNumber != t[j].Id.SerialNumber {
		return t[i].Id.SerialNumber < t[j].Id.SerialNumber
	}
	return t[i].Id.BaseNumber < t[j].Id.BaseNumber
}
