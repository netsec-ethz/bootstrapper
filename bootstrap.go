// Copyright 2020 Anapaya Systems
// Copyright 2021 ETH Zurich
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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"path"
	"time"

	"golang.org/x/net/context/ctxhttp"

	"github.com/netsec-ethz/bootstrapper/config"
	"github.com/netsec-ethz/bootstrapper/hinting"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/topology"
	//"github.com/scionproto/scion/go/pkg/cs/api"
)

const (
	baseURL              = ""
	topologyEndpoint     = "topology"
	TRCsEndpoint         = "trcs"
	TRCBlobEndpoint      = "trcs/isd%d-b%d-s%d/blob"
	TopologyJSONFileName = "topology.json"
	httpRequestTimeout   = 2 * time.Second
	hintsTimeout         = 10 * time.Second
)

type Bootstrapper struct {
	cfg   *config.Config
	iface *net.Interface
	// ipHintsChan is used to inform the bootstrapper about discovered IP:port hints
	ipHintsChan chan net.TCPAddr
}

func NewBootstrapper(cfg *config.Config) (*Bootstrapper, error) {
	log.Debug("Cfg", "", cfg)
	iface, err := net.InterfaceByName(cfg.InterfaceName)
	if err != nil {
		return nil, common.NewBasicError(common.ErrMsg("getting interface by name: "+cfg.InterfaceName), err)
	}
	return &Bootstrapper{
		cfg,
		iface,
		make(chan net.TCPAddr)}, nil
}

func (b *Bootstrapper) tryBootstrapping() error {
	hintGenerators := []hinting.HintGenerator{
		hinting.NewMockHintGenerator(&cfg.MOCK),
		hinting.NewDHCPHintGenerator(&cfg.DHCP, b.iface),
		// XXX: DNS-SD depends on DNS resolution working, which can depend on DHCP for getting the local DNS resolver IP
		hinting.NewDNSSDHintGenerator(&cfg.DNSSD),
		// XXX: mDNS depends on the DNS search domain to be correct, which can depend on DHCP for getting it
		hinting.NewMDNSHintGenerator(&cfg.MDNS, b.iface)}
	for _, g := range hintGenerators {
		go func(g hinting.HintGenerator) {
			defer log.HandlePanic()
			g.Generate(b.ipHintsChan)
		}(g)
	}
	hintsTimeout := time.After(hintsTimeout)
	log.Info("Waiting for hints ...")
OuterLoop:
	for {
		select {
		case ipAddr := <-b.ipHintsChan:
			serverAddr := &ipAddr
			if serverAddr.Port == 0 {
				serverAddr.Port = int(hinting.DiscoveryPort)
			}
			err := pullTopology(serverAddr)
			if err != nil {
				return err
			}
			err = pullTRCs(serverAddr)
			if err != nil {
				return err
			}
			break OuterLoop
		case <-hintsTimeout:
			return fmt.Errorf("bootstrapper timed out")
		}
	}
	return nil
}

func pullTopology(addr *net.TCPAddr) error {
	url := buildTopologyURL(addr.IP, addr.Port)
	log.Info("Fetching topology", "url", url)
	ctx, cancelF := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancelF()
	r, err := fetchHTTP(ctx, url)
	if err != nil {
		log.Error("Failed to fetch topology from "+url, "err", err)
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			log.Error("Error closing the body of the topology response", "err", err)
		}
	}()
	raw, err := ioutil.ReadAll(r)
	if err != nil {
		return common.NewBasicError("Unable to read from response body", err)
	}
	// Check that the topology is valid
	_, err = topology.RWTopologyFromJSONBytes(raw)
	if err != nil {
		return common.NewBasicError("unable to parse RWTopology from JSON bytes", err)
	}
	topologyPath := path.Join(cfg.SciondConfigDir, TopologyJSONFileName)
	err = ioutil.WriteFile(topologyPath, raw, 0644)
	if err != nil {
		return common.NewBasicError("Bootstrapper could not store topology", err)
	}
	return nil
}

func buildTopologyURL(ip net.IP, port int) string {
	urlPath := baseURL + topologyEndpoint
	return fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)
}

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

func pullTRCs(addr *net.TCPAddr) error {
	url := buildTRCsURL(addr.IP, addr.Port)
	log.Info("Fetching TRCs", "url", url)
	ctx, cancelF := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancelF()
	r, err := fetchHTTP(ctx, url)
	if err != nil {
		log.Error("Failed to fetch TRCs from "+url, "err", err)
		return err
	}
	// Close response reader and handle errors
	defer func() {
		if err := r.Close(); err != nil {
			log.Error("Error closing the body of the TRCs response", "err", err)
		}
	}()
	raw, err := ioutil.ReadAll(r)
	if err != nil {
		return common.NewBasicError("Unable to read from response body", err)
	}
	// Get TRC identifiers
	trcs := []TRCBrief{}
	err = json.Unmarshal(raw, &trcs)
	if err != nil {
		return common.NewBasicError("unable to parse TRCs listing from JSON bytes", err)
	}
	for _, trc := range trcs {
		err = pullTRC(addr, trc.Id)
		if err != nil {
			log.Error("Failed to retrieve TRC", "trc", trc, "err", err)
		}
	}
	return nil
}

func buildTRCsURL(ip net.IP, port int) string {
	urlPath := baseURL + TRCsEndpoint
	return fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)
}

func pullTRC(addr *net.TCPAddr, trcID TRCID) error {
	url := buildTRCURL(addr.IP, addr.Port, trcID)
	log.Info("Fetching TRC", "url", url)
	ctx, cancelF := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancelF()
	r, err := fetchHTTP(ctx, url)
	if err != nil {
		log.Error("Failed to fetch TRC from "+url, "err", err)
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			log.Error("Error closing the body of the TRC response", "err", err)
		}
	}()
	raw, err := ioutil.ReadAll(r)
	if err != nil {
		return common.NewBasicError("Unable to read from response body", err)
	}
	trcPath := path.Join(cfg.SciondConfigDir, "certs",
		fmt.Sprintf("ISD%d-B%d-S%d.trc", trcID.Isd, trcID.BaseNumber, trcID.SerialNumber))
	err = ioutil.WriteFile(trcPath, raw, 0644)
	if err != nil {
		return common.NewBasicError("Bootstrapper could not store TRC", err)
	}
	return nil
}

func buildTRCURL(ip net.IP, port int, trc TRCID) string {
	urlPath := baseURL + TRCBlobEndpoint
	uri := fmt.Sprintf("http://%s:%d/", ip, port) + urlPath
	return fmt.Sprintf(uri, trc.Isd, trc.BaseNumber, trc.SerialNumber)
}

func fetchHTTP(ctx context.Context, url string) (io.ReadCloser, error) {
	res, err := ctxhttp.Get(ctx, nil, url)
	if err != nil {
		return nil, common.NewBasicError("HTTP request failed", err)
	}
	if res.StatusCode != http.StatusOK {
		if err != res.Body.Close() {
			log.Error("Error closing response body", "err", err)
		}
		return nil, common.NewBasicError("Status not OK", nil, "status", res.Status)
	}
	return res.Body, nil
}
