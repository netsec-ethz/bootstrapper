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
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/bootstrapper/config"
	"github.com/netsec-ethz/bootstrapper/fetcher"
	"github.com/netsec-ethz/bootstrapper/hinting"
)

const (
	hintsTimeout = 15 * time.Second
)

type Bootstrapper struct {
	cfg   *config.Config
	iface *net.Interface
	// ipHintsChan is used to inform the bootstrapper about discovered IP:port hints
	ipHintsChan chan net.TCPAddr
}

func NewBootstrapper(cfg *config.Config) (*Bootstrapper, error) {
	log.Debug("Configuration loaded", "cfg", cfg)

	// Ensure working directory exists
	if _, err := os.Stat(cfg.WorkingDir()); os.IsNotExist(err) {
		err := os.Mkdir(cfg.WorkingDir(), 0775)
		if err != nil {
			return nil, fmt.Errorf("failed to create bootstrapper working directory: err: %w", err)
		}
	}

	var iface *net.Interface
	if cfg.DHCPv6.Enable || cfg.IPv6.Enable || cfg.DHCP.Enable || cfg.MDNS.Enable {
		var err error
		iface, err = net.InterfaceByName(cfg.InterfaceName)
		if err != nil {
			return nil, fmt.Errorf("getting interface '%s' by name: %w", cfg.InterfaceName, err)
		}
	}
	return &Bootstrapper{
		cfg,
		iface,
		make(chan net.TCPAddr)}, nil
}

func (b *Bootstrapper) tryBootstrapping() error {
	var hintGenerators []hinting.HintGenerator
	hintGenerators = append(hintGenerators,
		hinting.NewMockHintGenerator(&cfg.MOCK),
		// Gets DNS information from IPv6 RAs
		hinting.NewIPv6HintGenerator(&cfg.IPv6, b.iface),
		hinting.NewDHCPv6HintGenerator(&cfg.DHCPv6, b.iface),
		hinting.NewDHCPHintGenerator(&cfg.DHCP, b.iface),
		// XXX: DNS-SD depends on DNS resolution working, which can depend on DHCP for getting the local DNS resolver IP
		hinting.NewDNSSDHintGenerator(&cfg.DNSSD),
		// XXX: mDNS depends on the DNS search domain to be correct, which can depend on DHCP for getting it
		hinting.NewMDNSHintGenerator(&cfg.MDNS, b.iface))
	wg := sync.WaitGroup{}
	for _, g := range hintGenerators {
		wg.Add(1)
		go func(g hinting.HintGenerator) {
			defer wg.Done()
			g.Generate(b.ipHintsChan)
		}(g)
	}
	hintsTimeout := time.After(hintsTimeout)
	hintersDone := make(chan struct{})
	go func() {
		log.Info("Waiting for hints ...")
		wg.Wait()
		close(hintersDone)
	}()
OuterLoop:
	for {
		select {
		case ipAddr := <-b.ipHintsChan:
			if err := checkIsRoutable(ipAddr.IP); err != nil {
				// Ignore IPv6 hints if device does not have an IPv6 address, etc.
				log.Debug("Ignore hint, no route", "hint", ipAddr, "err", err)
				continue
			}
			serverAddr := &ipAddr
			if serverAddr.Port == 0 {
				serverAddr.Port = int(hinting.DiscoveryPort)
			}
			err := fetcher.FetchConfiguration(&cfg, serverAddr)
			if err != nil {
				return err
			}
			break OuterLoop
		case <-hintsTimeout:
			return fmt.Errorf("bootstrapper timed out")
		case <-hintersDone:
			log.Info("... all hinters terminated.")
			break OuterLoop
		}
	}
	return nil
}

func checkIsRoutable(dst net.IP) error {
	udpAddr := net.UDPAddr{IP: dst, Port: 1}
	udpConn, err := net.DialUDP(udpAddr.Network(), nil, &udpAddr)
	if err != nil {
		return err
	}
	udpConn.Close()
	return nil
}
