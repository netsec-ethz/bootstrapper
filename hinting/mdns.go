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

package hinting

import (
	"context"
	"net"
	"time"

	"github.com/grandcat/zeroconf"
	log "github.com/inconshreveable/log15"
)

const (
	resolverTimeout = 2 * time.Second
)

type MDNSHintGeneratorConf struct {
	Enable bool `toml:"Enable"`
}

var _ HintGenerator = (*MDNSSDHintGenerator)(nil)

// Multicast Domain Name System Service Discovery
type MDNSSDHintGenerator struct {
	cfg   *MDNSHintGeneratorConf
	iface *net.Interface
}

func NewMDNSHintGenerator(cfg *MDNSHintGeneratorConf, iface *net.Interface) *MDNSSDHintGenerator {
	return &MDNSSDHintGenerator{cfg, iface}
}

func (g *MDNSSDHintGenerator) Generate(ipHintsChan chan<- net.TCPAddr) {
	if !g.cfg.Enable {
		return
	}
	resolver, err := zeroconf.NewResolver(zeroconf.SelectIfaces([]net.Interface{*g.iface}))
	if err != nil {
		log.Error("mDNS could not construct dns resolver", "err", err)
		return
	}
	dnsChan := dispatcher.getDNSConfig()
	for dnsServer := range dnsChan {
		for _, searchDomain := range dnsServer.searchDomains {
			entriesChan := make(chan *zeroconf.ServiceEntry)
			go func() {
				handleEntries(entriesChan, ipHintsChan)
			}()
			discoverEntries(resolver, searchDomain, entriesChan)
		}
	}
	log.Info("mDNS hinting done")
}

func handleEntries(entriesChan <-chan *zeroconf.ServiceEntry, ipHintsChan chan<- net.TCPAddr) {
	for entry := range entriesChan {
		log.Debug("mDNS Got entry", "entry", entry)
		for _, ip := range entry.AddrIPv4 {
			addr := net.TCPAddr{IP: ip, Port: entry.Port}
			log.Info("mDNS hint", "Addr", addr)
			ipHintsChan <- addr
		}
		for _, ip := range entry.AddrIPv6 {
			addr := net.TCPAddr{IP: ip, Port: entry.Port}
			log.Info("mDNS hint", "Addr", addr)
			ipHintsChan <- addr
		}
	}
}

func discoverEntries(resolver *zeroconf.Resolver, searchDomain string, entriesChan chan *zeroconf.ServiceEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), resolverTimeout)
	defer cancel()
	err := resolver.Browse(ctx, "_sciondiscovery._tcp", searchDomain, entriesChan)
	if err != nil {
		log.Error("mDNS could not lookup", "searchDomain", searchDomain, "err", err)
		return
	}
	<-ctx.Done()
}
