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

package hinting

import (
	"context"
	"errors"
	"fmt"
	log "github.com/inconshreveable/log15"
	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
	"net"
	"net/netip"
)

// Use IPv6 NDP router advertisements to get DNS resolvers and DNS search lists
// https://datatracker.ietf.org/doc/html/rfc6106

type IPv6HintGeneratorConf struct {
	Enable bool `toml:"Enable"`
}

var _ HintGenerator = (*IPv6HintGenerator)(nil)

type IPv6HintGenerator struct {
	cfg   *IPv6HintGeneratorConf
	iface *net.Interface
}

func NewIPv6HintGenerator(cfg *IPv6HintGeneratorConf, iface *net.Interface) *IPv6HintGenerator {
	return &IPv6HintGenerator{cfg, iface}
}

func (g *IPv6HintGenerator) Generate(ipHintsChan chan<- net.TCPAddr) {
	if !g.cfg.Enable {
		return
	}
	log.Info("IPv6 Probing", "interface", g.iface.Name)
	rs, raFilter, err := g.createRouterSolicitation()
	if err != nil {
		log.Error("Error creating IPv6 Router Solicitation", "err", err)
		return
	}

	c, _, err := ndp.Listen(g.iface, ndp.Unspecified)
	resp, err := sendReceiveLoop(context.TODO(), c, nil, &rs, netip.MustParseAddr("ff02::2"), raFilter)
	if err != nil {
		if err == context.Canceled {
			log.Error("Error receiving IPv6 RA", "ack", resp, "err", err)
			return
		}
		err = fmt.Errorf("failed to send RS: %w", err)
		log.Error("Error sending IPv6 RS", "ack", resp, "err", err)
		return
	}
	if resp.Type() == ipv6.ICMPTypeRouterAdvertisement {
		// raFilter should already ensure this
		log.Error("Error reading IPv6 RA response, type is not RA", "type", resp.Type())
		return
	}
	ra, ok := resp.(*ndp.RouterAdvertisement)
	if !ok {
		log.Error("Error reading IPv6 RA, not a valid RA", "ack", resp)
		return
	}
	var resolvers []netip.Addr
	var searchDomains []string
	for _, o := range ra.Options {
		if rdns, ok := o.(*ndp.RecursiveDNSServer); ok {
			resolvers = rdns.Servers
		}
		if dnssl, ok := o.(*ndp.DNSSearchList); ok {
			searchDomains = dnssl.DomainNames
		}
	}
	if len(resolvers) < 1 {
		log.Info("No IPv6 hinting done")
		return
	}
	go g.dispatchDNSInfo(resolvers, searchDomains, dnsInfoChan)
	log.Info("IPv6 hinting done")
}

func (g *IPv6HintGenerator) createRouterSolicitation() (rs ndp.RouterSolicitation,
	rafilter func(m ndp.Message) bool, err error) {

	rs = ndp.RouterSolicitation{}
	if g.iface.HardwareAddr != nil {
		rs.Options = append(rs.Options, &ndp.LinkLayerAddress{
			Direction: ndp.Source,
			Addr:      g.iface.HardwareAddr,
		})
	}

	rafilter = func(m ndp.Message) bool {
		_, ok := m.(*ndp.RouterAdvertisement)
		return ok
	}
	return
}

func (g *IPv6HintGenerator) dispatchDNSInfo(resolvers []netip.Addr, searchDomains []string, dnsChan chan<- DNSInfo) {
	log.Debug("DHCP DNS resolver option", "resolvers", resolvers)
	log.Debug("DHCP DNS search domain option", "searchDomains", searchDomains)
	dnsInfo := DNSInfo{resolvers: []string{}, searchDomains: []string{}}
	for _, r := range resolvers {
		dnsInfo.resolvers = append(dnsInfo.resolvers, r.String())
	}
	for _, d := range searchDomains {
		dnsInfo.searchDomains = append(dnsInfo.searchDomains, d)
	}
	dnsInfoWriters.Add(1)
	select {
	case <-dnsInfoDone:
		// Ignore dnsInfo value, done publishing
	default:
		dnsChan <- dnsInfo
	}
	dnsInfoWriters.Done()
}

// Adapted from https://github.com/mdlayher/ndp/
//
// MIT License
//
// Copyright (C) 2017-2022 Matt Layher
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
// and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions
// of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
// BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

func sendReceiveLoop(
	ctx context.Context,
	c *ndp.Conn,
	ll *log.Logger,
	m ndp.Message,
	dst netip.Addr,
	check func(m ndp.Message) bool,
) (ndp.Message, error) {
	for i := 0; ; i++ {
		msg, _, err := sendReceiveRA(ctx, c, m, dst, check)
		switch err {
		case context.Canceled:
			return nil, err
		case errRetry:
			continue
		case nil:
			return msg, nil
		default:
			return nil, err
		}
	}
}

var errRetry = errors.New("retry")

func sendReceiveRA(
	ctx context.Context,
	c *ndp.Conn,
	m ndp.Message,
	dst netip.Addr,
	check func(m ndp.Message) bool,
) (ndp.Message, netip.Addr, error) {
	// TODO
	return nil, netip.Addr{}, fmt.Errorf("sendReceive not implemented")
}
