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
	"time"
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

	resp, err := g.sendReceiveLoopRA()
	if err != nil {
		if err == context.Canceled {
			log.Error("Error receiving IPv6 RA", "err", err)
			return
		}
		log.Error("Error sending IPv6 RS", "err", err)
		return
	}
	if resp.Type() != ipv6.ICMPTypeRouterAdvertisement {
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
		log.Info("No IPv6 hinting")
		return
	}
	g.dispatchDNSInfo(resolvers, searchDomains, dnsInfoChan)
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
		ra, ok := m.(*ndp.RouterAdvertisement)
		if !ok {
			return ok
		}
		return hasDNSOptions(ra.Options)
	}
	return
}

func hasDNSOptions(opts []ndp.Option) bool {
	hasRDNS := false
	hasDNSSL := false
	for _, o := range opts {
		if _, ok := o.(*ndp.RecursiveDNSServer); ok {
			hasRDNS = true
		}
		if _, ok := o.(*ndp.DNSSearchList); ok {
			hasDNSSL = true
		}
		if hasRDNS && hasDNSSL {
			break
		}
	}
	return hasRDNS && hasDNSSL
}

func (g *IPv6HintGenerator) dispatchDNSInfo(resolvers []netip.Addr, searchDomains []string, dnsChan chan<- DNSInfo) {
	log.Debug("RA DNS resolver option", "resolvers", resolvers)
	log.Debug("RA DNS search domain option", "searchDomains", searchDomains)
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

func (g *IPv6HintGenerator) sendReceiveLoopRA() (ndp.Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DNSInfoTimeout)
	defer cancel()
	rs, raFilter, err := g.createRouterSolicitation()
	if err != nil {
		return nil, fmt.Errorf("error creating IPv6 Router Solicitation: %w", err)
	}

	c, _, err := ndp.Listen(g.iface, ndp.Unspecified)
	if err != nil {
		return nil, fmt.Errorf("error creating ndp connection: %w", err)
	}
	dst := netip.MustParseAddr("ff02::2") // Multicast all routers in the link-local

	for {
		msg, _, err := sendReceiveRA(ctx, c, &rs, dst, raFilter)
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
	if err := c.WriteTo(m, nil, dst); err != nil {
		return nil, netip.Addr{}, fmt.Errorf("failed to write message: %v", err)
	}

	return receive(ctx, c, check)
}

func receive(
	ctx context.Context,
	c *ndp.Conn,
	check func(m ndp.Message) bool,
) (ndp.Message, netip.Addr, error) {
	if err := c.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return nil, netip.Addr{}, fmt.Errorf("failed to set deadline: %v", err)
	}

	msg, _, from, err := c.ReadFrom()
	if err == nil {
		if check != nil && !check(msg) {
			// Read a message, but it isn't the one we want.  Keep trying.
			return nil, netip.Addr{}, errRetry
		}

		// Got a message that passed the check, if check was not nil.
		return msg, from, nil
	}

	// Was the context canceled already?
	select {
	case <-ctx.Done():
		return nil, netip.Addr{}, ctx.Err()
	default:
	}

	// Was the error caused by a read timeout, and should the loop continue?
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		return nil, netip.Addr{}, errRetry
	}

	return nil, netip.Addr{}, fmt.Errorf("failed to read message: %v", err)
}
