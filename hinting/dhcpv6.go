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
	"encoding/binary"
	"fmt"
	"net"

	log "github.com/inconshreveable/log15"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/client6"
)

type DHCPv6HintGeneratorConf struct {
	Enable bool `toml:"Enable"`
}

var _ HintGenerator = (*DHCPv6HintGenerator)(nil)

type DHCPv6HintGenerator struct {
	cfg   *DHCPv6HintGeneratorConf
	iface *net.Interface
}

func NewDHCPv6HintGenerator(cfg *DHCPv6HintGeneratorConf, iface *net.Interface) *DHCPv6HintGenerator {
	return &DHCPv6HintGenerator{cfg, iface}
}

func (g *DHCPv6HintGenerator) Generate(ipHintsChan chan<- net.TCPAddr) {
	if !g.cfg.Enable {
		return
	}
	log.Info("DHCPv6 Probing", "interface", g.iface.Name)
	client := client6.NewClient()
	conv, err := client.Exchange(g.iface.Name)
	if err != nil {
		log.Error("Error during DHCPv6 solicit interaction", "err", err)
		return
	}
	go g.dispatchDNSInfo(conv, dnsInfoChan)
	g.dispatchIPHints(conv, ipHintsChan)
	log.Info("DHCPv6 hinting done")
}

func (g *DHCPv6HintGenerator) dispatchIPHints(conv []dhcpv6.DHCPv6, ipHintChan chan<- net.TCPAddr) {
	if !g.cfg.Enable {
		return
	}
	for _, p := range conv {
		options := p.GetOption(dhcpv6.OptionVendorOpts)
		for _, option := range options {
			if oVSIO, ok := option.(*dhcpv6.OptVendorOpts); ok {
				ip, port, err := parseBootstrapVendorInformationOption(*oVSIO)
				if err != nil {
					log.Error("Failed to parse Vendor-specific Information Option", "err", err)
					continue
				}
				addr := net.TCPAddr{IP: ip, Port: port}
				log.Info("DHCPv6 vi-encap hint", "Addr", addr)
				ipHintChan <- addr
			}
		}
	}
}

func (g *DHCPv6HintGenerator) dispatchDNSInfo(conv []dhcpv6.DHCPv6, dnsChan chan<- DNSInfo) {
	var resolvers []net.IP
	var searchDomains []string
	for _, p := range conv {
		options := p.GetOption(dhcpv6.OptionDNSRecursiveNameServer)
		for _, option := range options {
			if oRDNS, ok := option.(*dhcpv6.OptDNSRecursiveNameServer); ok {
				resolvers = append(resolvers, oRDNS.NameServers...)
			}
		}
		options = p.GetOption(dhcpv6.OptionDomainSearchList)
		for _, option := range options {
			if oDNSSL, ok := option.(*dhcpv6.OptDomainSearchList); ok {
				searchDomains = append(searchDomains, oDNSSL.DomainSearchList.Labels...)
			}
		}
	}
	if len(resolvers) < 1 {
		return
	}
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

func parseBootstrapVendorInformationOption(vsio dhcpv6.OptVendorOpts) (ip net.IP, port int, err error) {
	// Parses a Vendor-specific Information Option for DHCPv6 as defined in RFC3315.
	// `optionsBytes` should only contains the option's values byte stream, starting with the PEN,
	// and be already stripped of the 2-byte option code and 2-byte option length.
	//
	//
	// The enterprise number used to identify the option is the Private Enterprise Number
	// assigned to Anapaya Systems, PEN 55324.
	//
	//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//      |      OPTION_VENDOR_OPTS       |           option-len          |
	//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//      |                       enterprise-number                       |
	//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//      /                          option-data                          /
	//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//
	// The IP address and the port of the discovery server are encoded as a sequence of code/length/value fields
	// as defined in RFC2132 section 2 "DHCP Option Field Format".
	// An IPv6 address is encoded as a 16 byte sequence with type code 3.
	// A UDP port is encoded as a 2 byte sequence with type code 2.
	//
	//    Code   Len   Vendor-specific information
	//   +-----+-----+-----+-----+---
	//   |  tc |  n  |  i1 |  i2 | ...
	//   +-----+-----+-----+-----+---
	//

	// Anapaya Systems Private Enterprise Number
	const AnapayaPEN = 55324
	type typeCode uint16
	const (
		typePort typeCode = iota + 2
		typeIPv6
	)

	if vsio.EnterpriseNumber != AnapayaPEN {
		err = fmt.Errorf("failed to parse DHCP Vendor Specific Option (17), "+
			"unexpected Vendor-ID, PEN:%d", vsio.EnterpriseNumber)
		return
	}
	for _, field := range vsio.VendorOpts {
		switch typeCode(field.Code()) {
		case typeIPv6:
			ip = field.ToBytes()
			if len(ip) != 16 ||
				(!ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() && !ip.IsPrivate()) {

				err = fmt.Errorf("failed to parse DHCPv6 Vendor-specific Information Option (17), "+
					"invalid IP: %s", ip.String())
				ip = nil
				return
			}
		case typePort:
			if len(field.ToBytes()) != 2 {
				err = fmt.Errorf("failed to parse DHCPv6 Vendor-specific Information Option (17), "+
					"port parse error: wrong length: %d byte(s)", len(field.ToBytes()))
				return
			}
			port = int(binary.BigEndian.Uint16(field.ToBytes()))
		default:
			// Undefined, skip over
			log.Debug("Skipping unknown DHCPv6 Vendor-specific Information Option (17) field type",
				"type", field.Code(), "length", len(field.ToBytes()))
		}
	}
	return
}
