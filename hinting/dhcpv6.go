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
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"

	log "github.com/inconshreveable/log15"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/client6"
	"github.com/insomniacslk/dhcp/iana"
)

type DUIDType string

const (
	duidLL   DUIDType = "DUID-LL"   // DUID based on Link-layer Address
	duidLLT  DUIDType = "DUID-LLT"  // DUID based on Link-layer Address Plus Time (default)
	duidEN   DUIDType = "DUID-EN"   // (Not implemented) DUID assigned by vendor based on Enterprise Number
	duidUUID DUIDType = "DUID-UUID" // (Not implemented) DHCPv6 Unique Identifier based on Universally Unique IDentifier
)

type DHCPv6HintGeneratorConf struct {
	Enable   bool     `toml:"Enable"`
	ClientID string   `toml:"client_id,omitempty"` // Fixed hex string for the client DUID, no separators, no 0x prefix
	Duid     DUIDType `toml:"DUID_type,omitempty"` // Type of DUID to compute dynamically
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
	// request vendor options
	modifiers := []dhcpv6.Modifier{dhcpv6.WithRequestedOptions(dhcpv6.OptionVendorOpts)}
	// set configured client DUID
	if g.cfg.ClientID != "" || g.cfg.Duid != "" {
		duid, err := getDuid(g)
		if err != nil {
			log.Error("Error setting DHCPv6 client DUID", "err", err)
		} else {
			modifiers = append(modifiers, dhcpv6.WithClientID(duid))
		}
	}
	conv, err := client.Exchange(g.iface.Name, modifiers...)
	if err != nil {
		log.Error("Error during DHCPv6 solicit interaction", "err", err)
		return
	}
	go g.dispatchDNSInfo(conv, dnsInfoChan)
	g.dispatchIPHints(conv, ipHintsChan)
	log.Info("DHCPv6 hinting done")
}

func getDuid(g *DHCPv6HintGenerator) (duid dhcpv6.Duid, err error) {
	if g.cfg.ClientID != "" {
		var clientID []byte
		clientID, err = hex.DecodeString(g.cfg.ClientID)
		if err != nil {
			return
		}
		var duidp *dhcpv6.Duid
		duidp, err = dhcpv6.DuidFromBytes(clientID)
		if err != nil {
			return
		}
		return *duidp, nil
	}
	switch g.cfg.Duid {
	case duidLL:
		duid = dhcpv6.Duid{
			Type:          dhcpv6.DUID_LL,
			HwType:        iana.HWTypeEthernet,
			LinkLayerAddr: g.iface.HardwareAddr,
		}
	case duidLLT:
		duid = dhcpv6.Duid{
			Type:          dhcpv6.DUID_LLT,
			HwType:        iana.HWTypeEthernet,
			Time:          dhcpv6.GetTime(),
			LinkLayerAddr: g.iface.HardwareAddr,
		}
	case duidEN, duidUUID:
		// Not implemented
		log.Error("Unsupported DUID type %s, set DUID directly as `client_id` " +
			"or use the supported `DUID-LL` and `DUID-LLT`types.", "type", g.cfg.Duid)
		err = fmt.Errorf("not implemented DUID type: %s", g.cfg.Duid)
	default:
		err = fmt.Errorf("invalid DUID type: %s", g.cfg.Duid)
	}
	return
}

func (g *DHCPv6HintGenerator) dispatchIPHints(conv []dhcpv6.DHCPv6, ipHintChan chan<- net.TCPAddr) {
	if !g.cfg.Enable {
		return
	}
	for _, p := range conv {
		if p.Type() != dhcpv6.MessageTypeReply {
			continue
		}
		options := p.GetOption(dhcpv6.OptionVendorOpts)
		for _, option := range options {
			if oVSIO, ok := option.(*dhcpv6.OptVendorOpts); ok {
				ip, port, err := parseBootstrapVendorInformationOption(*oVSIO)
				if err != nil {
					log.Error("Failed to parse DHCPv6 Vendor-specific Information Option (17)", "err", err)
					continue
				}
				addr := net.TCPAddr{IP: ip.AsSlice(), Port: port}
				log.Info("DHCPv6 vi-encap hint", "Addr", addr)
				ipHintChan <- addr
			}
		}
	}
}

func (g *DHCPv6HintGenerator) dispatchDNSInfo(conv []dhcpv6.DHCPv6, dnsChan chan<- DNSInfo) {
	resolvers := make(map[netip.Addr]struct{})
	searchDomains := make(map[string]struct{})
	for _, p := range conv {
		options := p.GetOption(dhcpv6.OptionDNSRecursiveNameServer)
		for _, option := range options {
			if oRDNS, ok := option.(*dhcpv6.OptDNSRecursiveNameServer); ok {
				for _, resolver := range oRDNS.NameServers {
					if resolver, ok := netip.AddrFromSlice(resolver); ok {
						resolvers[resolver] = struct{}{}
					}
				}
			}
		}
		options = p.GetOption(dhcpv6.OptionDomainSearchList)
		for _, option := range options {
			if oDNSSL, ok := option.(*dhcpv6.OptDomainSearchList); ok {
				for _, searchDomain := range oDNSSL.DomainSearchList.Labels {
					searchDomains[searchDomain] = struct{}{}
				}
			}
		}
	}
	if len(resolvers) < 1 {
		return
	}
	dnsInfo := DNSInfo{resolvers: []string{}, searchDomains: []string{}}
	for r := range resolvers {
		dnsInfo.resolvers = append(dnsInfo.resolvers, r.String())
	}
	for d := range searchDomains {
		dnsInfo.searchDomains = append(dnsInfo.searchDomains, d)
	}
	log.Debug("DHCPv6 DNS resolver option", "resolvers", dnsInfo.resolvers)
	log.Debug("DHCPv6 DNS search domain option", "searchDomains", dnsInfo.searchDomains)
	dnsInfoWriters.Add(1)
	select {
	case <-dnsInfoDone:
		// Ignore dnsInfo value, done publishing
	default:
		dnsChan <- dnsInfo
	}
	dnsInfoWriters.Done()
}

func parseBootstrapVendorInformationOption(vsio dhcpv6.OptVendorOpts) (ip netip.Addr, port int, err error) {
	// Parses a Vendor-specific Information Option for DHCPv6 as defined in RFC3315.
	// `vsio.VendorOpts.ToBytes()` should only contains the option's values byte stream, starting WITHOUT the PEN,
	// and includes the 2-byte option code and 2-byte option length for each field.
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
	//    Code         Len         Vendor-specific information
	//   +-----+-----+-----+-----+-----+-----+---
	//   |     tc    |     n     |  i1 |  i2 | ...
	//   +-----+-----+-----+-----+-----+-----+---
	//

	const (
		typePort dhcpv6.OptionCode = iota + 2
		typeIPv6
	)

	if vsio.EnterpriseNumber != anapayaPEN {
		err = fmt.Errorf("unexpected Vendor-ID, PEN:%d", vsio.EnterpriseNumber)
		return
	}
	for _, field := range vsio.VendorOpts {
		switch field.Code() {
		case typeIPv6:
			var ok bool
			ip, ok = netip.AddrFromSlice(field.ToBytes())
			if !ok || !ip.Is6() {
				err = fmt.Errorf("IPv6 parse error: wrong length: %d byte(s)", len(field.ToBytes()))
				return
			}
		case typePort:
			if len(field.ToBytes()) != 2 {
				err = fmt.Errorf("port parse error: wrong length: %d byte(s)", len(field.ToBytes()))
				return
			}
			port = int(binary.BigEndian.Uint16(field.ToBytes()))
		default:
			// Undefined, skip over
			log.Debug("Skipping unknown DHCPv6 Vendor-specific Information Option (17) field type",
				"type", field.Code(), "length", len(field.ToBytes()))
		}
	}
	if !ip.IsValid() || !ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() && !ip.IsPrivate() {
		err = fmt.Errorf("invalid IPv6 address type: %s", ip)
		ip = netip.Addr{}
		return
	}
	return
}
