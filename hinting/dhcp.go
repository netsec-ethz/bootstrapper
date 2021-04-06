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
	"encoding/binary"
	"fmt"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/rfc1035label"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
)

type DHCPHintGeneratorConf struct {
	Enable bool `toml:"Enable"`
}

var _ HintGenerator = (*DHCPHintGenerator)(nil)

type DHCPHintGenerator struct {
	cfg   *DHCPHintGeneratorConf
	iface *net.Interface
}

func NewDHCPHintGenerator(cfg *DHCPHintGeneratorConf, iface *net.Interface) *DHCPHintGenerator {
	return &DHCPHintGenerator{cfg, iface}
}

func (g *DHCPHintGenerator) Generate(ipHintsChan chan<- net.TCPAddr) {
	if !g.cfg.Enable {
		return
	}
	log.Info("DHCP Probing", "interface", g.iface.Name)
	p, err := g.createDHCPRequest()
	if err != nil {
		log.Error("Error creating DHCP request", "err", err)
		return
	}
	ack, err := g.sendReceive(p, g.iface.Name)
	if err != nil {
		log.Error("Error creating sending/receiving DHCP request/response", "err", err)
		return
	}
	go g.dispatchDNSInfo(ack, dnsInfoChan)
	g.dispatchIPHints(ack, ipHintsChan)
	log.Info("DHCP hinting done")
}

func (g *DHCPHintGenerator) createDHCPRequest() (*dhcpv4.DHCPv4, error) {
	localIPs, err := dhcpv4.IPv4AddrsForInterface(g.iface)
	if err != nil || len(localIPs) == 0 {
		return nil, common.NewBasicError("DHCP hinter could not get local IPs", err)
	}
	p, err := dhcpv4.NewInform(g.iface.HardwareAddr, localIPs[0], dhcpv4.WithRequestedOptions(
		dhcpv4.OptionDefaultWorldWideWebServer,
		dhcpv4.OptionDomainNameServer,
		dhcpv4.OptionDNSDomainSearchList,
		dhcpv4.OptionVendorIdentifyingVendorSpecific))
	if err != nil {
		return nil, common.NewBasicError("DHCP hinter failed to build network packet", err)
	}
	return p, nil
}

func (g *DHCPHintGenerator) dispatchIPHints(ack *dhcpv4.DHCPv4, ipHintChan chan<- net.TCPAddr) {
	if !g.cfg.Enable {
		return
	}
	ips := dhcpv4.GetIPs(dhcpv4.OptionDefaultWorldWideWebServer, ack.Options)
	for _, ip := range ips {
		log.Info("DHCP hint", "IP", ip)
		ipHintChan <- net.TCPAddr{IP: ip}
	}
	VIVSBytes := ack.GetOneOption(dhcpv4.OptionVendorIdentifyingVendorSpecific)
	dataLen := len(VIVSBytes)
	if dataLen > 0 {
		ip, port, err := parseBootstrapVendorOption(VIVSBytes)
		if err != nil {
			log.Error("Failed to parse Vendor Identifying Vendor Specific Option", "err", err)
			return
		}
		addr := net.TCPAddr{IP: ip, Port: port}
		log.Info("DHCP vi-encap hint", "Addr", addr)
		ipHintChan <- addr
	}
}

func (g *DHCPHintGenerator) dispatchDNSInfo(ack *dhcpv4.DHCPv4, dnsChan chan<- DNSInfo) {
	resolvers := dhcpv4.GetIPs(dhcpv4.OptionDomainNameServer, ack.Options)
	log.Info("DHCP DNS resolver option", "resolvers", resolvers)
	rawSearchDomains := ack.Options.Get(dhcpv4.OptionDNSDomainSearchList)
	searchDomains, err := rfc1035label.FromBytes(rawSearchDomains)
	if err != nil {
		log.Error("DHCP failed to to read search domains", "err", err)
		// don't return, proceed without search domains
	}
	log.Info("DHCP DNS search domain option", "searchDomains", searchDomains)
	dnsInfo := DNSInfo{}
	for _, item := range resolvers {
		dnsInfo.resolvers = append(dnsInfo.resolvers, item.String())
	}
	if searchDomains != nil {
		for _, item := range searchDomains.Labels {
			dnsInfo.searchDomains = append(dnsInfo.searchDomains, item)
		}
	} else {
		dnsInfo.searchDomains = []string{}
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

func parseBootstrapVendorOption(optionBytes []byte) (ip net.IP, port int, err error) {
	// Parses a Vendor-Identifying Vendor Option for DHCPv4 as defined in RFC3925.
	// `optionsBytes` should only contains the option's values byte stream, starting with the PEN,
	// and be already stripped of the 1-byte option code and 1-byte option length.
	//
	//
	// The enterprise number used to identify the option is the Private Enterprise Number
	// assigned to Anapaya Systems, PEN 55324.
	//
	//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |  option-code  |  option-len   |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |      enterprise-number1       |
	//   |                               |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |   data-len1   |               |
	//   +-+-+-+-+-+-+-+-+               |
	//   /      vendor-class-data1       /
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//
	// The IP address and the port of the discovery server are encoded as a sequence of code/length/value fields
	// as defined in RFC2132 section 2 "DHCP Option Field Format".
	// An IPv4 address is encoded as a 4 byte sequence with type code 1.
	// A UDP port is encoded as a 2 byte sequence with code type 2.
	//
	//    Code   Len   Vendor-specific information
	//   +-----+-----+-----+-----+---
	//   |  tc |  n  |  i1 |  i2 | ...
	//   +-----+-----+-----+-----+---
	//

	// Anapaya Systems Private Enterprise Number
	const AnapayaPEN = 55324
	type typeCode uint8
	const (
		typeIPv4 typeCode = iota + 1
		typePort
	)

	buffLen := len(optionBytes)
	offset := 0
	if offset+4 > buffLen {
		err = fmt.Errorf("failed to parse DHCP Vendor Specific Option (125)")
		return
	}
	PEN := binary.BigEndian.Uint32(optionBytes[offset : offset+4])
	offset += 4
	if int(PEN) != AnapayaPEN {
		err = fmt.Errorf("failed to parse DHCP Vendor Specific Option (125), "+
			"unexpected Vendor-ID, PEN:%d", PEN)
		return
	}
	if offset+1 > buffLen {
		err = fmt.Errorf("failed to parse DHCP Vendor Specific Option (125), " +
			"missing data length")
		return
	}
	dataLen := int(optionBytes[offset])
	offset += 1
	if offset + dataLen > buffLen {
		err = fmt.Errorf("failed to parse DHCP Vendor Specific Option (125), " +
			"data length exceeds option buffer length")
		return
	}

	for offset+2 <= buffLen {
		typeCode := typeCode(optionBytes[offset])
		offset += 1
		typeLength := int(optionBytes[offset])
		offset += 1
		if offset+typeLength > buffLen || typeLength <= 0 {
			err = fmt.Errorf("failed to parse DHCP Vendor Specific Option (125), "+
				"wrong field length:%d", typeLength)
			return
		}
		switch typeCode {
		case typeIPv4:
			// IP address field
			var ipEncap dhcpv4.IP
			err = ipEncap.FromBytes(optionBytes[offset : offset+typeLength])
			if err != nil {
				err = fmt.Errorf("failed to parse DHCP Vendor Specific Option (125), "+
					"IP parse error: %w", err)
				return
			}
			ip = net.IP(ipEncap)
		case typePort:
			// Port field
			if typeLength != 2 {
				err = fmt.Errorf("failed to parse DHCP Vendor Specific Option (125), "+
					"port parse error: wrong length: %d byte(s)", typeLength)
				return
			}
			port = int(binary.BigEndian.Uint16(optionBytes[offset : offset+typeLength]))
		default:
			// Undefined, skip over
			log.Debug("Skipping unknown DHCP Vendor Specific Option type", "type", typeCode,
				"length", typeLength)
		}
		offset += typeLength
	}
	if offset != buffLen {
		log.Debug("Stray data after last field, ignored.", "offset", offset,
			"buffLen", buffLen)
	}
	return
}
