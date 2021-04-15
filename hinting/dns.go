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
	"math/rand"
	"net"
	"sort"
	"strconv"

	log "github.com/inconshreveable/log15"
	"github.com/miekg/dns"
)

const (
	discoveryServiceDNSName string = "_sciondiscovery._tcp"
	discoveryDDDSDNSName    string = "x-sciondiscovery:tcp"
)

type DNSInfo struct {
	resolvers     []string
	searchDomains []string
}

type DNSHintGeneratorConf struct {
	EnableSD    bool `toml:"enable_sd"`
	EnableNAPTR bool `toml:"enable_naptr"`
	EnableSRV   bool `toml:"enable_srv"`
}

var _ HintGenerator = (*DNSSDHintGenerator)(nil)

// DNSSDHintGenerator implements the Domain Name System Service Discovery
type DNSSDHintGenerator struct {
	cfg *DNSHintGeneratorConf
}

func NewDNSSDHintGenerator(cfg *DNSHintGeneratorConf) *DNSSDHintGenerator {
	return &DNSSDHintGenerator{cfg}
}

func (g *DNSSDHintGenerator) Generate(ipHintsChan chan<- net.TCPAddr) {
	if !g.cfg.EnableSRV && !g.cfg.EnableSD && !g.cfg.EnableNAPTR {
		return
	}
	dnsChan := dispatcher.getDNSConfig()
	for dnsServer := range dnsChan {
		log.Debug("Using following resolvers for DNS hinting", "resolvers", dnsServer.resolvers)
		for _, resolver := range dnsServer.resolvers {
			for _, domain := range dnsServer.searchDomains {
				if g.cfg.EnableSRV {
					query := getDNSSDQuery(resolver, domain)
					resolveDNS(resolver, query, 0, dns.TypeSRV, ipHintsChan)
				}
				if g.cfg.EnableSD {
					query := getDNSSDQuery(resolver, domain)
					resolveDNS(resolver, query, 0, dns.TypePTR, ipHintsChan)
				}
				if g.cfg.EnableNAPTR {
					query := getDNSNAPTRQuery(resolver, domain)
					resolveDNS(resolver, query, 0, dns.TypeNAPTR, ipHintsChan)
				}
			}
		}
	}
	log.Info("DNS hinting done")
}

func getDNSSDQuery(resolver, domain string) string {
	query := discoveryServiceDNSName + "." + domain + "."
	log.Debug("DNS-SD", "query", query, "rr", dns.TypePTR, "resolver", resolver)
	return query
}

// Straightforward Naming Authority Pointer
func getDNSNAPTRQuery(resolver, domain string) string {
	query := domain + "."
	log.Debug("DNS-S-NAPTR", "query", query, "rr", dns.TypeNAPTR, "resolver", resolver)
	return query
}

func resolveDNS(resolver, query string, resultPort uint16, dnsRR uint16, ipHintsChan chan<- net.TCPAddr) {
	msg := new(dns.Msg)
	msg.SetQuestion(query, dnsRR)
	msg.RecursionDesired = true
	result, err := dns.Exchange(msg, resolver+":53")
	if err != nil {
		if dnsRR != dns.TypeAAAA {
			log.Error("DNS-SD failed", "err", err)
		} else {
			log.Info("DNS-SD failed for IPv6", "err", err)
		}
		return
	}

	var serviceRecords []dns.SRV
	var naptrRecords []dns.NAPTR
	for _, answer := range result.Answer {
		log.Debug("DNS", "answer", answer)
		switch answer.(type) {
		case *dns.PTR:
			result := *(answer.(*dns.PTR))
			resolveDNS(resolver, result.Ptr, resultPort, dns.TypeSRV, ipHintsChan) // XXX: Set max recursion depth
		case *dns.NAPTR:
			result := *(answer.(*dns.NAPTR))
			if result.Service == discoveryDDDSDNSName {
				naptrRecords = append(naptrRecords, result)
				if resultPort == 0 {
					resultPort = queryTXTPortRecord(resolver, query)
				}
			}
		case *dns.SRV:
			result := *(answer.(*dns.SRV))
			serviceRecords = append(serviceRecords, result)
		case *dns.A:
			result := *(answer.(*dns.A))
			addr := net.TCPAddr{IP: result.A, Port: int(resultPort)}
			log.Info("DNS hint", "Addr", addr)
			ipHintsChan <- addr
		case *dns.AAAA:
			result := *(answer.(*dns.AAAA))
			addr := net.TCPAddr{IP: result.AAAA, Port: int(resultPort)}
			log.Info("DNS hint", "Addr", addr)
			ipHintsChan <- addr
		}
	}

	if len(serviceRecords) > 0 {
		sort.Sort(byPriority(serviceRecords))

		log.Debug("DNS Resolving service records", "serviceRecords", serviceRecords)
		for _, answer := range serviceRecords {
			resolveDNS(resolver, answer.Target, answer.Port, dns.TypeAAAA, ipHintsChan)
			resolveDNS(resolver, answer.Target, answer.Port, dns.TypeA, ipHintsChan)
		}
	}

	if len(naptrRecords) > 0 {
		sort.Sort(byOrder(naptrRecords))

		log.Debug("DNS Resolving NAPTR records", "serviceRecords", naptrRecords)
		for _, answer := range naptrRecords {
			switch answer.Flags {
			case "":
				resolveDNS(resolver, answer.Replacement, resultPort, dns.TypeNAPTR, ipHintsChan)
			case "A":
				resolveDNS(resolver, answer.Replacement, resultPort, dns.TypeAAAA, ipHintsChan)
				resolveDNS(resolver, answer.Replacement, resultPort, dns.TypeA, ipHintsChan)
			case "S":
				resolveDNS(resolver, answer.Replacement, resultPort, dns.TypeSRV, ipHintsChan)
			}
		}
	}
}

func queryTXTPortRecord(resolver, query string) (resultPort uint16) {
	msg := new(dns.Msg)
	msg.SetQuestion(query, dns.TypeTXT)
	msg.RecursionDesired = false
	res, err := dns.Exchange(msg, resolver+":53")
	if err != nil {
		log.Error("DNS-SD failed to resolve TXT record for S-NAPTR", "err", err)
	}
	for _, ans := range res.Answer {
		if txtRecords, ok := ans.(*dns.TXT); ok {
			for _, txt := range txtRecords.Txt {
				port, err := strconv.ParseUint(txt, 10, 16)
				if err != nil {
					log.Error("DNS-SD failed to convert TXT record to a valid port", "err", err)
					continue
				}
				resultPort = uint16(port)
				break
			}
		}
		if resultPort != 0 {
			break
		}
	}
	return
}

// Order as defined by DNS-SD RFC
type byPriority []dns.SRV

func (s byPriority) Len() int {
	return len(s)
}

func (s byPriority) Less(i, j int) bool {
	if s[i].Priority < s[j].Priority {
		return true
	} else if s[j].Priority < s[i].Priority {
		return false
	} else {
		if s[i].Weight == 0 && s[j].Weight == 0 {
			return rand.Intn(2) == 0
		}
		max := int(s[i].Weight) + int(s[j].Weight)
		return rand.Intn(max) < int(s[i].Weight)
	}
}

func (s byPriority) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Order as defined by RFC
type byOrder []dns.NAPTR

func (s byOrder) Len() int {
	return len(s)
}

func (s byOrder) Less(i, j int) bool {
	if s[i].Order < s[j].Order {
		return true
	} else if s[j].Order < s[i].Order {
		return false
	} else {
		return s[i].Preference < s[j].Preference
	}
}

func (s byOrder) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
