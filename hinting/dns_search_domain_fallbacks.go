package hinting

import (
	"net"
	"net/netip"
	"slices"
	"strings"
)

// getFallbackSearchDomains provides DNS search domain candidates to dnsChanWritable.
// The results are only retrieved and returned if no DNS search domains were provided by
// the dispatcher DNSInfo channel. The number of external entities contacted is minimized.
// The domains are obtained from reverse DNS lookups and alternatively whois contact info,
// and returned along with the resolvers learned from the dispatcher DNSInfo channel.
func getFallbackSearchDomains(dnsChanWritable chan<- DNSInfo) {
	resolverSet := make(map[netip.Addr]struct{})
	searchDomainSet := make(map[string]struct{})
	// fallback for DNS search domains was started, so dnsInfoDispatcher hinting.dispatcher
	// was already started.
	dnsChanReadable := dispatcher.getDNSConfig()
Fallback:
	for {
		select {
		case dnsInfo := <-dnsChanReadable:
			// collect info from happy path
			for _, resolver := range dnsInfo.resolvers {
				resolverSet[resolver] = struct{}{}
			}
			for _, searchDomain := range dnsInfo.searchDomains {
				searchDomainSet[searchDomain] = struct{}{}
			}
		case <-dnsInfoDone:
			// start with fallback
			break Fallback
		}
	}
	if len(searchDomainSet) > 0 {
		// do not attempt fallback as authoritative locally configured
		// search domains were found.
		return
	}

	// Collect domain information from DNS reverse lookup
	ips := getPublicAddresses()
	if len(ips) == 0 {
		// attempt fallback to reverse lookup of externally observed IP,
		// if all configured IPs are private.
		ip, err := queryExternalIP()
		if err == nil {
			ips = append(ips, *ip)
		}
	}

	for _, ip := range ips {
		domains := reverseLookupDomains(ip)
		for _, searchDomain := range domains {
			searchDomainSet[searchDomain] = struct{}{}
		}
	}

	resolvers := make([]netip.Addr, 0, len(resolverSet))
	for k := range resolverSet {
		resolvers = append(resolvers, k)
	}
	searchDomains := make([]string, 0, len(searchDomainSet))
	for k := range searchDomainSet {
		searchDomains = append(searchDomains, k)
	}
	dnsInfo := DNSInfo{resolvers: resolvers, searchDomains: searchDomains}
	dnsInfoWriters.Add(1)
	select {
	case <-dnsInfoFallbackDone:
		// Ignore dnsInfo value, done publishing
	default:
		dnsChanWritable <- dnsInfo
	}
	dnsInfoWriters.Done()
	return
}

func getPublicAddresses() (ips []netip.Addr) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, err := netip.ParseAddr(addr.String())
			if err != nil {
				continue
			}
			if !ip.IsPrivate() {
				ips = append(ips, ip)
			}
		}
	}
	return
}

func domainsFromHostnames(hostnames []string) (domains []string) {
	for _, hostname := range hostnames {
		labels := strings.Split(strings.TrimRight(hostname, "."), ".")
		// skip hostname label, not part of the search domain
		if len(labels) == 1 {
			domains = append(domains, "local")
			continue
		}
		domain := ""
		slices.Reverse(labels)
		for _, label := range labels[:len(labels)-1] {
			if domain == "" {
				domain = label
				// do not add TLD to domains candidate list
				continue
			}
			domain = strings.Join([]string{label, domain}, ".")
			// Filter out Effective ccTLDs (of the form "co.uk"), as we are only interested in the ETLD+1 domains
			if 5 == len(domain) && // TODO: complete TLD specific exceptions, or directly use PSL
				(label == "co" ||
					label == "ac" ||
					label == "re" ||
					label == "ne") {
				// do not add country-code second-level ETLD domains to domains candidate list
				continue
			}
			if !slices.Contains(domains, domain) {
				domains = append(domains, domain)
			}
		}
	}
	// order search domains by hostname from most specific to least specific,
	// a more specific search domain of an earlier hostname might sort after
	// a search domain derived from a later hostname.
	slices.Reverse(domains)
	return
}
