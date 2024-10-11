package hinting

import (
	"slices"
	"strings"
)

func domainsFromHostnames(hostnames []string) (domains []string) {
	for _, hostname := range hostnames {
		labels := strings.Split(strings.TrimRight(hostname, "."), ".")
		// skip hostname label, not part of the search domain
		if len(labels) == 1 {
			domains = append(domains, "local")
			continue
		}
		domainString := ""
		slices.Reverse(labels)
		for _, label := range labels[:len(labels)-1] {
			if domainString == "" {
				domainString = label
				// do not add TLD to domains candidate list
				continue
			}
			domainString = strings.Join([]string{label, domainString}, ".")
			if !slices.Contains(domains, domainString) {
				domains = append(domains, domainString)
			}
		}
	}
	// order search domains by hostname from most specific to least specific,
	// a more specific search domains of an earlier hostname might sort after
	// a search domain derived from a later hostname.
	slices.Reverse(domains)
	return
}
