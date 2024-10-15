package hinting

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

var (
	akamaiDomain     = "akamai.net."
	akamaiNameserver = "zh.akamaitech.net"
	quad9DNSResolver = "9.9.9.9:53"
)

// reverseLookupDomains obtains the reverse DNS entries for IP addr to derive DNS search domain candidates.
// Uses in-addr.arpa and ip6.arpa domains to lookup reverse pointer records.
func reverseLookupDomains(addr netip.Addr) (domains []string) {
	hostnames, err := net.LookupAddr(addr.String())
	if err != nil {
		return
	}
	return domainsFromHostnames(hostnames)
}

// Fallbacks to obtain an external public IP address using DNS.

// getAkaNS returns one random authoritative nameserver for akamai.net.
func getAkaNS() (nameserver string, err error) {
	// try default resolver
	resolver := net.Resolver{}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(DNSInfoTimeoutFallback-DNSInfoTimeout))
	defer cancel()
	nameservers, err := resolver.LookupNS(ctx, akamaiDomain)
	if err == nil {
		return nameservers[rand.Intn(len(nameservers))].Host, err
	}

	m := new(dns.Msg)
	m.SetQuestion(akamaiDomain, dns.TypeNS)
	// try Quad9
	in, err := dns.Exchange(m, quad9DNSResolver)
	if err != nil {
		return "", err
	}
	if len(in.Answer) < 1 {
		err = errors.New("getAkaNS: No DNS RR answer")
		return "", err
	}
	if ns, ok := in.Answer[rand.Intn(len(in.Answer))].(*dns.NS); ok {
		return ns.Ns, nil
	}
	return "", errors.New("getAkaNS: Invalid NS record")
}

// getExternalIP returns the external IP used for DNS resolution of the executing host using nameserver.
func getExternalIP(nameserver string) (addr netip.Addr, err error) {
	if nameserver == "" {
		// Default external authoritative nameserver
		nameserver = akamaiNameserver
	}
	m := new(dns.Msg)
	// The akamai.net nameservers reply to queries for the name `whoami`
	// with the IP address of the host sending the query.
	m.SetQuestion("whoami.akamai.net.", dns.TypeA)
	in, err := dns.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if err != nil {
		return netip.Addr{}, err
	}
	if len(in.Answer) < 1 {
		err = errors.New("getExternalIP: No DNS RR answer")
		return netip.Addr{}, err
	}
	if a, ok := in.Answer[0].(*dns.A); ok {
		if addr, ok := netip.AddrFromSlice(a.A); ok {
			return addr, nil
		}
		return netip.Addr{}, &net.AddrError{Err: "invalid IP address", Addr: a.A.String()}
	}
	return netip.Addr{}, errors.New("getExternalIP: Invalid A record")
}

// queryExternalIP returns the external IP used for DNS resolution of the executing host.
func queryExternalIP() (addr netip.Addr, err error) {
	// Try with default NS
	addr, err = getExternalIP("")
	if err != nil {
		// try with looking up alternative NS
		ns, err := getAkaNS()
		if err == nil {
			addr, err = getExternalIP(ns)
		}
	}
	return
}
