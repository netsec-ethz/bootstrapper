package hinting

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReverseLookupDomains(t *testing.T) {
	testCases := []struct {
		name   string
		values []struct {
			ip     netip.Addr
			domain string
		}
	}{
		{
			name: "ETHZ",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("129.132.19.216"), domain: "ethz.ch"},
				{ip: netip.MustParseAddr("82.130.64.0"), domain: "ethz.ch"},
				{ip: netip.MustParseAddr("148.187.192.0"), domain: "ethz.ch"},
			},
		},
		{
			name: "PU",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("66.180.178.131"), domain: "princeton.edu"},
				{ip: randIPFromCIDR("128.112.66.0/23"), domain: "princeton.edu"},
			},
		},
		{
			name: "VU",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("128.143.33.137"), domain: "virginia.edu"},
				{ip: netip.MustParseAddr("128.143.33.144"), domain: "virginia.edu"},
				{ip: randIPFromCIDR("128.143.0.128/25"), domain: "virginia.edu"},
			},
		},
		{
			name: "SWITCH",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("130.59.31.80"), domain: "switch.ch"},
				{ip: randIPFromCIDR("130.59.2.128/25"), domain: "switch.ch"},
			},
		},
		{
			name: "KREONET",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("134.75.254.11"), domain: "kreonet.net"},
				{ip: netip.MustParseAddr("134.75.254.12"), domain: "kreonet.net"},
			},
		},
		{
			name: "KU",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("163.152.6.10"), domain: "korea.ac.kr"},
				{ip: randIPFromCIDR("163.152.6.16/29"), domain: "korea.ac.kr"},
			},
		},
	}

	for _, tc := range testCases {
		t.Log(tc.name)
		for _, v := range tc.values {
			t.Log(v.ip)
			res := reverseLookupDomains(v.ip)
			t.Log(res)
			assert.Subset(t, res, []string{v.domain}, "")
		}
	}
}

func TestReverseLookupWHOIS(t *testing.T) {

	testCases := []struct {
		name   string
		values []struct {
			ip     netip.Addr
			domain string
		}
	}{
		{
			name: "ETHZ",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("129.132.19.216"), domain: "ethz.ch"},
			},
		},
		{
			name: "PU",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("128.112.0.11"), domain: "princeton.edu"},
			},
		},
		{
			name: "VU",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("128.143.3.126"), domain: "virginia.edu"},
			},
		},
		{
			name: "SWITCH",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("130.59.31.35"), domain: "switch.ch"},
			},
		},
		{
			name: "KREONET",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("203.250.215.48"), domain: "kreonet.net"},
			},
		},
		{
			name: "KU",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("163.152.6.1"), domain: "korea.ac.kr"},
			},
		},
	}
	for _, tc := range testCases {
		t.Log(tc.name)
		for _, v := range tc.values {
			t.Log(v.ip)
			res := reverseLookupWHOIS(v.ip)
			t.Log(res)
			assert.Subset(t, res, []string{v.domain},
				"WHOIS record for IP `%s` does not contain contact information with the domain `%s`.\n"+
					"Run `go test -v -run TestWHOISInfo ./hinting/dns_search_domain_fallbacks_test.go -args IP domain`"+
					" to debug WHOIS information for `IP` and expected `domain`.",
				v.ip, v.domain)
		}
	}
}

func TestWHOISInfo(t *testing.T) {
	if !strings.Contains(fmt.Sprintln(os.Args), "-test.run=") {
		return
	}
	// Manual test for debugging with -run
	args := strings.Fields(strings.Split(fmt.Sprintln(os.Args), "-test.run=")[1])
	if len(args) == 1 {
		// Do not run when not explicitly called with test arguments.
		return
	}
	if len(args) != 3 {
		assert.FailNow(t, "Call TestWHOISInfo with"+
			"`go test -v -run TestWHOISInfo ./hinting/dns_search_domain_fallbacks_test.go -args IP domain`",
			"args: %s", os.Args)
	}
	arg1 := netip.MustParseAddr(args[1])
	arg2 := args[2]
	addr := arg1
	response, err := resolveWHOISRedirects(addr, ianaWHOIS)
	if err != nil {
		assert.FailNow(t, "WHOIS lookup failed", "err: %s", err)
	}
	domains := extractEmailDomains(response)
	assert.Subset(t, domains, []string{arg2},
		"WHOIS record for IP `%s` does not contain contact information with the domain `%s`.\n"+
			"Full WHOIS: %s",
		arg1, arg2, response)
}

func TestDomainsFromHostnamesDerivation(t *testing.T) {
	testCases := []struct {
		name   string
		values []struct {
			hostnames []string
			domains   []string
		}
	}{
		{
			name: "ETHZ",
			values: []struct {
				hostnames []string
				domains   []string
			}{
				{hostnames: []string{"82-130-64-0.net4.ethz.ch."}, domains: []string{"net4.ethz.ch", "ethz.ch"}},
				{hostnames: []string{"service-id-api-cd-dcz1-server-4-b.ethz.ch."}, domains: []string{"ethz.ch"}},
				{hostnames: []string{"cms-publish."}, domains: []string{"local"}},
			},
		},
		{
			name: "KU",
			values: []struct {
				hostnames []string
				domains   []string
			}{
				{hostnames: []string{"60.korea.ac.kr.", "sub.korea.ac.kr."}, domains: []string{"korea.ac.kr"}},
			},
		},
	}

	for _, tc := range testCases {
		t.Log(tc.name)
		for _, v := range tc.values {
			t.Log(v.hostnames)
			res := domainsFromHostnames(v.hostnames)
			t.Log(res)
			assert.EqualValues(t, v.domains, res, "")
		}
	}
}

func TestSearchDomainFallbacks(t *testing.T) {
	dnsChanReadable := dispatcher.getDNSConfig()
	var regular []DNSInfo
	var fallback []DNSInfo

	// get info from happy path
	r := <-dnsChanReadable
	regular = append(regular, r)
	// wait for dnsInfoDone to be closed to move to fallback
	time.Sleep(DNSInfoTimeout)

	// get info from fallback
	select {
	case <-dnsInfoFallbackDone:
		// Fallback timed out
	case r, ok := <-dnsChanReadable:
		if ok {
			fallback = append(fallback, r)
		}
	}

	t.Log(regular)
	t.Log(fallback)
	assert.Condition(t, func() bool { return len(regular) != 0 || len(fallback) != 0 },
		"Both regular host system and DNS based DNS Search Domain discovery failed.")
}

func TestDNSLookupExternalIP(t *testing.T) {
	ip, err := queryExternalIP()
	assert.NoError(t, err, "queryExternalIP() failed with error %s.", err)
	assert.NotEmpty(t, ip, "queryExternalIP() did not return any external IP.")
}

func TestDNSLookupAkaNS(t *testing.T) {
	ns, err := getAkaNS()
	assert.NoError(t, err, "getAkaNS() failed with error %s.", err)
	assert.NotEmpty(t, ns, "getAkaNS() did not return the nameserver IP.")
}

// randIPFromCIDR returns a random host IP in the subnet specified by the CIDR
func randIPFromCIDR(cidr string) (ip netip.Addr) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	ip, ok := netip.AddrFromSlice(ipNet.IP)
	if !ok {
		return
	}
	var randBytes []byte
	randBytes = make([]byte, net.IPv6len)
	_, err = rand.Read(randBytes)
	if err != nil {
		return
	}
	if ip.Is4() {
		randBytes = randBytes[:net.IPv4len]
	}
	randomIP := net.IP(randBytes)
	maskedIP := randomIP.Mask(invertMask(ipNet.Mask))
	if len(ipNet.IP) != len(maskedIP) {
		return
	}
	for i := range ipNet.IP {
		randomIP[i] = ipNet.IP[i] | maskedIP[i]
	}
	return netip.MustParseAddr(randomIP.String())
}

func invertMask(mask net.IPMask) (invertedMask net.IPMask) {
	invertedMask = make(net.IPMask, len(mask))
	for i, b := range mask {
		invertedMask[i] = 0xff ^ b
	}
	return
}
