package hinting

import (
	"github.com/stretchr/testify/assert"
	"net/netip"
	"testing"
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
			},
		},
		{
			name: "SWITCH",
			values: []struct {
				ip     netip.Addr
				domain string
			}{
				{ip: netip.MustParseAddr("130.59.31.80"), domain: "switch.ch"},
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
			},
		},
		{
			name: "ETHZ",
			values: []struct {
				hostnames []string
				domains []string
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
