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
	"errors"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"

	log "github.com/inconshreveable/log15"
)

func getDNSConfigIPHlpAPI() (dnsInfo *DNSInfo) {
	const flags = 0
	// Sample code uses 15000, we expect the reply to fit in 20 entries
	size := uint32(unsafe.Sizeof(windows.IpAdapterAddresses{}) * 20)
	var ias []byte
	for i := 0; i < 3; i += 1 {
		ias = make([]byte, size)
		errcode := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&ias[0])), &size)
		if errcode == nil {
			break
		}
		if errcode != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(ias)) {
			// reply should have fitted in ias, but still got an error
			log.Error("Failed to get local DNS configuration from IP_ADAPTER_ADDRESSES", "err", errcode)
			return nil
		}
		ias = nil
	}
	if ias == nil {
		return nil
	}
	var DNSServers []netip.Addr
	var DNSSearchDomains []string
	for pipaa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&ias[0])); pipaa != nil; pipaa = pipaa.Next {
		if pipaa.FirstDnsServerAddress != nil {
			for ds := pipaa.FirstDnsServerAddress; ds != nil; ds = ds.Next {
				dsIP := ds.Address.IP()
				if dsIP != nil {
					dsIP, _ := netip.AddrFromSlice(dsIP)
					DNSServers = append(DNSServers, dsIP)
				}
			}
		}
		if pipaa.DnsSuffix != nil {
			// pipaa.DnsSuffix is null terminated
			dsd := windows.UTF16PtrToString(pipaa.DnsSuffix)
			// avoid passing on garbage if pipaa.DnsSuffix wasn't properly null terminated
			if len(dsd) < 256 {
				DNSSearchDomains = append(DNSSearchDomains, dsd)
			}
		}
	}
	if len(DNSServers) > 0 || len(DNSSearchDomains) > 0 {
		dnsInfo = &DNSInfo{resolvers: DNSServers, searchDomains: DNSSearchDomains}
	}
	return
}

func getDNSConfigResolv() (dnsInfo *DNSInfo) {
	log.Error("Resolv not supported on current OS", "err",
		errors.New("only reading from IP_ADAPTER_ADDRESSES is implemented for this OS,"+
			" use getDNSConfigIPHlpAPI to get local DNS config"))
	return nil
}
