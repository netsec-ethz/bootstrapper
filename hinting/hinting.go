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
	"net"
	"runtime"

	"github.com/scionproto/scion/go/lib/log"
)

const (
	DiscoveryPort uint16 = 8041
)

type HintGenerator interface {
	Generate(chan<- net.IP)
}

func getLocalDNSConfig() {
	var dnsInfo *DNSInfo
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "aix", "dragonfly", "hurd", "illumos", "netbsd", "openbsd", "solaris", "zos":
		// "linux": https://wiki.debian.org/resolv.conf
		// "darwin": https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/res_send.3.html
		// "freebsd": https://docs.freebsd.org/en_US.ISO8859-1/books/handbook/configtuning-configfiles.html
		// Untested:
		// "aix": https://www.ibm.com/support/knowledgecenter/en/ssw_aix_71/filesreference/resolv.conf.html
		// "dragonfly": https://leaf.dragonflybsd.org/cgi/web-man?command=resolvconf&section=8
		// "hurd": https://www.gnu.org/software/hurd/users-guide/using_gnuhurd.html
		// "illumos": https://illumos.org/man/4/resolv.conf
		// "netbsd": https://man.netbsd.org/resolvconf.8
		// "openbsd": https://man.openbsd.org/resolv.conf.5
		// "solaris": https://support.oracle.com/knowledge/Oracle%20Database%20Products/433870_1.html
		// "zos": https://www.ibm.com/support/knowledgecenter/SSLTBW_2.3.0/com.ibm.zos.v2r3.halz002/resolver_srch_orders_unix_base.htm
		log.Debug("Getting local DNS configuration from resolv.conf")
		dnsInfo = getDNSConfigResolv()
	case "windows":
		// "windows": https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
		log.Debug("Getting local DNS configuration from IP_ADAPTER_ADDRESSES")
	default:
		// "android": https://gist.github.com/ernesto-jimenez/8042366
		// "plan": https://9p.io/wiki/plan9/Network_configuration/index.html
		log.Debug("Cannot easily get local DNS configuration from OS.", "OS", runtime.GOOS)
	}
	if dnsInfo != nil {
		dnsServersChan <- *dnsInfo
	}
	return
}

type MOCKHintGeneratorConf struct {
	Enable  bool
	Address string
}

var _ HintGenerator = (*MockHintGenerator)(nil)

type MockHintGenerator struct {
	cfg *MOCKHintGeneratorConf
}

func NewMockHintGenerator(cfg *MOCKHintGeneratorConf) *MockHintGenerator {
	return &MockHintGenerator{cfg}
}

func (m *MockHintGenerator) Generate(ipHintsChan chan<- net.IP) {
	if !m.cfg.Enable {
		return
	}
	ip := net.ParseIP(m.cfg.Address)
	if ip == nil {
		log.Error("Invalid IP Address for mock generator", "ip", ip)
	} else {
		ipHintsChan <- ip
	}
}
