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
	"net/netip"
	"runtime"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
)

const (
	anapayaPEN             = 55324 // Anapaya Systems Private Enterprise Number
	DiscoveryPort  uint16  = 8041
	DNSInfoTimeout         = 8 * time.Second
	DNSInfoTimeoutFallback = 10 * time.Second
)

var (
	dnsInfoChan         = make(chan DNSInfo)
	dnsInfoDone         = make(chan struct{})
	dnsInfoFallbackDone = make(chan struct{})
	dnsInfoWriters      sync.WaitGroup

	dispatcher       *dnsInfoDispatcher
	singleDispatcher = &sync.Mutex{}
)

type HintGenerator interface {
	Generate(chan<- net.TCPAddr)
}

func getLocalDNSConfig(dnsChan chan<- DNSInfo) {
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
		dnsInfo = getDNSConfigIPHlpAPI()
	default:
		// "android": https://gist.github.com/ernesto-jimenez/8042366
		// "plan": https://9p.io/wiki/plan9/Network_configuration/index.html
		log.Debug("Cannot easily get local DNS configuration from OS.", "OS", runtime.GOOS)
	}
	if dnsInfo != nil {
		dnsInfoWriters.Add(1)
		select {
		case <-dnsInfoDone:
			// Ignore dnsInfo value, done publishing
		default:
			dnsChan <- *dnsInfo
		}
		dnsInfoWriters.Done()
	}
	return
}

type dnsInfoDispatcher struct {
	pubDone  chan struct{}
	subChans []chan DNSInfo
	sync.Mutex
}

// subscribes to dnsInfoChan dispatcher and returns subscriber channel
func (d *dnsInfoDispatcher) subscribe() <-chan DNSInfo {
	d.Lock()
	// guard the append to subChans, since it is being iterated on in publish()
	defer d.Unlock()
	subscriber := make(chan DNSInfo)
	select {
	case <-d.pubDone:
		close(subscriber)
		// don't add closed channel to subChans
		// return closed channel to unblock caller
		return subscriber
	default:
	}
	d.subChans = append(d.subChans, subscriber)
	return subscriber
}

// publish data feed dnsInfoChan to all subscribers
func (d *dnsInfoDispatcher) publish() {
	// Only retrieve local config once
	go getLocalDNSConfig(dnsInfoChan)

	d.pubDone = make(chan struct{})
	var openRequests sync.WaitGroup
	for i := range dnsInfoChan {
		d.Lock()
		// Publish value to all subscribers
		for _, s := range d.subChans {
			openRequests.Add(1)
			// Send on each subscriber at its own rate, ordering depends on the scheduler
			go func(requester chan DNSInfo, dnsInfo DNSInfo) {
				defer openRequests.Done()
				select {
				case requester <- dnsInfo:
				case <-d.pubDone:
					return
				}
			}(s, i)
		}
		d.Unlock()
	}
	// all done, nothing to publish anymore, close out publishing channels
	d.Lock()
	close(d.pubDone)
	d.Unlock()
	openRequests.Wait()
	d.Lock()
	for _, s := range d.subChans {
		close(s)
	}
	d.Unlock()
}

// getDNSConfig returns a channel providing DNSInfo
func (d *dnsInfoDispatcher) getDNSConfig() (dnsChan <-chan DNSInfo) {
	if d != nil {
		return d.subscribe()
	}
	return initDispatcher()
}

// initDispatcher initializes the dispatcher and returns subscriber channel
func initDispatcher() (dnsChan <-chan DNSInfo) {
	// Lazily create a single dispatcher
	singleDispatcher.Lock()
	defer singleDispatcher.Unlock()
	if dispatcher != nil {
		return dispatcher.subscribe()
	}
	dispatcher = &dnsInfoDispatcher{}
	dnsChan = dispatcher.subscribe()
	// Start search domain fallback routine, listens for resolver IPs
	go getFallbackSearchDomains(dnsInfoChan)
	// Only start dispatcher when we have subscribers
	go dispatcher.publish()
	// Signal dnsInfoChan senders after timeout
	dnsInfoTimeout := time.After(DNSInfoTimeout)
	// Signal dnsInfoChan fallback senders after timeout
	dnsInfoTimeoutFallback := time.After(DNSInfoTimeoutFallback)
	go func() {
		for {
			select {
			case <-dnsInfoTimeout:
				// Signal senders about timeout
				close(dnsInfoDone)
			case <-dnsInfoTimeoutFallback:
				// Signal fallback about timeout
				close(dnsInfoFallbackDone)
				// Wait for remaining senders
				dnsInfoWriters.Wait()
				// Stop publishing new DNSInfo
				close(dnsInfoChan)
				return
			}
		}
	}()
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

func (m *MockHintGenerator) Generate(ipHintsChan chan<- net.TCPAddr) {
	if !m.cfg.Enable {
		return
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", m.cfg.Address)
	if err != nil {
		log.Error("Invalid IP:port for mock generator", "value", m.cfg.Address)
		return
	}
	ipHintsChan <- *tcpAddr
}

func HasIPv6(iface *net.Interface) bool {
	return len(ifaceIPv6Addrs(iface)) > 0
}

func ifaceIPv6Addrs(iface *net.Interface) (ips []netip.Addr) {
	if iface == nil {
		return
	}
	ifaddrs, err := iface.Addrs()
	if err != nil {
		return
	}
	for _, ifaddr := range ifaddrs {
		ifaddr, ok := ifaddr.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ifaddr.IP)
		// do not include IPv6 mapped IPv4 addresses and IPv6 loopback
		if ok && ip.Is6() && !ip.Is4In6() && !ip.IsLoopback() {
			ips = append(ips, ip)
		}
	}
	return
}
