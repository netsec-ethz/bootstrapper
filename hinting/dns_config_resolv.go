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

// +build linux darwin freebsd aix dragonfly hurd illumos netbsd openbsd solaris zos

package hinting

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/scionproto/scion/go/lib/log"
)

const (
	resolvPath string = "/etc/resolv.conf"
)

func getDNSConfigResolv() (dnsInfo *DNSInfo) {
	fd, err := os.Open(resolvPath)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to read %s", resolvPath), "err", err)
		return nil
	}
	defer fd.Close()
	var DNSServers, DNSSearchDomains []string
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// empty line
			continue
		}
		if strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			// comment
			continue
		}
		// options
		option := strings.Fields(line)
		if len(option) < 2 {
			// missing option value(s)
			continue
		}
		optionName, optionValues := option[0], option[1:]
		switch optionName {
		case "nameserver":
			for _, serverIP := range optionValues {
				if ip := net.ParseIP(serverIP); ip != nil && len(DNSServers) < 3 {
					DNSServers = append(DNSServers, serverIP)
				}
			}
		case "domain":
			DNSSearchDomains = append(DNSSearchDomains, optionValues[0])
		case "search":
			DNSSearchDomains = append(DNSSearchDomains, optionValues...)
		default:
			// unhandled options, see https://www.man7.org/linux/man-pages/man5/resolv.conf.5.html for other options
			// and https://github.com/golang/go/blob/master/src/net/dnsconfig_unix.go for a different
			// implementation, dnsReadConfig is not exported unfortunately.
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		log.Error(fmt.Sprintf("Error while reading %s", resolvPath), "err", err)
	}
	if len(DNSServers) > 0 || len(DNSSearchDomains) > 0 {
		dnsInfo = &DNSInfo{resolvers: DNSServers, searchDomains: DNSSearchDomains}
	}
	return
}

func getDNSConfigIPHlpAPI() (dnsInfo *DNSInfo) {
	log.Error("IP Helper API not supported on current OS", "err",
		errors.New("only resolv.conf is implemented for this OS, use getDNSConfigResolv to get local DNS config"))
	return nil
}
