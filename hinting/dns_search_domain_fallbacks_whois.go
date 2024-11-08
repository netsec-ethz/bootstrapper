package hinting

import (
	"io"
	"net"
	"net/mail"
	"net/netip"
	"slices"
	"strings"
)

var (
	ianaWHOIS = "whois.iana.org"
	rirWHOIS  = []string{
		"whois.afrinic.net",
		"whois.lacnic.net",
		"whois.apnic.net",
		"whois.ripe.net",
		"whois.arin.net",
	}
)

func reverseLookupWHOIS(addr netip.Addr) (domains []string) {
	response, err := resolveWHOISRedirects(addr, ianaWHOIS)
	if err != nil {
		return
	}
	return extractEmailDomains(response)
}

func resolveWHOISRedirects(addr netip.Addr, server string) (response string, err error) {
	whoisServer := server
	for i := 0; i < 10; i++ {
		// arbitrary upper limit of 10 redirects allowed, usually no more than 3 (IANA, RIR legacy registration, RIR)
		var raddr *net.TCPAddr
		raddr, err = net.ResolveTCPAddr("tcp4", net.JoinHostPort(whoisServer, "43"))
		if err != nil {
			return
		}
		response, err = queryWHOIS(raddr, addr)
		if err != nil {
			return
		}
		var entry string
		for _, entry = range strings.Split(response, "\n") {
			if strings.HasPrefix(entry, "refer:") ||
				strings.HasPrefix(entry, "ReferralServer:") {
				break
			}
		}
		if strings.HasPrefix(entry, "refer:") {
			value := strings.TrimPrefix(entry, "refer:")
			whoisRefer := strings.TrimSpace(value)
			if slices.Contains(rirWHOIS, whoisRefer) {
				whoisServer = whoisRefer
				continue
			}
		}
		if strings.HasPrefix(entry, "ReferralServer:") {
			value := strings.TrimPrefix(entry, "ReferralServer:")
			whoisRefer := strings.TrimPrefix(strings.TrimSpace(value), "whois://")
			if slices.Contains(rirWHOIS, whoisRefer) {
				whoisServer = whoisRefer
				continue
			}
		}
		break
	}
	return
}

func queryWHOIS(serverTCPAddr *net.TCPAddr, queryAddr netip.Addr) (response string, err error) {
	var tcpConn *net.TCPConn
	var responseBuff []byte
	tcpConn, err = net.DialTCP("tcp", nil, serverTCPAddr)
	if err != nil {
		return
	}
	defer tcpConn.Close()
	if _, err = tcpConn.Write([]byte(queryAddr.String() + "\n")); err != nil {
		return
	}
	responseBuff, err = io.ReadAll(tcpConn)
	if err != nil {
		return
	}
	response = string(responseBuff)
	return
}

func extractEmailDomains(response string) (domains []string) {
	var emailsFields []string
	for _, entry := range strings.Split(response, "\n") {
		if strings.Contains(entry, "abuse@") ||
			strings.Contains(entry, "security@") ||
			strings.Contains(entry, "noc@") {
			fields := strings.Fields(entry)
			for _, field := range fields {
				if strings.Contains(field, "@") {
					emailsFields = append(emailsFields, field)
				}
			}
		}
	}
	var hostnames []string
	for _, email := range emailsFields {
		if address, err := mail.ParseAddress(email); err == nil {
			addressLabels := strings.Split(address.Address, "@")
			domain := "." + strings.Trim(addressLabels[len(addressLabels)-1], "'.")
			hostnames = append(hostnames, domain)
		}
	}
	// filter out RIR domains
	return domainsFromHostnames(hostnames)
}
