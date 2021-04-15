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
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/windows"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func (g *DHCPHintGenerator) sendReceive(p *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	p.SetBroadcast()
	sender, err := makeBroadcastSocket()
	if err != nil {
		return nil, fmt.Errorf("DHCP hinter failed to open broadcast sender socket: %w", err)
	}
	defer sender.Close()
	receiver, err := makeListeningSocket()
	if err != nil {
		return nil, fmt.Errorf("DHCP hinter failed to open receiver socket. %w", err)
	}
	defer receiver.Close()
	raddr := &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ServerPort}
	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: dhcpv4.ClientPort}
	ack, err := sendReceive(sender, receiver, raddr, laddr, p, dhcpv4.MessageTypeAck)
	if err != nil {
		return nil, fmt.Errorf("DHCP hinter failed to send inform request: %w", err)
	}
	return ack, nil
}

// Package github.com/insomniacslk/dhcp/client4 has u-root as dependency, which does not support windows,
// including the changes required to broadcast send and receive on windows.

// "github.com/insomniacslk/dhcp/client4/client.go"
var (
	// Use same defaults as on linux
	defaultReadTimeout       = 3 * time.Second
	defaultWriteTimeout      = 3 * time.Second
	maxUDPReceivedPacketSize = 8192
)

func makeBroadcastSocket() (*ipv4.RawConn, error) {
	ipConn, err := net.ListenIP("ip:udp", nil)
	if err != nil {
		return nil, err
	}
	rawConn, err := ipv4.NewRawConn(ipConn)
	if err != nil {
		return nil, err
	}

	sysconn, err := rawConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	// https://github.com/wine-mirror/wine/blob/master/include/ws2ipdef.h
	IP_HDRINCL := 2
	err2 := sysconn.Control(func(fd uintptr) {
		err = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
		if err != nil {
			return
		}
		err = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_HDRINCL, 1)
		if err != nil {
			return
		}
		err = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
		if err != nil {
			return
		}
	})
	if err2 != nil {
		return nil, err2
	}
	if err != nil {
		return nil, err
	}
	return rawConn, nil
}

func makeListeningSocket() (*ipv4.RawConn, error) {
	listenAddr := net.IPAddr{IP: net.IPv4zero}
	ipConn, err := net.ListenIP("ip:udp", &listenAddr)
	if err != nil {
		return nil, err
	}
	rawConn, err := ipv4.NewRawConn(ipConn)
	if err != nil {
		return nil, err
	}
	return rawConn, nil
}

func sendReceive(sendFd, recvFd *ipv4.RawConn, raddr, laddr *net.UDPAddr, packet *dhcpv4.DHCPv4, messageType dhcpv4.MessageType) (*dhcpv4.DHCPv4, error) {
	packetBytes, err := makeRawUDPPacket(packet.ToBytes(), *raddr, *laddr)
	if err != nil {
		return nil, err
	}

	var (
		destination [net.IPv4len]byte
		response    *dhcpv4.DHCPv4
	)
	copy(destination[:], raddr.IP.To4())
	recvErrors := make(chan error, 1)
	go func(errs chan<- error) {
		// set read timeout
		err := recvFd.SetDeadline(time.Now().Add(defaultReadTimeout))
		if err != nil {
			errs <- err
			return
		}
		for {
			buf := make([]byte, maxUDPReceivedPacketSize)
			n, ipAddr, innerErr := recvFd.ReadFromIP(buf)
			if innerErr != nil {
				errs <- fmt.Errorf("failed to read DHCP reply packet from %s: %w", ipAddr, innerErr)
				return
			}

			var iph ipv4.Header
			if err := iph.Parse(buf[:n]); err != nil {
				// skip non-IP data
				continue
			}
			if iph.Protocol != 17 {
				// skip non-UDP packets
				continue
			}
			udph := buf[iph.Len:n]
			if 8 > len(udph) {
				errs <- fmt.Errorf("failed to parse DHCP reply packet from %s: " +
					"invalid UDP header length", ipAddr)
				return
			}
			// check source and destination ports
			srcPort := int(binary.BigEndian.Uint16(udph[0:2]))
			expectedSrcPort := dhcpv4.ServerPort
			if raddr != nil {
				expectedSrcPort = raddr.Port
			}
			if srcPort != expectedSrcPort {
				continue
			}
			dstPort := int(binary.BigEndian.Uint16(udph[2:4]))
			expectedDstPort := dhcpv4.ClientPort
			if laddr != nil {
				expectedDstPort = laddr.Port
			}
			if dstPort != expectedDstPort {
				continue
			}
			pLen := int(binary.BigEndian.Uint16(udph[4:6]))
			// UDP checksum is not checked
			payloadOffsetEnd := iph.Len+pLen
			if payloadOffsetEnd > n || payloadOffsetEnd > iph.TotalLen {
				errs <- fmt.Errorf("failed to parse DHCP reply packet from %s: " +
					"invalid UDP payload length", ipAddr)
				return
			}
			payload := buf[iph.Len+8 : payloadOffsetEnd]

			response, innerErr = dhcpv4.FromBytes(payload)
			if innerErr != nil {
				errs <- innerErr
				return
			}
			// check that this is a response to our message
			if response.TransactionID != packet.TransactionID {
				continue
			}
			// wait for a response message
			if response.OpCode != dhcpv4.OpcodeBootReply {
				continue
			}
			// if we are not requested to wait for a specific message type,
			// return what we have
			if messageType == dhcpv4.MessageTypeNone {
				break
			}
			// break if it's a reply of the desired type, continue otherwise
			if response.MessageType() == messageType {
				break
			}
		}
		recvErrors <- nil
	}(recvErrors)

	// send the DHCP broadcast request while the goroutine waits for replies
	err = sendFd.SetDeadline(time.Now().Add(defaultWriteTimeout))
	if err != nil {
		return nil, err
	}
	n, werr := sendFd.WriteToIP(packetBytes, &net.IPAddr{IP: net.IPv4bcast})
	if werr != nil {
		return nil, fmt.Errorf("failed to send DHCP request packet, sent only %d bytes: %w", n, werr)
	}

	select {
	case err = <-recvErrors:
		if err == syscall.EAGAIN {
			return nil, fmt.Errorf("timed out while listening for replies")
		}
		if err != nil {
			return nil, err
		}
	case <-time.After(defaultReadTimeout):
		return nil, fmt.Errorf("timed out while listening for replies")
	}

	return response, nil
}

func makeRawUDPPacket(payload []byte, serverAddr, clientAddr net.UDPAddr) ([]byte, error) {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[:2], uint16(clientAddr.Port))
	binary.BigEndian.PutUint16(udp[2:4], uint16(serverAddr.Port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(udp[6:8], 0) // try to offload the checksum

	h := ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + len(udp) + len(payload),
		TTL:      64,
		Protocol: 17, // UDP
		Dst:      serverAddr.IP,
		Src:      clientAddr.IP,
	}
	ret, err := h.Marshal()
	if err != nil {
		return nil, err
	}
	ret = append(ret, udp...)
	ret = append(ret, payload...)
	return ret, nil
}
