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

// +build !windows
// +build !linux

package hinting

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func (g *DHCPHintGenerator) sendReceive(p *dhcpv4.DHCPv4, ifname string) (*dhcpv4.DHCPv4, error) {
	p.SetBroadcast()
	sender, err := makeBroadcastSocket(ifname)
	if err != nil {
		return nil, fmt.Errorf("DHCP hinter failed to open broadcast sender socket: %w", err)
	}
	receiver, err := makeListeningSocket()
	if err != nil {
		return nil, fmt.Errorf("DHCP hinter failed to open receiver socket: %w", err)
	}
	raddr := &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ServerPort}
	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: dhcpv4.ClientPort}
	ack, err := sendReceive(sender, receiver, raddr, laddr, p, dhcpv4.MessageTypeAck)
	if err != nil {
		return nil, fmt.Errorf("DHCP hinter failed to send inform request: %w", err)
	}
	return ack, nil
}

// Package github.com/insomniacslk/dhcp/client4 uses unix.AF_PACKET, which is not supported on various *nixes,
// including the changes required to broadcast send and receive on those.

// "github.com/insomniacslk/dhcp/client4/client.go"
var (
	// Use same defaults as on linux
	defaultReadTimeout       = 3 * time.Second
	maxUDPReceivedPacketSize = 8192
)

func htons(v uint16) uint16 {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], v)
	return binary.LittleEndian.Uint16(tmp[:])
}

func makeBroadcastSocket(ifname string) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return fd, err
	}
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err != nil {
		return fd, err
	}
	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		return fd, err
	}
	err = dhcpv4.BindToInterface(fd, ifname)
	if err != nil {
		return fd, err
	}
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	return fd, err
}

func makeListeningSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, int(htons(unix.IPPROTO_UDP)))
	if err != nil {
		return fd, err
	}
	llAddr := unix.SockaddrInet4{
		Addr: [4]byte{0, 0, 0, 0},
		Port: dhcpv4.ClientPort,
	}
	err = unix.Bind(fd, &llAddr)
	return fd, err
}

func sendReceive(sendFd, recvFd int, raddr, laddr *net.UDPAddr, packet *dhcpv4.DHCPv4, messageType dhcpv4.MessageType) (*dhcpv4.DHCPv4, error) {
	packetBytes, err := makeRawUDPPacket(packet.ToBytes(), *raddr, *laddr)
	if err != nil {
		return nil, err
	}

	var (
		destination [net.IPv4len]byte
		response    *dhcpv4.DHCPv4
	)
	copy(destination[:], raddr.IP.To4())
	remoteAddr := unix.SockaddrInet4{Port: laddr.Port, Addr: destination}
	recvErrors := make(chan error, 1)
	go func(errs chan<- error) {
		// set read timeout
		deadline := &unix.Timeval{Sec: time.Now().Add(defaultReadTimeout).Unix(), Usec: 0}
		if innerErr := unix.SetsockoptTimeval(recvFd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, deadline); innerErr != nil {
			errs <- innerErr
			return
		}
		for {
			buf := make([]byte, maxUDPReceivedPacketSize)
			n, _, innerErr := unix.Recvfrom(recvFd, buf, 0)
			if innerErr != nil {
				errs <- innerErr
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
				errs <- fmt.Errorf("failed to parse DHCP reply packet: " +
					"invalid UDP header length")
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
				errs <- fmt.Errorf("failed to parse DHCP reply packet: " +
					"invalid UDP payload length")
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

	// send the request while the goroutine waits for replies
	if err = unix.Sendto(sendFd, packetBytes, 0, &remoteAddr); err != nil {
		return nil, err
	}

	select {
	case err = <-recvErrors:
		if err == unix.EAGAIN {
			return nil, errors.New("timed out while listening for replies")
		}
		if err != nil {
			return nil, err
		}
	case <-time.After(defaultReadTimeout):
		return nil, errors.New("timed out while listening for replies")
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
