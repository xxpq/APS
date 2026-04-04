package main

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestParseGridSTUNServerCandidate(t *testing.T) {
	host, port, ok := parseGridSTUNServerCandidate("stun:stun.example.com:3478")
	if !ok || host != "stun.example.com" || port != 3478 {
		t.Fatalf("unexpected stun parse result host=%s port=%d ok=%v", host, port, ok)
	}

	host, port, ok = parseGridSTUNServerCandidate("stuns://stun.example.com:5349")
	if !ok || host != "stun.example.com" || port != 5349 {
		t.Fatalf("unexpected stuns parse result host=%s port=%d ok=%v", host, port, ok)
	}
}

func TestDiscoverGridSTUNMappedAddress(t *testing.T) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	serverConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer serverConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		n, remote, readErr := serverConn.ReadFromUDP(buf)
		if readErr != nil || n < 20 {
			return
		}
		txID := append([]byte(nil), buf[8:20]...)
		resp := buildSTUNSuccessResponse(txID, net.ParseIP("203.0.113.20").To4(), 54321)
		_, _ = serverConn.WriteToUDP(resp, remote)
	}()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)
	host, port, err := discoverGridSTUNMappedAddress(net.JoinHostPort(serverAddr.IP.String(), strconv.Itoa(serverAddr.Port)), 800*time.Millisecond)
	if err != nil {
		t.Fatalf("discoverGridSTUNMappedAddress failed: %v", err)
	}
	if host != "203.0.113.20" || port != 54321 {
		t.Fatalf("unexpected mapped address %s:%d", host, port)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stun server goroutine timeout")
	}
}

func buildSTUNSuccessResponse(txID []byte, ip net.IP, port int) []byte {
	attr := make([]byte, 12)
	binary.BigEndian.PutUint16(attr[0:2], stunAttrXorMappedAddr)
	binary.BigEndian.PutUint16(attr[2:4], 8)
	attr[4] = 0
	attr[5] = 0x01
	xorPort := uint16(port) ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(attr[6:8], xorPort)
	cookieBytes := []byte{0x21, 0x12, 0xA4, 0x42}
	for i := 0; i < 4; i++ {
		attr[8+i] = ip[i] ^ cookieBytes[i]
	}

	packet := make([]byte, 20+len(attr))
	binary.BigEndian.PutUint16(packet[0:2], stunBindingSuccessType)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:20], txID)
	copy(packet[20:], attr)
	return packet
}
