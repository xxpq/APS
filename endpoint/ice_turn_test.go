package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func resetEndpointTURNStateForTest() {
	endpointTURNState.mu.Lock()
	for _, alloc := range endpointTURNState.entries {
		if alloc != nil {
			alloc.close()
		}
	}
	endpointTURNState.entries = make(map[string]*endpointTURNAllocation)
	endpointTURNState.mu.Unlock()
}

func TestParseGridTURNServerCandidate(t *testing.T) {
	candidate, ok := parseGridTURNServerCandidate("turn://alice:secret@turn.example.com:3478?transport=udp", "", "")
	if !ok {
		t.Fatal("expected turn candidate to parse")
	}
	if candidate.ServerAddr != "turn.example.com:3478" {
		t.Fatalf("unexpected server addr: %s", candidate.ServerAddr)
	}
	if candidate.Username != "alice" || candidate.Password != "secret" {
		t.Fatalf("unexpected credentials user=%s pass=%s", candidate.Username, candidate.Password)
	}
}

func TestParseGridTURNServerCandidateTURNS(t *testing.T) {
	candidate, ok := parseGridTURNServerCandidate("turns://alice:secret@turn.example.com", "", "")
	if !ok {
		t.Fatal("expected turns candidate to parse")
	}
	if candidate.ServerAddr != "turn.example.com:5349" {
		t.Fatalf("unexpected server addr: %s", candidate.ServerAddr)
	}
	if candidate.Network != "tcp" || !candidate.UseTLS {
		t.Fatalf("unexpected transport network=%s tls=%v", candidate.Network, candidate.UseTLS)
	}
}

func TestParseGridTURNServerCandidatesAutoTransport(t *testing.T) {
	candidates := parseGridTURNServerCandidates("turn://alice:secret@turn.example.com:3478", "", "")
	if len(candidates) != 2 {
		t.Fatalf("expected 2 transport candidates (udp+tcp), got %d", len(candidates))
	}
	if candidates[0].Network != "udp" || candidates[0].UseTLS {
		t.Fatalf("unexpected first candidate: network=%s tls=%v", candidates[0].Network, candidates[0].UseTLS)
	}
	if candidates[1].Network != "tcp" || candidates[1].UseTLS {
		t.Fatalf("unexpected second candidate: network=%s tls=%v", candidates[1].Network, candidates[1].UseTLS)
	}
}

func TestDiscoverEndpointGridTURNCandidates(t *testing.T) {
	resetEndpointTURNStateForTest()
	defer resetEndpointTURNStateForTest()

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
		buf := make([]byte, 2048)
		for {
			_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, remote, readErr := serverConn.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			msg, parseErr := parseTURNMessage(buf[:n])
			if parseErr != nil || msg == nil {
				continue
			}
			switch msg.Type {
			case turnAllocateRequestType:
				if _, hasUser := msg.Attrs[turnAttrUsername]; !hasUser {
					errResp := buildTURNMessage(turnAllocateErrorType, msg.TxID, []turnAttribute{
						{Type: turnAttrErrorCode, Value: buildTURNErrorCodeAttr(401, "Unauthorized")},
						{Type: turnAttrRealm, Value: []byte("example.org")},
						{Type: turnAttrNonce, Value: []byte("nonce-1")},
					}, nil)
					_, _ = serverConn.WriteToUDP(errResp, remote)
					continue
				}

				successResp := buildTURNMessage(turnAllocateSuccessType, msg.TxID, []turnAttribute{
					{Type: turnAttrXORRelayedAddress, Value: buildTURNXORAddress(net.ParseIP("198.51.100.40").To4(), 50000, msg.TxID)},
					{Type: turnAttrLifetime, Value: encodeTURNLifetime(120)},
				}, nil)
				_, _ = serverConn.WriteToUDP(successResp, remote)
			case turnRefreshRequestType:
				successResp := buildTURNMessage(turnRefreshSuccessType, msg.TxID, []turnAttribute{
					{Type: turnAttrLifetime, Value: encodeTURNLifetime(120)},
				}, nil)
				_, _ = serverConn.WriteToUDP(successResp, remote)
			}
		}
	}()

	server := serverConn.LocalAddr().(*net.UDPAddr)
	raw := fmt.Sprintf("turn://alice:secret@127.0.0.1:%d?transport=udp", server.Port)
	candidates := discoverEndpointGridTURNCandidates([]string{raw}, "", "", nil, 1200*time.Millisecond)
	if len(candidates) == 0 {
		t.Fatalf("expected turn relay candidates, got %v", candidates)
	}
	expected := net.JoinHostPort("198.51.100.40", strconv.Itoa(50000))
	found := false
	for _, candidate := range candidates {
		if candidate == expected {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected relay candidate %s in %v", expected, candidates)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

func TestDiscoverEndpointGridTURNCandidatesTCP(t *testing.T) {
	resetEndpointTURNStateForTest()
	defer resetEndpointTURNStateForTest()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		for {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			packet, readErr := readTURNStreamPacket(conn)
			if readErr != nil {
				return
			}
			msg, parseErr := parseTURNMessage(packet)
			if parseErr != nil || msg == nil {
				continue
			}
			switch msg.Type {
			case turnAllocateRequestType:
				if _, hasUser := msg.Attrs[turnAttrUsername]; !hasUser {
					errResp := buildTURNMessage(turnAllocateErrorType, msg.TxID, []turnAttribute{
						{Type: turnAttrErrorCode, Value: buildTURNErrorCodeAttr(401, "Unauthorized")},
						{Type: turnAttrRealm, Value: []byte("example.org")},
						{Type: turnAttrNonce, Value: []byte("nonce-1")},
					}, nil)
					_, _ = conn.Write(errResp)
					continue
				}
				successResp := buildTURNMessage(turnAllocateSuccessType, msg.TxID, []turnAttribute{
					{Type: turnAttrXORRelayedAddress, Value: buildTURNXORAddress(net.ParseIP("198.51.100.41").To4(), 50001, msg.TxID)},
					{Type: turnAttrLifetime, Value: encodeTURNLifetime(120)},
				}, nil)
				_, _ = conn.Write(successResp)
			case turnRefreshRequestType:
				successResp := buildTURNMessage(turnRefreshSuccessType, msg.TxID, []turnAttribute{
					{Type: turnAttrLifetime, Value: encodeTURNLifetime(120)},
				}, nil)
				_, _ = conn.Write(successResp)
			}
		}
	}()

	server := ln.Addr().(*net.TCPAddr)
	raw := fmt.Sprintf("turn://alice:secret@127.0.0.1:%d?transport=tcp", server.Port)
	candidates := discoverEndpointGridTURNCandidates([]string{raw}, "", "", nil, 1200*time.Millisecond)
	if len(candidates) == 0 {
		t.Fatalf("expected turn relay candidates over tcp, got %v", candidates)
	}
	expected := net.JoinHostPort("198.51.100.41", strconv.Itoa(50001))
	if candidates[0] != expected {
		t.Fatalf("expected relay candidate %s, got %v", expected, candidates)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

func buildTURNErrorCodeAttr(code int, reason string) []byte {
	class := code / 100
	number := code % 100
	out := make([]byte, 4+len(reason))
	out[2] = byte(class & 0x07)
	out[3] = byte(number & 0xFF)
	copy(out[4:], []byte(reason))
	return out
}

func buildTURNXORAddress(ip net.IP, port int, txID [12]byte) []byte {
	_ = txID
	if ip4 := ip.To4(); ip4 != nil {
		out := make([]byte, 8)
		out[0] = 0
		out[1] = 0x01
		binary.BigEndian.PutUint16(out[2:4], uint16(port)^uint16(stunMagicCookie>>16))
		cookie := []byte{0x21, 0x12, 0xA4, 0x42}
		for i := 0; i < 4; i++ {
			out[4+i] = ip4[i] ^ cookie[i]
		}
		return out
	}
	out := make([]byte, 20)
	out[0] = 0
	out[1] = 0x02
	binary.BigEndian.PutUint16(out[2:4], uint16(port)^uint16(stunMagicCookie>>16))
	mask := make([]byte, 16)
	copy(mask[:4], []byte{0x21, 0x12, 0xA4, 0x42})
	copy(mask[4:], txID[:])
	for i := 0; i < 16 && i < len(ip); i++ {
		out[4+i] = ip[i] ^ mask[i]
	}
	return out
}

func readTURNStreamPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 20)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < 0 || length > 64*1024 {
		return nil, fmt.Errorf("invalid turn packet length: %d", length)
	}
	packet := make([]byte, 20+length)
	copy(packet[:20], header)
	if length > 0 {
		if _, err := io.ReadFull(conn, packet[20:]); err != nil {
			return nil, err
		}
	}
	return packet, nil
}
