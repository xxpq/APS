package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

// STUN message types (RFC 5389)
const (
	stunMsgTypeBindingRequest  uint16 = 0x0001
	stunMsgTypeBindingResponse uint16 = 0x0101
)

// STUN attributes
const (
	stunAttrMappedAddress    uint16 = 0x0001
	stunAttrXorMappedAddress uint16 = 0x0020
)

// STUN magic cookie (RFC 5389)
const stunMagicCookie uint32 = 0x2112A442

// STUNClient performs STUN requests to discover external IP and port
type STUNClient struct {
	servers []string
}

// NATInfo contains information gathered from STUN discovery
type NATInfo struct {
	ExternalIP   string
	ExternalPort int
	LocalIP      string
	LocalPort    int
	NATType      string // symmetric, full-cone, restricted, port-restricted
}

// NewSTUNClient creates a new STUN client
func NewSTUNClient(servers []string) *STUNClient {
	return &STUNClient{servers: servers}
}

// Discover performs STUN discovery and returns NAT info
func (c *STUNClient) Discover() (*NATInfo, error) {
	if len(c.servers) == 0 {
		return nil, fmt.Errorf("no STUN servers configured")
	}

	// Try each STUN server until one succeeds
	var lastErr error
	for _, server := range c.servers {
		info, err := c.querySTUNServer(server)
		if err == nil {
			return info, nil
		}
		lastErr = err
		log.Printf("[STUN] Server %s failed: %v", server, err)
	}

	return nil, fmt.Errorf("all STUN servers failed: %v", lastErr)
}

// querySTUNServer queries a single STUN server
func (c *STUNClient) querySTUNServer(server string) (*NATInfo, error) {
	// Resolve STUN server address
	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", server, err)
	}

	// Create UDP connection
	conn, err := net.DialUDP("udp4", nil, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Set timeout
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Build STUN binding request
	request := c.buildBindingRequest()
	transactionID := request[8:20] // Save transaction ID for response verification

	// Send request
	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	extIP, extPort, err := c.parseBindingResponse(response[:n], transactionID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Get local address
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	info := &NATInfo{
		ExternalIP:   extIP,
		ExternalPort: extPort,
		LocalIP:      localAddr.IP.String(),
		LocalPort:    localAddr.Port,
		NATType:      "unknown", // Can be determined with additional tests
	}

	log.Printf("[STUN] Discovered: external=%s:%d, local=%s:%d",
		info.ExternalIP, info.ExternalPort, info.LocalIP, info.LocalPort)

	return info, nil
}

// buildBindingRequest creates a STUN binding request message
func (c *STUNClient) buildBindingRequest() []byte {
	// STUN header: 20 bytes
	// - 2 bytes: message type
	// - 2 bytes: message length (0 for binding request)
	// - 4 bytes: magic cookie
	// - 12 bytes: transaction ID
	request := make([]byte, 20)

	// Message type: Binding Request
	binary.BigEndian.PutUint16(request[0:2], stunMsgTypeBindingRequest)

	// Message length: 0 (no attributes)
	binary.BigEndian.PutUint16(request[2:4], 0)

	// Magic cookie
	binary.BigEndian.PutUint32(request[4:8], stunMagicCookie)

	// Transaction ID: 12 random bytes
	// Using current time as simple pseudo-random
	now := time.Now().UnixNano()
	binary.BigEndian.PutUint64(request[8:16], uint64(now))
	binary.BigEndian.PutUint32(request[16:20], uint32(now>>32)^uint32(now))

	return request
}

// parseBindingResponse parses STUN binding response
func (c *STUNClient) parseBindingResponse(response []byte, transactionID []byte) (string, int, error) {
	if len(response) < 20 {
		return "", 0, fmt.Errorf("response too short: %d bytes", len(response))
	}

	// Check message type
	msgType := binary.BigEndian.Uint16(response[0:2])
	if msgType != stunMsgTypeBindingResponse {
		return "", 0, fmt.Errorf("unexpected message type: %04x", msgType)
	}

	// Check magic cookie
	cookie := binary.BigEndian.Uint32(response[4:8])
	if cookie != stunMagicCookie {
		return "", 0, fmt.Errorf("invalid magic cookie: %08x", cookie)
	}

	// Verify transaction ID
	for i := 0; i < 12; i++ {
		if response[8+i] != transactionID[i] {
			return "", 0, fmt.Errorf("transaction ID mismatch")
		}
	}

	// Parse message length
	msgLen := binary.BigEndian.Uint16(response[2:4])
	if len(response) < 20+int(msgLen) {
		return "", 0, fmt.Errorf("response truncated")
	}

	// Parse attributes
	offset := 20
	for offset < 20+int(msgLen) {
		if offset+4 > len(response) {
			break
		}

		attrType := binary.BigEndian.Uint16(response[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(response[offset+2 : offset+4])
		offset += 4

		if offset+int(attrLen) > len(response) {
			break
		}

		switch attrType {
		case stunAttrXorMappedAddress:
			ip, port, err := c.parseXorMappedAddress(response[offset:offset+int(attrLen)], response[4:8], transactionID)
			if err == nil {
				return ip, port, nil
			}
		case stunAttrMappedAddress:
			ip, port, err := c.parseMappedAddress(response[offset : offset+int(attrLen)])
			if err == nil {
				return ip, port, nil
			}
		}

		// Align to 4-byte boundary
		offset += int(attrLen)
		if attrLen%4 != 0 {
			offset += int(4 - attrLen%4)
		}
	}

	return "", 0, fmt.Errorf("no mapped address found in response")
}

// parseXorMappedAddress parses XOR-MAPPED-ADDRESS attribute
func (c *STUNClient) parseXorMappedAddress(data []byte, magicCookie []byte, transactionID []byte) (string, int, error) {
	if len(data) < 8 {
		return "", 0, fmt.Errorf("XOR-MAPPED-ADDRESS too short")
	}

	family := data[1]
	port := binary.BigEndian.Uint16(data[2:4]) ^ binary.BigEndian.Uint16(magicCookie[0:2])

	if family == 0x01 { // IPv4
		ip := make([]byte, 4)
		for i := 0; i < 4; i++ {
			ip[i] = data[4+i] ^ magicCookie[i]
		}
		return net.IP(ip).String(), int(port), nil
	}

	return "", 0, fmt.Errorf("unsupported address family: %d", family)
}

// parseMappedAddress parses MAPPED-ADDRESS attribute
func (c *STUNClient) parseMappedAddress(data []byte) (string, int, error) {
	if len(data) < 8 {
		return "", 0, fmt.Errorf("MAPPED-ADDRESS too short")
	}

	family := data[1]
	port := binary.BigEndian.Uint16(data[2:4])

	if family == 0x01 { // IPv4
		ip := net.IP(data[4:8])
		return ip.String(), int(port), nil
	}

	return "", 0, fmt.Errorf("unsupported address family: %d", family)
}

// PerformDiscovery is a convenience function for one-time STUN discovery
func PerformDiscovery(servers []string) (*NATInfo, error) {
	client := NewSTUNClient(servers)
	return client.Discover()
}
