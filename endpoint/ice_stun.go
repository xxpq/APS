package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"net"
	neturl "net/url"
	"strconv"
	"strings"
	"time"
)

const (
	stunBindingRequestType = 0x0001
	stunBindingSuccessType = 0x0101
	stunAttrMappedAddress  = 0x0001
	stunAttrUsername       = 0x0006
	stunAttrMessageInt     = 0x0008
	stunAttrXorMappedAddr  = 0x0020
	stunMagicCookie        = 0x2112A442
	stunSharedAuthUsername = "aps-grid"
)

type stunAttribute struct {
	Type  uint16
	Value []byte
}

func parseGridSTUNServerCandidate(raw string) (string, int, bool) {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return "", 0, false
	}

	lower := strings.ToLower(candidate)
	if !strings.HasPrefix(lower, "stun:") &&
		!strings.HasPrefix(lower, "stuns:") {
		return "", 0, false
	}

	normalized := candidate
	if !strings.Contains(normalized, "://") {
		if idx := strings.Index(normalized, ":"); idx > 0 {
			normalized = normalized[:idx] + "://" + strings.TrimPrefix(normalized[idx+1:], "//")
		}
	}
	parsed, err := neturl.Parse(normalized)
	if err != nil {
		return "", 0, false
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "", 0, false
	}
	port := 3478
	if strings.EqualFold(parsed.Scheme, "stuns") || strings.EqualFold(parsed.Scheme, "turns") {
		port = 5349
	}
	if parsed.Port() != "" {
		parsedPort, convErr := strconv.Atoi(parsed.Port())
		if convErr != nil || parsedPort <= 0 || parsedPort > 65535 {
			return "", 0, false
		}
		port = parsedPort
	}
	return host, port, true
}

func discoverGridSTUNMappedAddress(serverAddr string, timeout time.Duration) (string, int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(serverAddr))
	if err != nil {
		return "", 0, err
	}
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	port, convErr := strconv.Atoi(strings.TrimSpace(portText))
	if convErr != nil || port <= 0 || port > 65535 {
		return "", 0, errors.New("invalid stun port")
	}

	target, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", 0, err
	}
	conn, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return "", 0, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", 0, err
	}

	txID := make([]byte, 12)
	if _, err := rand.Read(txID); err != nil {
		return "", 0, err
	}
	username, password := currentEndpointGridSTUNAuthCredentials()
	req := buildSTUNBindingRequest(txID, username, password)
	if _, err := conn.Write(req); err != nil {
		return "", 0, err
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return "", 0, err
	}
	// Do not force MESSAGE-INTEGRITY for third-party/public STUN services.
	return parseSTUNBindingResponse(buf[:n], txID, "")
}

func buildSTUNBindingRequest(txID []byte, username, password string) []byte {
	attrs := []stunAttribute(nil)
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if username != "" {
		attrs = append(attrs, stunAttribute{
			Type:  stunAttrUsername,
			Value: []byte(username),
		})
	}
	if password == "" {
		return buildSTUNMessage(stunBindingRequestType, txID, attrs, "")
	}
	if username == "" {
		return buildSTUNMessage(stunBindingRequestType, txID, nil, "")
	}
	return buildSTUNMessage(stunBindingRequestType, txID, attrs, password)
}

func parseSTUNBindingRequest(packet []byte, expectedUsername, expectedPassword string) ([]byte, bool) {
	if len(packet) < 20 {
		return nil, false
	}
	msgType := binary.BigEndian.Uint16(packet[0:2])
	if msgType != stunBindingRequestType {
		return nil, false
	}
	msgLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if msgLen != len(packet)-20 {
		return nil, false
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return nil, false
	}

	expectedUsername = strings.TrimSpace(expectedUsername)
	expectedPassword = strings.TrimSpace(expectedPassword)
	attrs := packet[20:]
	attrOffset := 20
	requestUsername := ""
	messageIntegrity := []byte(nil)
	messageIntegrityOffset := -1
	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if len(attrs) < 4+attrLen {
			break
		}
		value := attrs[4 : 4+attrLen]
		switch attrType {
		case stunAttrUsername:
			if requestUsername == "" {
				requestUsername = strings.TrimSpace(string(value))
			}
		case stunAttrMessageInt:
			if attrLen == 20 && messageIntegrityOffset < 0 {
				messageIntegrityOffset = attrOffset
				messageIntegrity = append([]byte(nil), value...)
			}
		}
		padded := attrLen
		if rem := attrLen % 4; rem != 0 {
			padded += 4 - rem
		}
		if len(attrs) < 4+padded {
			break
		}
		attrs = attrs[4+padded:]
		attrOffset += 4 + padded
	}

	if expectedPassword != "" {
		if expectedUsername != "" && !strings.EqualFold(requestUsername, expectedUsername) {
			return nil, false
		}
		if len(messageIntegrity) != 20 || messageIntegrityOffset < 0 {
			return nil, false
		}
		if !verifySTUNMessageIntegrity(packet, messageIntegrityOffset, messageIntegrity, expectedPassword) {
			return nil, false
		}
	}

	txID := make([]byte, 12)
	copy(txID, packet[8:20])
	return txID, true
}

func buildSTUNBindingSuccessResponse(txID []byte, remote *net.UDPAddr, _ string, password string) []byte {
	if len(txID) != 12 || remote == nil || remote.IP == nil {
		return nil
	}
	attr := buildSTUNXORMappedAddress(remote.IP, remote.Port, txID)
	if len(attr) == 0 {
		return nil
	}
	return buildSTUNMessage(stunBindingSuccessType, txID, []stunAttribute{
		{Type: stunAttrXorMappedAddr, Value: attr},
	}, strings.TrimSpace(password))
}

func buildSTUNXORMappedAddress(ip net.IP, port int, txID []byte) []byte {
	if port <= 0 || port > 65535 || len(txID) != 12 {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		out := make([]byte, 8)
		out[1] = 0x01
		xorPort := uint16(port) ^ uint16(stunMagicCookie>>16)
		binary.BigEndian.PutUint16(out[2:4], xorPort)
		mask := []byte{0x21, 0x12, 0xA4, 0x42}
		for i := 0; i < 4; i++ {
			out[4+i] = ip4[i] ^ mask[i]
		}
		return out
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}
	out := make([]byte, 20)
	out[1] = 0x02
	xorPort := uint16(port) ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(out[2:4], xorPort)
	mask := make([]byte, 16)
	copy(mask[:4], []byte{0x21, 0x12, 0xA4, 0x42})
	copy(mask[4:], txID)
	for i := 0; i < 16; i++ {
		out[4+i] = ip16[i] ^ mask[i]
	}
	return out
}

func parseSTUNBindingResponse(packet []byte, txID []byte, expectedPassword string) (string, int, error) {
	if len(packet) < 20 {
		return "", 0, errors.New("short stun packet")
	}
	msgType := binary.BigEndian.Uint16(packet[0:2])
	if msgType != stunBindingSuccessType {
		return "", 0, errors.New("unexpected stun response type")
	}
	msgLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if 20+msgLen > len(packet) {
		return "", 0, errors.New("invalid stun message length")
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return "", 0, errors.New("invalid stun magic cookie")
	}
	if len(txID) == 12 && !bytes.Equal(packet[8:20], txID) {
		return "", 0, errors.New("stun transaction id mismatch")
	}

	attrs := packet[20 : 20+msgLen]
	attrOffset := 20
	miOffset := -1
	miValue := []byte(nil)
	mappedHost, mappedPort := "", 0
	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if len(attrs) < 4+attrLen {
			break
		}
		value := attrs[4 : 4+attrLen]
		switch attrType {
		case stunAttrXorMappedAddr:
			host, port, err := parseSTUNMappedAddress(value, true, txID)
			if err == nil {
				mappedHost, mappedPort = host, port
			}
		case stunAttrMappedAddress:
			host, port, err := parseSTUNMappedAddress(value, false, txID)
			if err == nil {
				mappedHost, mappedPort = host, port
			}
		case stunAttrMessageInt:
			if attrLen == 20 && miOffset < 0 {
				miOffset = attrOffset
				miValue = append([]byte(nil), value...)
			}
		}

		padded := attrLen
		if rem := attrLen % 4; rem != 0 {
			padded += 4 - rem
		}
		if len(attrs) < 4+padded {
			break
		}
		attrs = attrs[4+padded:]
		attrOffset += 4 + padded
	}
	if mappedHost == "" {
		return "", 0, errors.New("no mapped address in stun response")
	}
	expectedPassword = strings.TrimSpace(expectedPassword)
	if expectedPassword != "" {
		if len(miValue) != 20 || miOffset < 0 {
			return "", 0, errors.New("missing stun message integrity")
		}
		if !verifySTUNMessageIntegrity(packet, miOffset, miValue, expectedPassword) {
			return "", 0, errors.New("invalid stun message integrity")
		}
	}
	return mappedHost, mappedPort, nil
}

func buildSTUNMessage(msgType uint16, txID []byte, attrs []stunAttribute, integrityKey string) []byte {
	if len(txID) != 12 {
		return nil
	}
	encodedAttrs := encodeSTUNAttributes(attrs)
	integrityKey = strings.TrimSpace(integrityKey)
	if integrityKey == "" {
		msg := make([]byte, 20+len(encodedAttrs))
		binary.BigEndian.PutUint16(msg[0:2], msgType)
		binary.BigEndian.PutUint16(msg[2:4], uint16(len(encodedAttrs)))
		binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
		copy(msg[8:20], txID)
		copy(msg[20:], encodedAttrs)
		return msg
	}

	totalLen := len(encodedAttrs) + 24
	msg := make([]byte, 20+totalLen)
	binary.BigEndian.PutUint16(msg[0:2], msgType)
	binary.BigEndian.PutUint16(msg[2:4], uint16(totalLen))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID)
	copy(msg[20:], encodedAttrs)
	offset := 20 + len(encodedAttrs)
	binary.BigEndian.PutUint16(msg[offset:offset+2], stunAttrMessageInt)
	binary.BigEndian.PutUint16(msg[offset+2:offset+4], 20)
	mac := hmac.New(sha1.New, []byte(integrityKey))
	mac.Write(msg[:offset+4])
	sum := mac.Sum(nil)
	copy(msg[offset+4:offset+24], sum[:20])
	return msg
}

func encodeSTUNAttributes(attrs []stunAttribute) []byte {
	if len(attrs) == 0 {
		return nil
	}
	total := 0
	for _, attr := range attrs {
		attrLen := len(attr.Value)
		total += 4 + attrLen
		if rem := attrLen % 4; rem != 0 {
			total += 4 - rem
		}
	}

	out := make([]byte, total)
	offset := 0
	for _, attr := range attrs {
		attrLen := len(attr.Value)
		binary.BigEndian.PutUint16(out[offset:offset+2], attr.Type)
		binary.BigEndian.PutUint16(out[offset+2:offset+4], uint16(attrLen))
		copy(out[offset+4:offset+4+attrLen], attr.Value)
		offset += 4 + attrLen
		if rem := attrLen % 4; rem != 0 {
			offset += 4 - rem
		}
	}
	return out
}

func verifySTUNMessageIntegrity(packet []byte, attrOffset int, received []byte, key string) bool {
	key = strings.TrimSpace(key)
	if key == "" || len(received) != 20 || attrOffset < 20 || attrOffset+24 > len(packet) {
		return false
	}
	payloadLen := attrOffset + 24 - 20
	if payloadLen < 0 || payloadLen > 65535 {
		return false
	}
	verifyPacket := make([]byte, attrOffset+4)
	copy(verifyPacket, packet[:attrOffset+4])
	binary.BigEndian.PutUint16(verifyPacket[2:4], uint16(payloadLen))
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write(verifyPacket)
	expected := mac.Sum(nil)
	return hmac.Equal(expected[:20], received)
}

func currentEndpointGridSTUNAuthCredentials() (string, string) {
	if connCtx, loaded := currentEndpointGridRuntimeContext(); loaded {
		credential := strings.TrimSpace(connCtx.SessionCredential)
		if credential != "" {
			return stunSharedAuthUsername, credential
		}
	}
	username, password := currentEndpointGridICESessionAuth()
	return strings.TrimSpace(username), strings.TrimSpace(password)
}

func parseSTUNMappedAddress(value []byte, xor bool, txID []byte) (string, int, error) {
	if len(value) < 8 {
		return "", 0, errors.New("short mapped-address attribute")
	}
	family := value[1]
	rawPort := binary.BigEndian.Uint16(value[2:4])
	port := int(rawPort)
	if xor {
		port = int(rawPort ^ uint16(stunMagicCookie>>16))
	}

	switch family {
	case 0x01: // IPv4
		if len(value) < 8 {
			return "", 0, errors.New("short ipv4 mapped-address attribute")
		}
		ip := make(net.IP, net.IPv4len)
		copy(ip, value[4:8])
		if xor {
			cookie := []byte{0x21, 0x12, 0xA4, 0x42}
			for i := 0; i < net.IPv4len; i++ {
				ip[i] ^= cookie[i]
			}
		}
		return ip.String(), port, nil
	case 0x02: // IPv6
		if len(value) < 20 {
			return "", 0, errors.New("short ipv6 mapped-address attribute")
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, value[4:20])
		if xor {
			mask := make([]byte, 16)
			copy(mask[:4], []byte{0x21, 0x12, 0xA4, 0x42})
			copy(mask[4:], txID)
			for i := 0; i < net.IPv6len; i++ {
				ip[i] ^= mask[i]
			}
		}
		return ip.String(), port, nil
	default:
		return "", 0, errors.New("unsupported mapped-address family")
	}
}

func discoverEndpointGridSTUNCandidates(seedCandidates []string, listenPorts []int, timeout time.Duration) []string {
	if len(seedCandidates) == 0 {
		return nil
	}
	ports := normalizeGridCandidatePorts(listenPorts)
	seenServer := make(map[string]struct{}, len(seedCandidates))
	seenCandidate := make(map[string]struct{}, len(seedCandidates)*2)
	out := make([]string, 0, len(seedCandidates)*2)

	addCandidate := func(host string, port int) {
		host = strings.TrimSpace(host)
		if host == "" || port <= 0 || port > 65535 {
			return
		}
		candidate := net.JoinHostPort(host, strconv.Itoa(port))
		if _, exists := seenCandidate[candidate]; exists {
			return
		}
		seenCandidate[candidate] = struct{}{}
		out = append(out, candidate)
	}

	for _, raw := range seedCandidates {
		host, port, ok := parseGridSTUNServerCandidate(raw)
		if !ok {
			continue
		}
		serverAddr := net.JoinHostPort(host, strconv.Itoa(port))
		if _, exists := seenServer[serverAddr]; exists {
			continue
		}
		seenServer[serverAddr] = struct{}{}

		mappedHost, mappedPort, err := discoverGridSTUNMappedAddress(serverAddr, timeout)
		if err != nil || mappedHost == "" {
			continue
		}
		addCandidate(mappedHost, mappedPort)
		for _, listenPort := range ports {
			addCandidate(mappedHost, listenPort)
		}
	}

	return out
}
