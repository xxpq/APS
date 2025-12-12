package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// UPnPClient handles UPnP/IGD operations for NAT traversal
type UPnPClient struct {
	gateway       *IGDGateway
	mappedPorts   map[int]*PortMapping // internal port -> mapping
	externalIP    string
	mu            sync.RWMutex
	discoveryDone bool
}

// IGDGateway represents an Internet Gateway Device
type IGDGateway struct {
	URL         string // Control URL for WANIPConnection or WANPPPConnection
	ServiceType string // urn:schemas-upnp-org:service:WANIPConnection:1 or WANPPPConnection:1
	LocalIP     string // Local IP address used for mapping
}

// PortMapping represents an active port mapping
type PortMapping struct {
	InternalPort int
	ExternalPort int
	Protocol     string // "TCP" or "UDP"
	Description  string
	CreatedAt    time.Time
}

// UPnP SSDP discovery constants
const (
	ssdpMulticastAddr = "239.255.255.250:1900"
	ssdpSearchRequest = "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"\r\n"
)

// NewUPnPClient creates a new UPnP client
func NewUPnPClient() *UPnPClient {
	return &UPnPClient{
		mappedPorts: make(map[int]*PortMapping),
	}
}

// Discover discovers UPnP IGD devices on the network
func (uc *UPnPClient) Discover() error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	if uc.discoveryDone && uc.gateway != nil {
		return nil // Already discovered
	}

	log.Println("[UPNP] Starting IGD discovery...")

	// Get local IP address
	localIP, err := getOutboundIP()
	if err != nil {
		return fmt.Errorf("failed to get local IP: %w", err)
	}

	// Create UDP socket for SSDP discovery
	localAddr := &net.UDPAddr{IP: localIP, Port: 0}
	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer conn.Close()

	// Parse multicast address
	multicastAddr, err := net.ResolveUDPAddr("udp4", ssdpMulticastAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve multicast address: %w", err)
	}

	// Send SSDP M-SEARCH request
	_, err = conn.WriteToUDP([]byte(ssdpSearchRequest), multicastAddr)
	if err != nil {
		return fmt.Errorf("failed to send SSDP request: %w", err)
	}

	// Wait for responses with timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)

	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break // Timeout - no more responses
			}
			return fmt.Errorf("failed to read SSDP response: %w", err)
		}

		response := string(buf[:n])
		location := extractHeader(response, "LOCATION")
		if location == "" {
			continue
		}

		// Try to get the root device description
		gateway, err := uc.fetchGatewayInfo(location, localIP.String())
		if err != nil {
			log.Printf("[UPNP] Failed to fetch gateway info from %s: %v", location, err)
			continue
		}

		uc.gateway = gateway
		uc.discoveryDone = true

		// Get external IP
		extIP, err := uc.getExternalIPAddress()
		if err == nil {
			uc.externalIP = extIP
		}

		log.Printf("[UPNP] Found IGD gateway: %s (external IP: %s)", gateway.URL, uc.externalIP)
		return nil
	}

	return errors.New("no UPnP IGD device found")
}

// fetchGatewayInfo fetches the device description and finds the control URL
func (uc *UPnPClient) fetchGatewayInfo(location, localIP string) (*IGDGateway, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(location)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse XML to find WANIPConnection or WANPPPConnection service
	controlURL, serviceType, err := parseDeviceDescription(body, location)
	if err != nil {
		return nil, err
	}

	return &IGDGateway{
		URL:         controlURL,
		ServiceType: serviceType,
		LocalIP:     localIP,
	}, nil
}

// parseDeviceDescription parses the device description XML to find the control URL
func parseDeviceDescription(body []byte, baseURL string) (string, string, error) {
	type Service struct {
		ServiceType string `xml:"serviceType"`
		ControlURL  string `xml:"controlURL"`
	}
	type Device struct {
		DeviceType  string    `xml:"deviceType"`
		DeviceList  []Device  `xml:"deviceList>device"`
		ServiceList []Service `xml:"serviceList>service"`
	}
	type Root struct {
		XMLName xml.Name `xml:"root"`
		Device  Device   `xml:"device"`
	}

	var root Root
	if err := xml.Unmarshal(body, &root); err != nil {
		return "", "", err
	}

	// Service types to look for (in order of preference)
	serviceTypes := []string{
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
	}

	// Recursively search for the service
	var findService func(device Device) (string, string, bool)
	findService = func(device Device) (string, string, bool) {
		for _, svc := range device.ServiceList {
			for _, st := range serviceTypes {
				if strings.Contains(svc.ServiceType, st) || strings.Contains(st, svc.ServiceType) {
					// Build absolute URL
					controlURL := svc.ControlURL
					if !strings.HasPrefix(controlURL, "http") {
						if strings.HasPrefix(controlURL, "/") {
							// Extract base from location
							idx := strings.Index(baseURL[7:], "/") // Skip "http://"
							if idx > 0 {
								controlURL = baseURL[:7+idx] + controlURL
							}
						} else {
							// Relative URL
							idx := strings.LastIndex(baseURL, "/")
							if idx > 0 {
								controlURL = baseURL[:idx+1] + controlURL
							}
						}
					}
					return controlURL, svc.ServiceType, true
				}
			}
		}
		// Search nested devices
		for _, dev := range device.DeviceList {
			if url, st, found := findService(dev); found {
				return url, st, true
			}
		}
		return "", "", false
	}

	url, serviceType, found := findService(root.Device)
	if !found {
		return "", "", errors.New("WANIPConnection/WANPPPConnection service not found")
	}

	return url, serviceType, nil
}

// AddPortMapping adds a port mapping through UPnP
func (uc *UPnPClient) AddPortMapping(internalPort, externalPort int, protocol, description string, leaseDuration int) error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	if uc.gateway == nil {
		return errors.New("UPnP gateway not discovered")
	}

	if protocol != "TCP" && protocol != "UDP" {
		return errors.New("protocol must be TCP or UDP")
	}

	soapBody := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="%s">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
<NewInternalPort>%d</NewInternalPort>
<NewInternalClient>%s</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>%s</NewPortMappingDescription>
<NewLeaseDuration>%d</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>`, uc.gateway.ServiceType, externalPort, protocol, internalPort, uc.gateway.LocalIP, description, leaseDuration)

	req, err := http.NewRequest("POST", uc.gateway.URL, bytes.NewBufferString(soapBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", fmt.Sprintf("\"%s#AddPortMapping\"", uc.gateway.ServiceType))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("SOAP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("AddPortMapping failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// Record the mapping
	uc.mappedPorts[internalPort] = &PortMapping{
		InternalPort: internalPort,
		ExternalPort: externalPort,
		Protocol:     protocol,
		Description:  description,
		CreatedAt:    time.Now(),
	}

	log.Printf("[UPNP] Port mapping added: %s %d -> %s:%d", protocol, externalPort, uc.gateway.LocalIP, internalPort)
	return nil
}

// DeletePortMapping removes a port mapping
func (uc *UPnPClient) DeletePortMapping(externalPort int, protocol string) error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	if uc.gateway == nil {
		return errors.New("UPnP gateway not discovered")
	}

	soapBody := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:DeletePortMapping xmlns:u="%s">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
</u:DeletePortMapping>
</s:Body>
</s:Envelope>`, uc.gateway.ServiceType, externalPort, protocol)

	req, err := http.NewRequest("POST", uc.gateway.URL, bytes.NewBufferString(soapBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", fmt.Sprintf("\"%s#DeletePortMapping\"", uc.gateway.ServiceType))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("SOAP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Remove from tracked mappings
	for port, mapping := range uc.mappedPorts {
		if mapping.ExternalPort == externalPort && mapping.Protocol == protocol {
			delete(uc.mappedPorts, port)
			break
		}
	}

	log.Printf("[UPNP] Port mapping deleted: %s %d", protocol, externalPort)
	return nil
}

// getExternalIPAddress gets the external IP address from the IGD
func (uc *UPnPClient) getExternalIPAddress() (string, error) {
	if uc.gateway == nil {
		return "", errors.New("UPnP gateway not discovered")
	}

	soapBody := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetExternalIPAddress xmlns:u="%s">
</u:GetExternalIPAddress>
</s:Body>
</s:Envelope>`, uc.gateway.ServiceType)

	req, err := http.NewRequest("POST", uc.gateway.URL, bytes.NewBufferString(soapBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", fmt.Sprintf("\"%s#GetExternalIPAddress\"", uc.gateway.ServiceType))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse the response to extract external IP
	var envelope struct {
		Body struct {
			Response struct {
				ExternalIP string `xml:"NewExternalIPAddress"`
			} `xml:"GetExternalIPAddressResponse"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(body, &envelope); err != nil {
		// Try alternative parsing
		start := strings.Index(string(body), "<NewExternalIPAddress>")
		end := strings.Index(string(body), "</NewExternalIPAddress>")
		if start >= 0 && end > start {
			return string(body)[start+22 : end], nil
		}
		return "", err
	}

	return envelope.Body.Response.ExternalIP, nil
}

// GetExternalIP returns the cached external IP address
func (uc *UPnPClient) GetExternalIP() string {
	uc.mu.RLock()
	defer uc.mu.RUnlock()
	return uc.externalIP
}

// IsAvailable returns true if UPnP IGD is available
func (uc *UPnPClient) IsAvailable() bool {
	uc.mu.RLock()
	defer uc.mu.RUnlock()
	return uc.gateway != nil
}

// ClearAllMappings removes all port mappings created by this client
func (uc *UPnPClient) ClearAllMappings() {
	uc.mu.Lock()
	mappings := make([]*PortMapping, 0, len(uc.mappedPorts))
	for _, m := range uc.mappedPorts {
		mappings = append(mappings, m)
	}
	uc.mu.Unlock()

	for _, m := range mappings {
		if err := uc.DeletePortMapping(m.ExternalPort, m.Protocol); err != nil {
			log.Printf("[UPNP] Failed to delete mapping %s:%d: %v", m.Protocol, m.ExternalPort, err)
		}
	}
}

// extractHeader extracts a header value from an HTTP response string
func extractHeader(response, header string) string {
	lines := strings.Split(response, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToUpper(line), strings.ToUpper(header)+":") {
			return strings.TrimSpace(line[len(header)+1:])
		}
	}
	return ""
}

// getOutboundIP gets the preferred outbound IP of this machine
func getOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}
