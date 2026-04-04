package main

import (
	"net"
	"os"
	"strconv"
	"sync"
)

var endpointICEConnectivityRuntime = struct {
	mu        sync.Mutex
	listeners map[int]*net.UDPConn
}{
	listeners: make(map[int]*net.UDPConn),
}

func ensureEndpointICEConnectivityRuntime(connCtx ImmutableConnectionContext) {
	ports := []int{}
	if p := endpointGridListenPort(connCtx); p > 0 {
		ports = append(ports, p)
	}
	ports = append(ports, parseGridPortList(os.Getenv("APS_GRID_ICE_LISTEN_PORTS"))...)
	ports = normalizeGridCandidatePorts(ports)
	if len(ports) == 0 {
		return
	}
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		startEndpointICEConnectivityListener(port)
	}
}

func startEndpointICEConnectivityListener(port int) {
	endpointICEConnectivityRuntime.mu.Lock()
	if _, exists := endpointICEConnectivityRuntime.listeners[port]; exists {
		endpointICEConnectivityRuntime.mu.Unlock()
		return
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		endpointICEConnectivityRuntime.mu.Unlock()
		DebugLog("[GRID-ICE] failed to start connectivity listener udp/%d: %v", port, err)
		return
	}
	endpointICEConnectivityRuntime.listeners[port] = conn
	endpointICEConnectivityRuntime.mu.Unlock()

	DebugLog("[GRID-ICE] connectivity listener started on udp/%d", port)
	go serveEndpointICEConnectivity(conn, port)
}

func serveEndpointICEConnectivity(conn *net.UDPConn, port int) {
	buf := make([]byte, 2048)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		txID, ok := parseSTUNBindingRequest(buf[:n])
		if !ok {
			continue
		}
		resp := buildSTUNBindingSuccessResponse(txID, remote)
		if len(resp) == 0 {
			continue
		}
		if _, writeErr := conn.WriteToUDP(resp, remote); writeErr != nil {
			DebugLog("[GRID-ICE] connectivity response failed udp/%d remote=%s err=%v", port, net.JoinHostPort(remote.IP.String(), strconv.Itoa(remote.Port)), writeErr)
		}
	}
}
