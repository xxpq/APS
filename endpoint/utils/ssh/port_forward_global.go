package ssh

import (
	"net"
	"strconv"

	"golang.org/x/crypto/ssh"
)

type tcpipForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type tcpipForwardResponse struct {
	BindPort uint32
}

type forwardedTCPIPPayload struct {
	ConnectedAddr string
	ConnectedPort uint32
	OriginAddr    string
	OriginPort    uint32
}

func (s *session) handleGlobalRequests(in <-chan *ssh.Request) {
	for req := range in {
		switch req.Type {
		case "tcpip-forward":
			s.handleTCPIPForward(req)
		case "cancel-tcpip-forward":
			s.handleCancelTCPIPForward(req)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (s *session) handleTCPIPForward(req *ssh.Request) {
	var payload tcpipForwardRequest
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	bindAddr := payload.BindAddr
	bindPort := payload.BindPort
	listener, err := net.Listen("tcp", net.JoinHostPort(bindAddr, strconv.Itoa(int(bindPort))))
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	actualPort := uint32(tcpAddr.Port)

	key := portForwardKey(bindAddr, actualPort)
	s.mu.Lock()
	if _, exists := s.forwardedTCPPorts[key]; exists {
		s.mu.Unlock()
		_ = listener.Close()
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	s.forwardedTCPPorts[key] = listener
	s.mu.Unlock()

	if req.WantReply {
		var replyPayload []byte
		if bindPort == 0 {
			replyPayload = ssh.Marshal(&tcpipForwardResponse{BindPort: actualPort})
		}
		if err := req.Reply(true, replyPayload); err != nil {
			s.mu.Lock()
			delete(s.forwardedTCPPorts, key)
			s.mu.Unlock()
			_ = listener.Close()
			return
		}
	}

	go s.acceptForwardedTCPIP(listener, key)
}

func (s *session) handleCancelTCPIPForward(req *ssh.Request) {
	var payload tcpipForwardRequest
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	key := portForwardKey(payload.BindAddr, payload.BindPort)
	s.mu.Lock()
	listener, ok := s.forwardedTCPPorts[key]
	if ok {
		delete(s.forwardedTCPPorts, key)
	}
	s.mu.Unlock()
	if ok {
		_ = listener.Close()
	}

	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func (s *session) acceptForwardedTCPIP(listener net.Listener, key string) {
	defer func() {
		_ = listener.Close()
		s.mu.Lock()
		if current, ok := s.forwardedTCPPorts[key]; ok && current == listener {
			delete(s.forwardedTCPPorts, key)
		}
		s.mu.Unlock()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go s.openForwardedTCPIPChannel(conn)
	}
}

func (s *session) openForwardedTCPIPChannel(conn net.Conn) {
	connectedAddr, connectedPort := splitAddr(conn.LocalAddr())
	originAddr, originPort := splitAddr(conn.RemoteAddr())
	payload := forwardedTCPIPPayload{
		ConnectedAddr: connectedAddr,
		ConnectedPort: connectedPort,
		OriginAddr:    originAddr,
		OriginPort:    originPort,
	}

	channel, requests, err := s.c.OpenChannel("forwarded-tcpip", ssh.Marshal(&payload))
	if err != nil {
		_ = conn.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	pipeChannelAndConn(channel, conn)
}

func splitAddr(addr net.Addr) (string, uint32) {
	if addr == nil {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return host, 0
	}
	return host, uint32(port)
}

func portForwardKey(addr string, port uint32) string {
	return net.JoinHostPort(addr, strconv.Itoa(int(port)))
}
