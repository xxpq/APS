package main

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "aps/tunnelpb"
)

// TunnelServer implements the gRPC TunnelService.
type TunnelServer struct {
	pb.UnimplementedTunnelServiceServer
	tunnelManager *TunnelManager
	grpcServer    *grpc.Server
	mu            sync.Mutex
}

// NewTunnelServer creates and starts a new gRPC tunnel server.
func NewTunnelServer(tm *TunnelManager) *TunnelServer {
	return &TunnelServer{
		tunnelManager: tm,
	}
}

func (s *TunnelServer) Start(addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.grpcServer != nil {
		return errors.New("gRPC server is already running")
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.grpcServer = grpc.NewServer()
	pb.RegisterTunnelServiceServer(s.grpcServer, s)

	log.Printf("[GRPC] Tunnel server listening on %s", addr)
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			log.Printf("[GRPC] Server failed: %v", err)
		}
	}()
	return nil
}

// Stop gracefully stops the gRPC server.
func (s *TunnelServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
		s.grpcServer = nil
		log.Println("[GRPC] Tunnel server stopped.")
	}
}

// Establish is the main RPC method for the bidirectional stream.
func (s *TunnelServer) Establish(stream pb.TunnelService_EstablishServer) error {
	// 1. Read the first message, which must be a registration request.
	msg, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "Failed to receive registration message: %v", err)
	}

	reg := msg.GetRegistration()
	if reg == nil {
		return status.Errorf(codes.InvalidArgument, "The first message must be a RegistrationRequest")
	}

	// 获取客户端远程地址
	remoteAddr := "unknown"
	if peer, ok := peer.FromContext(stream.Context()); ok {
		if addr, ok := peer.Addr.(*net.TCPAddr); ok {
			remoteAddr = addr.String()
		} else {
			remoteAddr = peer.Addr.String()
		}
	}

	// 2. Authenticate and register the endpoint stream.
	endpointStream, err := s.tunnelManager.RegisterEndpointStream(reg.TunnelName, reg.EndpointName, reg.Password, stream, remoteAddr)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "Failed to register endpoint: %v", err)
	}
	defer s.tunnelManager.UnregisterEndpointStream(reg.TunnelName, reg.EndpointName, endpointStream.ID)

	log.Printf("[GRPC] Endpoint '%s' connected to tunnel '%s' with stream ID %s", reg.EndpointName, reg.TunnelName, endpointStream.ID)

	// 3. Enter a loop to process incoming messages from the endpoint.
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			// Client closed the stream cleanly.
			log.Printf("[GRPC] Stream %s for endpoint '%s' closed by client.", endpointStream.ID, reg.EndpointName)
			return nil
		}
		if err != nil {
			// An error occurred.
			log.Printf("[GRPC] Error receiving from stream %s for endpoint '%s': %v", endpointStream.ID, reg.EndpointName, err)
			return err
		}

		// Process the received message (e.g., a response to a request).
		s.tunnelManager.HandleIncomingMessage(in)
	}
}