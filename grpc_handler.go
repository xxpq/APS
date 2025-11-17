package main

import (
	"io"
	"log"

	pb "aps/tunnelpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const minEndpointVersion = "1.0.0"

// TunnelServiceServer is the implementation of the gRPC TunnelService
type TunnelServiceServer struct {
	pb.UnimplementedTunnelServiceServer
	tunnelManager *TunnelManager
}

// Establish handles the bidirectional streaming RPC for the tunnel
func (s *TunnelServiceServer) Establish(stream pb.TunnelService_EstablishServer) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return status.Errorf(codes.InvalidArgument, "missing metadata")
	}

	// Version Check
	versions := md.Get("x-aps-tunnel")
	if len(versions) == 0 {
		return status.Errorf(codes.FailedPrecondition, "missing x-aps-tunnel version header")
	}
	clientVersion := versions[0]
	// TODO: Implement more robust semantic versioning check if needed
	if clientVersion < minEndpointVersion {
		return status.Errorf(codes.FailedPrecondition, "endpoint version %s is too old, please upgrade to at least %s", clientVersion, minEndpointVersion)
	}

	tunnelNames := md.Get("tunnel-name")
	endpointNames := md.Get("endpoint-name")
	passwords := md.Get("password")

	if len(tunnelNames) == 0 || len(endpointNames) == 0 {
		return status.Errorf(codes.InvalidArgument, "tunnel-name and endpoint-name metadata are required")
	}
	tunnelName := tunnelNames[0]
	endpointName := endpointNames[0]
	password := ""
	if len(passwords) > 0 {
		password = passwords[0]
	}

	log.Printf("[GRPC] New stream attempt for tunnel '%s', endpoint '%s'", tunnelName, endpointName)

	endpointStream, err := s.tunnelManager.RegisterEndpointStream(tunnelName, endpointName, password, stream)
	if err != nil {
		log.Printf("[GRPC] Failed to register stream for endpoint '%s': %v", endpointName, err)
		return status.Errorf(codes.Unauthenticated, "failed to register stream: %v", err)
	}
	defer s.tunnelManager.UnregisterEndpointStream(tunnelName, endpointName, endpointStream.id)

	log.Printf("[GRPC] Stream %s registered successfully for endpoint '%s'", endpointStream.id, endpointName)

	// Loop to receive messages from the client
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			log.Printf("[GRPC] Stream %s for endpoint '%s' closed by client.", endpointStream.id, endpointName)
			return nil
		}
		if err != nil {
			log.Printf("[GRPC] Error receiving from stream %s for endpoint '%s': %v", endpointStream.id, endpointName, err)
			return err
		}

		// Process the incoming message
		s.tunnelManager.HandleIncomingMessage(msg)
	}
}