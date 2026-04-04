package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	gridEtcdNodePrefix  = "/aps/grid/nodes/"
	gridEtcdLeasePrefix = "/aps/grid/leases/"
	gridEtcdRoutePrefix = "/aps/grid/routes/"
	gridEtcdTokenPrefix = "/aps/grid/tokens/"
	gridEtcdICEPrefix   = "/aps/grid/ice/"
)

type EtcdGridStore struct {
	client *clientv3.Client
}

func NewEtcdGridStore(endpoints []string) (*EtcdGridStore, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("etcd endpoints are required")
	}
	cfg := clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
	}
	client, err := clientv3.New(cfg)
	if err != nil {
		return nil, err
	}
	return &EtcdGridStore{client: client}, nil
}

func (s *EtcdGridStore) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

func (s *EtcdGridStore) UpsertNode(ctx context.Context, node *NodeIdentity) error {
	if node == nil || strings.TrimSpace(node.NodeID) == "" {
		return errors.New("node_id is required")
	}
	payload, err := json.Marshal(node)
	if err != nil {
		return err
	}
	_, err = s.client.Put(ctx, gridEtcdNodePrefix+node.NodeID, string(payload))
	return err
}

func (s *EtcdGridStore) GetNode(ctx context.Context, nodeID string) (*NodeIdentity, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil, errors.New("node_id is required")
	}
	resp, err := s.client.Get(ctx, gridEtcdNodePrefix+nodeID)
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, nil
	}
	var node NodeIdentity
	if err := json.Unmarshal(resp.Kvs[0].Value, &node); err != nil {
		return nil, err
	}
	return &node, nil
}

func (s *EtcdGridStore) ListNodes(ctx context.Context) ([]NodeIdentity, error) {
	resp, err := s.client.Get(ctx, gridEtcdNodePrefix, clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}
	out := make([]NodeIdentity, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var node NodeIdentity
		if err := json.Unmarshal(kv.Value, &node); err != nil {
			return nil, err
		}
		out = append(out, node)
	}
	return out, nil
}

func (s *EtcdGridStore) DeleteNode(ctx context.Context, nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("node_id is required")
	}
	_, err := s.client.Delete(ctx, gridEtcdNodePrefix+nodeID)
	return err
}

func (s *EtcdGridStore) UpsertLease(ctx context.Context, lease *NodeLease) error {
	if lease == nil || strings.TrimSpace(lease.NodeID) == "" {
		return errors.New("node_id is required")
	}
	payload, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	_, err = s.client.Put(ctx, gridEtcdLeasePrefix+lease.NodeID, string(payload))
	return err
}

func (s *EtcdGridStore) GetLease(ctx context.Context, nodeID string) (*NodeLease, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil, errors.New("node_id is required")
	}
	resp, err := s.client.Get(ctx, gridEtcdLeasePrefix+nodeID)
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, nil
	}
	var lease NodeLease
	if err := json.Unmarshal(resp.Kvs[0].Value, &lease); err != nil {
		return nil, err
	}
	return &lease, nil
}

func (s *EtcdGridStore) DeleteLease(ctx context.Context, nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("node_id is required")
	}
	_, err := s.client.Delete(ctx, gridEtcdLeasePrefix+nodeID)
	return err
}

func (s *EtcdGridStore) AnnounceRoute(ctx context.Context, route *RouteDescriptor) error {
	if route == nil || strings.TrimSpace(route.RouteID) == "" {
		return errors.New("route_id is required")
	}
	payload, err := json.Marshal(route)
	if err != nil {
		return err
	}
	_, err = s.client.Put(ctx, gridEtcdRoutePrefix+route.RouteID, string(payload))
	return err
}

func (s *EtcdGridStore) QueryRoutes(ctx context.Context, sourceNode, destinationNode string, limit int) ([]RouteDescriptor, error) {
	if limit <= 0 {
		limit = 16
	}
	resp, err := s.client.Get(ctx, gridEtcdRoutePrefix, clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Unix()
	out := make([]RouteDescriptor, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var route RouteDescriptor
		if err := json.Unmarshal(kv.Value, &route); err != nil {
			return nil, err
		}
		if route.SourceNode != sourceNode || route.DestinationNode != destinationNode {
			continue
		}
		if route.ExpiresAt > 0 && route.ExpiresAt < now {
			continue
		}
		out = append(out, route)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ReliabilityScore == out[j].ReliabilityScore {
			if out[i].LatencyMs == out[j].LatencyMs {
				return out[i].Epoch > out[j].Epoch
			}
			return out[i].LatencyMs < out[j].LatencyMs
		}
		return out[i].ReliabilityScore > out[j].ReliabilityScore
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *EtcdGridStore) ListRoutes(ctx context.Context, limit int) ([]RouteDescriptor, error) {
	if limit <= 0 {
		limit = 1024
	}
	resp, err := s.client.Get(ctx, gridEtcdRoutePrefix, clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Unix()
	out := make([]RouteDescriptor, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var route RouteDescriptor
		if err := json.Unmarshal(kv.Value, &route); err != nil {
			return nil, err
		}
		if route.ExpiresAt > 0 && route.ExpiresAt < now {
			continue
		}
		out = append(out, route)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Epoch == out[j].Epoch {
			return out[i].RouteID > out[j].RouteID
		}
		return out[i].Epoch > out[j].Epoch
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *EtcdGridStore) RevokeRoute(ctx context.Context, routeID string) error {
	routeID = strings.TrimSpace(routeID)
	if routeID == "" {
		return errors.New("route_id is required")
	}
	_, err := s.client.Delete(ctx, gridEtcdRoutePrefix+routeID)
	return err
}

func (s *EtcdGridStore) SaveToken(ctx context.Context, token *SessionToken) error {
	if token == nil || strings.TrimSpace(token.Token) == "" {
		return errors.New("token is required")
	}
	payload, err := json.Marshal(token)
	if err != nil {
		return err
	}
	_, err = s.client.Put(ctx, gridEtcdTokenPrefix+token.Token, string(payload))
	return err
}

func (s *EtcdGridStore) GetToken(ctx context.Context, tokenValue string) (*SessionToken, error) {
	tokenValue = strings.TrimSpace(tokenValue)
	if tokenValue == "" {
		return nil, errors.New("token is required")
	}
	resp, err := s.client.Get(ctx, gridEtcdTokenPrefix+tokenValue)
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, nil
	}
	var token SessionToken
	if err := json.Unmarshal(resp.Kvs[0].Value, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *EtcdGridStore) RevokeToken(ctx context.Context, tokenValue string) error {
	tokenValue = strings.TrimSpace(tokenValue)
	if tokenValue == "" {
		return errors.New("token is required")
	}
	token, err := s.GetToken(ctx, tokenValue)
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("token not found")
	}
	token.Revoked = true
	return s.SaveToken(ctx, token)
}

func (s *EtcdGridStore) UpsertICECandidateSet(ctx context.Context, set *ICECandidateSet) error {
	if set == nil || strings.TrimSpace(set.NodeID) == "" {
		return errors.New("node_id is required")
	}
	if set.ExpiresAt <= 0 {
		return errors.New("expires_at is required")
	}
	payload, err := json.Marshal(set)
	if err != nil {
		return err
	}
	_, err = s.client.Put(ctx, gridEtcdICEPrefix+set.NodeID, string(payload))
	return err
}

func (s *EtcdGridStore) GetICECandidateSet(ctx context.Context, nodeID string) (*ICECandidateSet, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil, errors.New("node_id is required")
	}
	resp, err := s.client.Get(ctx, gridEtcdICEPrefix+nodeID)
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, nil
	}
	var set ICECandidateSet
	if err := json.Unmarshal(resp.Kvs[0].Value, &set); err != nil {
		return nil, err
	}
	if set.ExpiresAt > 0 && set.ExpiresAt < time.Now().UTC().Unix() {
		_, _ = s.client.Delete(ctx, gridEtcdICEPrefix+nodeID)
		return nil, nil
	}
	return &set, nil
}
