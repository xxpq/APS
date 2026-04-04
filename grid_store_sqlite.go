package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type SQLiteGridStore struct {
	db *sql.DB
}

func NewSQLiteGridStore(path string) (*SQLiteGridStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("sqlite path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &SQLiteGridStore{db: db}
	if err := store.initSchema(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteGridStore) initSchema(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode=WAL;`,
		`CREATE TABLE IF NOT EXISTS grid_nodes (
			node_id TEXT PRIMARY KEY,
			payload TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS grid_leases (
			node_id TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS grid_routes (
			route_id TEXT PRIMARY KEY,
			source_node TEXT NOT NULL,
			destination_node TEXT NOT NULL,
			reliability_score REAL NOT NULL,
			latency_ms INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			payload TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_grid_routes_query
			ON grid_routes(source_node, destination_node, reliability_score, latency_ms);`,
		`CREATE TABLE IF NOT EXISTS grid_tokens (
			token TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			scope TEXT NOT NULL,
			issued_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0,
			payload TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_grid_tokens_node ON grid_tokens(node_id);`,
		`CREATE TABLE IF NOT EXISTS grid_ice_candidates (
			node_id TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL,
			payload TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_grid_ice_expiry
			ON grid_ice_candidates(expires_at);`,
	}

	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("init grid schema failed: %w", err)
		}
	}
	return nil
}

func (s *SQLiteGridStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteGridStore) UpsertNode(ctx context.Context, node *NodeIdentity) error {
	if node == nil || strings.TrimSpace(node.NodeID) == "" {
		return errors.New("node_id is required")
	}
	payload, err := json.Marshal(node)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO grid_nodes(node_id, payload, updated_at)
		 VALUES(?, ?, ?)
		 ON CONFLICT(node_id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at`,
		node.NodeID, string(payload), now,
	)
	return err
}

func (s *SQLiteGridStore) GetNode(ctx context.Context, nodeID string) (*NodeIdentity, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil, errors.New("node_id is required")
	}
	var payload string
	err := s.db.QueryRowContext(ctx, `SELECT payload FROM grid_nodes WHERE node_id=?`, nodeID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var node NodeIdentity
	if err := json.Unmarshal([]byte(payload), &node); err != nil {
		return nil, err
	}
	return &node, nil
}

func (s *SQLiteGridStore) ListNodes(ctx context.Context) ([]NodeIdentity, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM grid_nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]NodeIdentity, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var node NodeIdentity
		if err := json.Unmarshal([]byte(payload), &node); err != nil {
			return nil, err
		}
		out = append(out, node)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLiteGridStore) DeleteNode(ctx context.Context, nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("node_id is required")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM grid_nodes WHERE node_id=?`, nodeID)
	return err
}

func (s *SQLiteGridStore) UpsertLease(ctx context.Context, lease *NodeLease) error {
	if lease == nil || strings.TrimSpace(lease.NodeID) == "" {
		return errors.New("node_id is required")
	}
	if lease.ExpiresAt <= 0 {
		return errors.New("expires_at is required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO grid_leases(node_id, expires_at)
		 VALUES(?, ?)
		 ON CONFLICT(node_id) DO UPDATE SET expires_at=excluded.expires_at`,
		lease.NodeID, lease.ExpiresAt,
	)
	return err
}

func (s *SQLiteGridStore) GetLease(ctx context.Context, nodeID string) (*NodeLease, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil, errors.New("node_id is required")
	}
	var expiresAt int64
	err := s.db.QueryRowContext(ctx, `SELECT expires_at FROM grid_leases WHERE node_id=?`, nodeID).Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &NodeLease{NodeID: nodeID, ExpiresAt: expiresAt}, nil
}

func (s *SQLiteGridStore) DeleteLease(ctx context.Context, nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("node_id is required")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM grid_leases WHERE node_id=?`, nodeID)
	return err
}

func (s *SQLiteGridStore) AnnounceRoute(ctx context.Context, route *RouteDescriptor) error {
	if route == nil || strings.TrimSpace(route.RouteID) == "" {
		return errors.New("route_id is required")
	}
	payload, err := json.Marshal(route)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO grid_routes(route_id, source_node, destination_node, reliability_score, latency_ms, expires_at, payload, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(route_id) DO UPDATE SET
		    source_node=excluded.source_node,
		    destination_node=excluded.destination_node,
		    reliability_score=excluded.reliability_score,
		    latency_ms=excluded.latency_ms,
		    expires_at=excluded.expires_at,
		    payload=excluded.payload,
		    updated_at=excluded.updated_at`,
		route.RouteID,
		route.SourceNode,
		route.DestinationNode,
		route.ReliabilityScore,
		route.LatencyMs,
		route.ExpiresAt,
		string(payload),
		now,
	)
	return err
}

func (s *SQLiteGridStore) QueryRoutes(ctx context.Context, sourceNode, destinationNode string, limit int) ([]RouteDescriptor, error) {
	if limit <= 0 {
		limit = 16
	}
	now := time.Now().UTC().Unix()
	rows, err := s.db.QueryContext(ctx,
		`SELECT payload
		 FROM grid_routes
		 WHERE source_node=? AND destination_node=? AND expires_at>=?
		 ORDER BY reliability_score DESC, latency_ms ASC, updated_at DESC
		 LIMIT ?`,
		sourceNode, destinationNode, now, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]RouteDescriptor, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var route RouteDescriptor
		if err := json.Unmarshal([]byte(payload), &route); err != nil {
			return nil, err
		}
		out = append(out, route)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLiteGridStore) ListRoutes(ctx context.Context, limit int) ([]RouteDescriptor, error) {
	if limit <= 0 {
		limit = 1024
	}
	now := time.Now().UTC().Unix()
	rows, err := s.db.QueryContext(ctx,
		`SELECT payload
		 FROM grid_routes
		 WHERE expires_at>=?
		 ORDER BY updated_at DESC
		 LIMIT ?`,
		now, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]RouteDescriptor, 0, limit)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var route RouteDescriptor
		if err := json.Unmarshal([]byte(payload), &route); err != nil {
			return nil, err
		}
		out = append(out, route)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLiteGridStore) RevokeRoute(ctx context.Context, routeID string) error {
	routeID = strings.TrimSpace(routeID)
	if routeID == "" {
		return errors.New("route_id is required")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM grid_routes WHERE route_id=?`, routeID)
	return err
}

func (s *SQLiteGridStore) SaveToken(ctx context.Context, token *SessionToken) error {
	if token == nil || strings.TrimSpace(token.Token) == "" {
		return errors.New("token is required")
	}
	payload, err := json.Marshal(token)
	if err != nil {
		return err
	}
	revoked := 0
	if token.Revoked {
		revoked = 1
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO grid_tokens(token, node_id, scope, issued_at, expires_at, revoked, payload)
		 VALUES(?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(token) DO UPDATE SET
		    node_id=excluded.node_id,
		    scope=excluded.scope,
		    issued_at=excluded.issued_at,
		    expires_at=excluded.expires_at,
		    revoked=excluded.revoked,
		    payload=excluded.payload`,
		token.Token, token.NodeID, token.Scope, token.IssuedAt, token.ExpiresAt, revoked, string(payload),
	)
	return err
}

func (s *SQLiteGridStore) GetToken(ctx context.Context, tokenValue string) (*SessionToken, error) {
	tokenValue = strings.TrimSpace(tokenValue)
	if tokenValue == "" {
		return nil, errors.New("token is required")
	}
	var payload string
	err := s.db.QueryRowContext(ctx, `SELECT payload FROM grid_tokens WHERE token=?`, tokenValue).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var token SessionToken
	if err := json.Unmarshal([]byte(payload), &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *SQLiteGridStore) RevokeToken(ctx context.Context, tokenValue string) error {
	tokenValue = strings.TrimSpace(tokenValue)
	if tokenValue == "" {
		return errors.New("token is required")
	}
	token, err := s.GetToken(ctx, tokenValue)
	if err != nil {
		return err
	}
	if token == nil {
		return nil
	}
	token.Revoked = true
	return s.SaveToken(ctx, token)
}

func (s *SQLiteGridStore) UpsertICECandidateSet(ctx context.Context, set *ICECandidateSet) error {
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
	now := time.Now().UTC().Unix()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO grid_ice_candidates(node_id, expires_at, payload, updated_at)
		 VALUES(?, ?, ?, ?)
		 ON CONFLICT(node_id) DO UPDATE SET
		    expires_at=excluded.expires_at,
		    payload=excluded.payload,
		    updated_at=excluded.updated_at`,
		set.NodeID, set.ExpiresAt, string(payload), now,
	)
	return err
}

func (s *SQLiteGridStore) GetICECandidateSet(ctx context.Context, nodeID string) (*ICECandidateSet, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil, errors.New("node_id is required")
	}
	var payload string
	err := s.db.QueryRowContext(ctx, `SELECT payload FROM grid_ice_candidates WHERE node_id=?`, nodeID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var set ICECandidateSet
	if err := json.Unmarshal([]byte(payload), &set); err != nil {
		return nil, err
	}
	if set.ExpiresAt > 0 && set.ExpiresAt < time.Now().UTC().Unix() {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM grid_ice_candidates WHERE node_id=?`, nodeID)
		return nil, nil
	}
	return &set, nil
}
