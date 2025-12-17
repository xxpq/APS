package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type StatsDB struct {
	db *sql.DB
}

// QuotaUsageData holds quota usage statistics.
type QuotaUsageData struct {
	TrafficUsed  int64
	RequestsUsed int64
}

// NewStatsDB initializes the stats module with a shared database connection.
func NewStatsDB(db *sql.DB) (*StatsDB, error) {
	statsDB := &StatsDB{db: db}
	if err := statsDB.initSchema(); err != nil {
		return nil, err
	}

	return statsDB, nil
}

// Close is a no-op as the database connection is managed externally
func (s *StatsDB) Close() error {
	// Database is closed in main.go
	return nil
}

func (s *StatsDB) initSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER NOT NULL,
			total_requests INTEGER DEFAULT 0,
			active_connections INTEGER DEFAULT 0,
			requests_per_second REAL DEFAULT 0,
			bytes_received INTEGER DEFAULT 0,
			bytes_sent INTEGER DEFAULT 0
		);`,
		`CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON snapshots(timestamp);`,
		`CREATE TABLE IF NOT EXISTS dimension_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			snapshot_id INTEGER NOT NULL,
			dimension_type TEXT NOT NULL,
			dimension_key TEXT NOT NULL,
			requests INTEGER DEFAULT 0,
			bytes_recv INTEGER DEFAULT 0,
			bytes_sent INTEGER DEFAULT 0,
			errors INTEGER DEFAULT 0,
			avg_resp_time REAL DEFAULT 0,
			http_requests INTEGER DEFAULT 0,
			http_success INTEGER DEFAULT 0,
			http_failure INTEGER DEFAULT 0,
			raw_tcp_requests INTEGER DEFAULT 0,
			http_bytes_sent INTEGER DEFAULT 0,
			http_bytes_recv INTEGER DEFAULT 0,
			raw_tcp_bytes_sent INTEGER DEFAULT 0,
			raw_tcp_bytes_recv INTEGER DEFAULT 0,
			FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_dimension_stats_snapshot_id ON dimension_stats(snapshot_id);`,
		`CREATE INDEX IF NOT EXISTS idx_dimension_stats_lookup ON dimension_stats(dimension_type, dimension_key);`,
		`CREATE TABLE IF NOT EXISTS quota_usage (
			source_key TEXT PRIMARY KEY,
			traffic_used INTEGER DEFAULT 0,
			requests_used INTEGER DEFAULT 0
		);`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute init query: %v", err)
		}
	}

	// Add missing columns if they don't exist (for existing DBs)
	// SQLite doesn't support IF NOT EXISTS in ADD COLUMN, so we catch error or check pragma
	// A simple way is to try adding and ignore duplicate column error
	cols := []string{
		"http_requests", "http_success", "http_failure", "raw_tcp_requests",
		"http_bytes_sent", "http_bytes_recv", "raw_tcp_bytes_sent", "raw_tcp_bytes_recv",
	}
	for _, col := range cols {
		s.db.Exec(fmt.Sprintf("ALTER TABLE dimension_stats ADD COLUMN %s INTEGER DEFAULT 0", col))
	}

	return nil
}

// AddSnapshot saves a TimeSeriesSnapshot to the database and cleans up old data.
func (s *StatsDB) AddSnapshot(snapshot TimeSeriesSnapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Insert global stats
	res, err := tx.Exec(`
		INSERT INTO snapshots (timestamp, total_requests, active_connections, requests_per_second, bytes_received, bytes_sent)
		VALUES (?, ?, ?, ?, ?, ?)
	`, snapshot.Timestamp, snapshot.Global.TotalRequests, snapshot.Global.ActiveConnections, snapshot.Global.RequestsPerSecond, snapshot.Global.BytesReceived, snapshot.Global.BytesSent)
	if err != nil {
		return fmt.Errorf("failed to insert snapshot: %v", err)
	}

	snapshotID, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %v", err)
	}

	// Helper to insert dimension stats
	insertDim := func(dimType string, m map[string]*DimensionStats) error {
		stmt, err := tx.Prepare(`
			INSERT INTO dimension_stats (
				snapshot_id, dimension_type, dimension_key, requests, bytes_recv, bytes_sent, errors, avg_resp_time,
				http_requests, http_success, http_failure, raw_tcp_requests,
				http_bytes_sent, http_bytes_recv, raw_tcp_bytes_sent, raw_tcp_bytes_recv
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for key, stat := range m {
			if stat == nil {
				continue
			}
			_, err = stmt.Exec(
				snapshotID, dimType, key,
				stat.Requests, stat.BytesRecv, stat.BytesSent, stat.Errors, stat.AvgRespTime,
				stat.HTTPRequests, stat.HTTPSuccess, stat.HTTPFailure, stat.RawTCPRequests,
				stat.HTTPBytesSent, stat.HTTPBytesRecv, stat.RawTCPBytesSent, stat.RawTCPBytesRecv,
			)
			if err != nil {
				return err
			}
		}
		return nil
	}

	if err := insertDim("rules", snapshot.Rules); err != nil {
		return err
	}
	if err := insertDim("users", snapshot.Users); err != nil {
		return err
	}
	if err := insertDim("servers", snapshot.Servers); err != nil {
		return err
	}
	if err := insertDim("tunnels", snapshot.Tunnels); err != nil {
		return err
	}
	if err := insertDim("proxies", snapshot.Proxies); err != nil {
		return err
	}
	if err := insertDim("ips", snapshot.IPs); err != nil {
		return err
	}

	// Cleanup old data (older than 24 hours)
	cutoff := time.Now().Unix() - 24*60*60
	_, err = tx.Exec("DELETE FROM snapshots WHERE timestamp < ?", cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup old snapshots: %v", err)
	}
	// dimension_stats will be deleted automatically via ON DELETE CASCADE if enabled?
	// SQLite foreign keys are disabled by default. We should manually delete or enable FKs.
	// For safety, let's manually delete or just enable FK support.
	// But let's just use manual delete for broad compatibility.
	_, err = tx.Exec("DELETE FROM dimension_stats WHERE snapshot_id NOT IN (SELECT id FROM snapshots)")
	if err != nil {
		return fmt.Errorf("failed to cleanup orphaned dimension stats: %v", err)
	}

	return tx.Commit()
}

// GetGlobalTimeSeries retrieves global stats for the last 24 hours.
func (s *StatsDB) GetGlobalTimeSeries() ([]map[string]interface{}, error) {
	rows, err := s.db.Query(`
		SELECT timestamp, total_requests, active_connections, requests_per_second, bytes_received, bytes_sent
		FROM snapshots
		ORDER BY timestamp ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var ts int64
		var totalReq uint64
		var activeConn int64
		var qps float64
		var bytesRecv, bytesSent uint64
		if err := rows.Scan(&ts, &totalReq, &activeConn, &qps, &bytesRecv, &bytesSent); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{
			"timestamp":         ts,
			"totalRequests":     totalReq,
			"activeConnections": activeConn,
			"requestsPerSecond": qps,
			"bytesReceived":     bytesRecv,
			"bytesSent":         bytesSent,
		})
	}
	return result, nil
}

// GetDimensionTimeSeries retrieves stats for a specific dimension key.
func (s *StatsDB) GetDimensionTimeSeries(dimType, key string) ([]map[string]interface{}, error) {
	rows, err := s.db.Query(`
		SELECT s.timestamp, d.requests, d.bytes_recv, d.bytes_sent, d.errors, d.avg_resp_time,
		       d.http_bytes_sent, d.http_bytes_recv, d.raw_tcp_bytes_sent, d.raw_tcp_bytes_recv
		FROM dimension_stats d
		JOIN snapshots s ON d.snapshot_id = s.id
		WHERE d.dimension_type = ? AND d.dimension_key = ?
		ORDER BY s.timestamp ASC
	`, dimType, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var ts int64
		var reqs, bRecv, bSent, errs uint64
		var avgResp float64
		var hBSent, hBRecv, rBSent, rBRecv uint64

		if err := rows.Scan(&ts, &reqs, &bRecv, &bSent, &errs, &avgResp, &hBSent, &hBRecv, &rBSent, &rBRecv); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{
			"timestamp":       ts,
			"requests":        reqs,
			"bytesRecv":       bRecv,
			"bytesSent":       bSent,
			"errors":          errs,
			"avgRespTime":     avgResp,
			"httpBytesSent":   hBSent,
			"httpBytesRecv":   hBRecv,
			"rawTcpBytesSent": rBSent,
			"rawTcpBytesRecv": rBRecv,
		})
	}
	return result, nil
}

// SaveQuotaUsage saves or updates a quota usage entry in the database.
func (s *StatsDB) SaveQuotaUsage(sourceKey string, trafficUsed, requestsUsed int64) error {
	_, err := s.db.Exec(`
		INSERT INTO quota_usage (source_key, traffic_used, requests_used)
		VALUES (?, ?, ?)
		ON CONFLICT(source_key) DO UPDATE SET
			traffic_used = EXCLUDED.traffic_used,
			requests_used = EXCLUDED.requests_used
	`,
		sourceKey, trafficUsed, requestsUsed)
	if err != nil {
		return fmt.Errorf("failed to save quota usage for %s: %v", sourceKey, err)
	}
	return nil
}

// LoadAllQuotaUsage loads all quota usage entries from the database.
func (s *StatsDB) LoadAllQuotaUsage() (map[string]*QuotaUsageData, error) {
	rows, err := s.db.Query(`SELECT source_key, traffic_used, requests_used FROM quota_usage`)
	if err != nil {
		return nil, fmt.Errorf("failed to load all quota usage: %v", err)
	}
	defer rows.Close()

	quotas := make(map[string]*QuotaUsageData)
	for rows.Next() {
		var sourceKey string
		var trafficUsed, requestsUsed int64
		if err := rows.Scan(&sourceKey, &trafficUsed, &requestsUsed); err != nil {
			return nil, fmt.Errorf("failed to scan quota usage row: %v", err)
		}
		quotas[sourceKey] = &QuotaUsageData{
			TrafficUsed:  trafficUsed,
			RequestsUsed: requestsUsed,
		}
	}
	return quotas, nil
}
