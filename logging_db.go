package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// LoggingDB manages the SQLite database for request logging
type LoggingDB struct {
	db *sql.DB
}

// LogEntry represents a single request log entry
type LogEntry struct {
	ID             int64     `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Protocol       string    `json:"protocol"`              // "http", "https", or "rawtcp"
	URL            string    `json:"url,omitempty"`         // for HTTP/HTTPS
	Destination    string    `json:"destination,omitempty"` // for RawTCP (host:port)
	Method         string    `json:"method,omitempty"`      // for HTTP/HTTPS
	StatusCode     int       `json:"statusCode,omitempty"`  // for HTTP/HTTPS
	DurationMs     int64     `json:"durationMs"`
	RequestSize    int64     `json:"requestSize"`
	ResponseSize   int64     `json:"responseSize"`
	ServerName     string    `json:"serverName,omitempty"`
	TunnelName     string    `json:"tunnelName,omitempty"`
	ProxyName      string    `json:"proxyName,omitempty"`
	EndpointName   string    `json:"endpointName,omitempty"`
	FirewallName   string    `json:"firewallName,omitempty"`
	UserName       string    `json:"userName,omitempty"`
	UserGroup      string    `json:"userGroup,omitempty"`
	ClientIP       string    `json:"clientIP"`
	Country        string    `json:"country,omitempty"`        // IP geolocation: Country name
	Region         string    `json:"region,omitempty"`         // IP geolocation: State/Region name
	Token          string    `json:"token,omitempty"`          // Extracted token (if any)
	RequestHeaders string    `json:"requestHeaders,omitempty"` // JSON string, level 2 only
	RequestBody    string    `json:"requestBody,omitempty"`    // TEXT, level 2 only (limited to 1MB)
}

// LogQueryFilter represents query filter parameters
type LogQueryFilter struct {
	StartTime  *time.Time
	EndTime    *time.Time
	Protocols  []string // "http", "https", "rawtcp"
	Servers    []string
	Tunnels    []string
	Proxies    []string
	Endpoints  []string
	Firewalls  []string
	Users      []string
	UserGroups []string
	Page       int // 1-indexed
	PageSize   int // default 50, max 100
}

// NewLoggingDB creates and initializes logging module with a shared database connection
func NewLoggingDB(db *sql.DB) (*LoggingDB, error) {
	loggingDB := &LoggingDB{db: db}
	if err := loggingDB.initSchema(); err != nil {
		return nil, err
	}

	return loggingDB, nil
}

// Close closes the database connection
// Close is a no-op as the database connection is managed externally
func (l *LoggingDB) Close() error {
	// Database is closed in main.go
	return nil
}

// initSchema creates the necessary tables and indexes
func (l *LoggingDB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS request_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		url TEXT,
		destination TEXT,
		method TEXT,
		status_code INTEGER,
		duration_ms INTEGER NOT NULL,
		request_size INTEGER NOT NULL,
		response_size INTEGER NOT NULL,
		server_name TEXT,
		tunnel_name TEXT,
		proxy_name TEXT,
		endpoint_name TEXT,
		firewall_name TEXT,
		user_name TEXT,
		user_group TEXT,
		client_ip TEXT NOT NULL,
		country TEXT,
		region TEXT,
		token TEXT,
		request_headers TEXT,
		request_body TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON request_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_logs_protocol ON request_logs(protocol);
	CREATE INDEX IF NOT EXISTS idx_logs_server ON request_logs(server_name);
	CREATE INDEX IF NOT EXISTS idx_logs_tunnel ON request_logs(tunnel_name);
	CREATE INDEX IF NOT EXISTS idx_logs_user ON request_logs(user_name);
	CREATE INDEX IF NOT EXISTS idx_logs_client_ip ON request_logs(client_ip);
	CREATE INDEX IF NOT EXISTS idx_logs_country ON request_logs(country);
	`

	if _, err := l.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create logging schema: %v", err)
	}

	// Migration: Add token column if it doesn't exist
	// Ignore error "duplicate column name"
	l.db.Exec("ALTER TABLE request_logs ADD COLUMN token TEXT;")

	// Migration: Add geolocation columns if they don't exist
	l.db.Exec("ALTER TABLE request_logs ADD COLUMN country TEXT;")
	l.db.Exec("ALTER TABLE request_logs ADD COLUMN region TEXT;")

	return nil
}

// AddLog adds a new log entry to the database
func (l *LoggingDB) AddLog(entry *LogEntry) error {
	query := `
		INSERT INTO request_logs (
			timestamp, protocol, url, destination, method, status_code,
			duration_ms, request_size, response_size,
			server_name, tunnel_name, proxy_name, endpoint_name,
			firewall_name, user_name, user_group, client_ip,
			country, region, token,
			request_headers, request_body
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := l.db.Exec(query,
		entry.Timestamp.Unix(),
		entry.Protocol,
		entry.URL,
		entry.Destination,
		entry.Method,
		entry.StatusCode,
		entry.DurationMs,
		entry.RequestSize,
		entry.ResponseSize,
		entry.ServerName,
		entry.TunnelName,
		entry.ProxyName,
		entry.EndpointName,
		entry.FirewallName,
		entry.UserName,
		entry.UserGroup,
		entry.ClientIP,
		entry.Country,
		entry.Region,
		entry.Token,
		entry.RequestHeaders,
		entry.RequestBody,
	)

	if err != nil {
		return fmt.Errorf("failed to insert log entry: %v", err)
	}

	return nil
}

// QueryLogs retrieves logs based on the provided filter with pagination
// Returns (logs, totalCount, error)
func (l *LoggingDB) QueryLogs(filter LogQueryFilter) ([]LogEntry, int, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}

	if filter.StartTime != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.StartTime.Unix())
	}

	if filter.EndTime != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.EndTime.Unix())
	}

	if len(filter.Protocols) > 0 {
		placeholders := make([]string, len(filter.Protocols))
		for i, p := range filter.Protocols {
			placeholders[i] = "?"
			args = append(args, p)
		}
		conditions = append(conditions, fmt.Sprintf("protocol IN (%s)", strings.Join(placeholders, ",")))
	}

	// Helper to add IN clause for string arrays
	addInCondition := func(column string, values []string) {
		if len(values) > 0 {
			placeholders := make([]string, len(values))
			for i, v := range values {
				placeholders[i] = "?"
				args = append(args, v)
			}
			conditions = append(conditions, fmt.Sprintf("%s IN (%s)", column, strings.Join(placeholders, ",")))
		}
	}

	addInCondition("server_name", filter.Servers)
	addInCondition("tunnel_name", filter.Tunnels)
	addInCondition("proxy_name", filter.Proxies)
	addInCondition("endpoint_name", filter.Endpoints)
	addInCondition("firewall_name", filter.Firewalls)
	addInCondition("user_name", filter.Users)
	addInCondition("user_group", filter.UserGroups)

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM request_logs %s", whereClause)
	var totalCount int
	if err := l.db.QueryRow(countQuery, args...).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("failed to count logs: %v", err)
	}

	// Calculate pagination
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 {
		filter.PageSize = 50
	}
	if filter.PageSize > 100 {
		filter.PageSize = 100
	}

	offset := (filter.Page - 1) * filter.PageSize

	// Query logs with pagination
	query := fmt.Sprintf(`
		SELECT id, timestamp, protocol, url, destination, method, status_code,
		       duration_ms, request_size, response_size,
		       server_name, tunnel_name, proxy_name, endpoint_name,
		       firewall_name, user_name, user_group, client_ip,
		       country, region, token,
		       request_headers, request_body
		FROM request_logs
		%s
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	args = append(args, filter.PageSize, offset)

	rows, err := l.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query logs: %v", err)
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var entry LogEntry
		var timestamp int64
		var url, destination, method sql.NullString
		var statusCode sql.NullInt64
		var serverName, tunnelName, proxyName, endpointName sql.NullString
		var firewallName, userName, userGroup sql.NullString
		var country, region sql.NullString
		var token sql.NullString
		var requestHeaders, requestBody sql.NullString

		err := rows.Scan(
			&entry.ID,
			&timestamp,
			&entry.Protocol,
			&url,
			&destination,
			&method,
			&statusCode,
			&entry.DurationMs,
			&entry.RequestSize,
			&entry.ResponseSize,
			&serverName,
			&tunnelName,
			&proxyName,
			&endpointName,
			&firewallName,
			&userName,
			&userGroup,
			&entry.ClientIP,
			&country,
			&region,
			&token,
			&requestHeaders,
			&requestBody,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan log entry: %v", err)
		}

		entry.Timestamp = time.Unix(timestamp, 0)
		if url.Valid {
			entry.URL = url.String
		}
		if destination.Valid {
			entry.Destination = destination.String
		}
		if method.Valid {
			entry.Method = method.String
		}
		if statusCode.Valid {
			entry.StatusCode = int(statusCode.Int64)
		}
		if serverName.Valid {
			entry.ServerName = serverName.String
		}
		if tunnelName.Valid {
			entry.TunnelName = tunnelName.String
		}
		if proxyName.Valid {
			entry.ProxyName = proxyName.String
		}
		if endpointName.Valid {
			entry.EndpointName = endpointName.String
		}
		if firewallName.Valid {
			entry.FirewallName = firewallName.String
		}
		if userName.Valid {
			entry.UserName = userName.String
		}
		if userGroup.Valid {
			entry.UserGroup = userGroup.String
		}
		if country.Valid {
			entry.Country = country.String
		}
		if region.Valid {
			entry.Region = region.String
		}
		if token.Valid {
			entry.Token = token.String
		}
		if requestHeaders.Valid {
			entry.RequestHeaders = requestHeaders.String
		}
		if requestBody.Valid {
			entry.RequestBody = requestBody.String
		}

		logs = append(logs, entry)
	}

	return logs, totalCount, nil
}

// DeleteLogs deletes logs by their IDs
func (l *LoggingDB) DeleteLogs(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf("DELETE FROM request_logs WHERE id IN (%s)", strings.Join(placeholders, ","))
	_, err := l.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to delete logs: %v", err)
	}

	return nil
}

// CleanupOldLogs removes logs older than the specified retention period
func (l *LoggingDB) CleanupOldLogs(retentionHours int) error {
	cutoff := time.Now().Add(-time.Duration(retentionHours) * time.Hour)

	result, err := l.db.Exec("DELETE FROM request_logs WHERE timestamp < ?", cutoff.Unix())
	if err != nil {
		return fmt.Errorf("failed to cleanup old logs: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		DebugLog("[LOGGING] Cleaned up %d old log entries", rowsAffected)
	}

	return nil
}

// Helper function to convert http.Header to JSON string
func HeadersToJSON(headers map[string][]string) string {
	if headers == nil {
		return ""
	}
	data, err := json.Marshal(headers)
	if err != nil {
		return ""
	}
	return string(data)
}
