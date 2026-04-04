package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type GridHandlers struct {
	config     *Config
	control    *GridControlPlane
	serverName string
}

func NewGridHandlers(config *Config, control *GridControlPlane, serverName string) *GridHandlers {
	return &GridHandlers{
		config:     config,
		control:    control,
		serverName: serverName,
	}
}

func (h *GridHandlers) RegisterHandlers(mux *http.ServeMux) {
	if h == nil || h.control == nil || mux == nil {
		return
	}
	mux.HandleFunc("/.grid/register", h.handleRegister)
	mux.HandleFunc("/.grid/heartbeat", h.handleHeartbeat)
	mux.HandleFunc("/.grid/route/announce", h.handleRouteAnnounce)
	mux.HandleFunc("/.grid/route/query", h.handleRouteQuery)
	mux.HandleFunc("/.grid/ice/publish", h.handleICEPublish)
	mux.HandleFunc("/.grid/ice/query", h.handleICEQuery)
	mux.HandleFunc("/.grid/ice/session/issue", h.handleICESessionIssue)
	mux.HandleFunc("/.grid/ice/session/refresh", h.handleICESessionRefresh)
	mux.HandleFunc("/.grid/events/pull", h.handleEventsPull)
	mux.HandleFunc("/.grid/topology", h.handleTopology)
	mux.HandleFunc("/.grid/session/issue", h.handleSessionIssue)
	mux.HandleFunc("/.grid/session/refresh", h.handleSessionRefresh)
	mux.HandleFunc("/.grid/session/revoke", h.handleSessionRevoke)
}

func (h *GridHandlers) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req GridRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if !h.authorizeNodeScope(w, r, req.Node.NodeID, GridScopeNodeRegister) {
		return
	}
	resp, err := h.control.RegisterNode(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req GridHeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if !h.authorizeNodeScope(w, r, req.NodeID, GridScopeNodeHeartbeat) {
		return
	}
	resp, err := h.control.HeartbeatNode(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleRouteAnnounce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req GridAnnounceRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if !h.authorizeNodeScope(w, r, req.Route.SourceNode, GridScopeRouteAnnounce) {
		return
	}
	resp, err := h.control.AnnounceRoute(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleRouteQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req GridQueryRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if !h.authorizeNodeScope(w, r, req.SourceNode, GridScopeRouteQuery) {
		return
	}
	resp, err := h.control.QueryRoutes(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleICEPublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req GridICEPublishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if !h.authorizeNodeScope(w, r, req.NodeID, GridScopeICEPublish) {
		return
	}
	resp, err := h.control.PublishICECandidates(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleICEQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req GridICEQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if !h.authorizeNodeScope(w, r, req.NodeID, GridScopeICEQuery) {
		return
	}
	resp, err := h.control.QueryICECandidates(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleICESessionIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req GridICEIssueSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if !h.authorizeNodeScope(w, r, req.NodeID, GridScopeICESessionIssue) {
		return
	}
	resp, err := h.control.IssueICESession(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleICESessionRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req GridICERefreshSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if !h.authorizeNodeScope(w, r, req.NodeID, GridScopeICESessionRefresh) {
		return
	}
	resp, err := h.control.RefreshICESession(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleSessionIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var req GridIssueTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	resp, err := h.control.IssueSessionToken(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleSessionRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := extractGridBearerToken(r)
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var req GridRefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	resp, err := h.control.RefreshSessionToken(r.Context(), token, &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if resp == nil || !resp.Success {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var req GridRevokeTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	resp, err := h.control.RevokeSessionToken(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleEventsPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req GridEventsPullRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if !h.authorizeNodeScope(w, r, req.NodeID, GridScopeEventPull) {
		return
	}
	resp, err := h.control.PullEvents(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func (h *GridHandlers) handleTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	req := GridTopologyRequest{}
	if r.Method == http.MethodPost {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	resp, err := h.control.TopologySnapshot(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGridJSON(w, resp)
}

func writeGridJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (h *GridHandlers) authorizeNodeScope(w http.ResponseWriter, r *http.Request, nodeID string, requiredScope string) bool {
	if h == nil || h.control == nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return false
	}
	token := extractGridBearerToken(r)
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	_, err := h.control.ValidateSessionToken(r.Context(), token, nodeID, requiredScope)
	if err == nil {
		return true
	}
	status := http.StatusUnauthorized
	if errors.Is(err, ErrGridTokenNodeMismatch) || errors.Is(err, ErrGridScopeDenied) {
		status = http.StatusForbidden
	}
	http.Error(w, "Unauthorized", status)
	return false
}

func extractGridBearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) < 8 {
		return ""
	}
	if !strings.EqualFold(auth[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(auth[7:])
}
