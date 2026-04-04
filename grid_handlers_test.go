package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGridHandlersSessionAuthAndRegister(t *testing.T) {
	cp := buildTestGridControlPlane(t, GridDeploymentModeStandalone)
	defer cp.Close()

	adminToken := "grid-admin-token"
	cfg := &Config{
		Auth: &AuthConfig{
			Users: map[string]*User{
				"admin": {
					Admin: true,
					Token: adminToken,
				},
			},
		},
	}

	mux := http.NewServeMux()
	NewGridHandlers(cfg, cp, "server-a").RegisterHandlers(mux)

	registerReqBody := []byte(`{"node":{"node_id":"node-a","capabilities":["quic","tcp"]}}`)
	registerReq := httptest.NewRequest(http.MethodPost, "/.grid/register", bytes.NewReader(registerReqBody))
	registerRec := httptest.NewRecorder()
	mux.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized register status, got %d", registerRec.Code)
	}

	unauthorizedIssueReq := httptest.NewRequest(http.MethodPost, "/.grid/session/issue", bytes.NewReader([]byte(`{"node_id":"node-a"}`)))
	unauthorizedIssueRec := httptest.NewRecorder()
	mux.ServeHTTP(unauthorizedIssueRec, unauthorizedIssueReq)
	if unauthorizedIssueRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized issue status, got %d", unauthorizedIssueRec.Code)
	}

	issueReq := httptest.NewRequest(http.MethodPost, "/.grid/session/issue", bytes.NewReader([]byte(`{"node_id":"node-a","scope":"`+defaultGridEndpointControlScopes()+`"}`)))
	issueReq.Header.Set("Authorization", "Bearer "+adminToken)
	issueRec := httptest.NewRecorder()
	mux.ServeHTTP(issueRec, issueReq)
	if issueRec.Code != http.StatusOK {
		t.Fatalf("issue status=%d body=%s", issueRec.Code, issueRec.Body.String())
	}
	var issueResp GridIssueTokenResponse
	if err := json.Unmarshal(issueRec.Body.Bytes(), &issueResp); err != nil {
		t.Fatalf("parse issue response failed: %v", err)
	}
	if !issueResp.Success || issueResp.Token == nil || issueResp.Token.Token == "" {
		t.Fatalf("unexpected issue response: %+v", issueResp)
	}
	endpointToken := issueResp.Token.Token

	registerReq = httptest.NewRequest(http.MethodPost, "/.grid/register", bytes.NewReader(registerReqBody))
	registerReq.Header.Set("Authorization", "Bearer "+endpointToken)
	registerRec = httptest.NewRecorder()
	mux.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", registerRec.Code, registerRec.Body.String())
	}
	var registerResp GridRegisterResponse
	if err := json.Unmarshal(registerRec.Body.Bytes(), &registerResp); err != nil {
		t.Fatalf("parse register response failed: %v", err)
	}
	if !registerResp.Success || registerResp.Node.NodeID != "node-a" {
		t.Fatalf("unexpected register response: %+v", registerResp)
	}

	icePublishReq := httptest.NewRequest(http.MethodPost, "/.grid/ice/publish", bytes.NewReader([]byte(`{"node_id":"node-a","candidates":["192.168.1.10:5000","203.0.113.10:443"],"ttl_seconds":60}`)))
	icePublishReq.Header.Set("Authorization", "Bearer "+endpointToken)
	icePublishRec := httptest.NewRecorder()
	mux.ServeHTTP(icePublishRec, icePublishReq)
	if icePublishRec.Code != http.StatusOK {
		t.Fatalf("ice publish status=%d body=%s", icePublishRec.Code, icePublishRec.Body.String())
	}
	var icePublishResp GridICEPublishResponse
	if err := json.Unmarshal(icePublishRec.Body.Bytes(), &icePublishResp); err != nil {
		t.Fatalf("parse ice publish response failed: %v", err)
	}
	if !icePublishResp.Success || icePublishResp.Set == nil || len(icePublishResp.Set.Candidates) == 0 {
		t.Fatalf("unexpected ice publish response: %+v", icePublishResp)
	}

	iceQueryReq := httptest.NewRequest(http.MethodPost, "/.grid/ice/query", bytes.NewReader([]byte(`{"node_id":"node-a"}`)))
	iceQueryReq.Header.Set("Authorization", "Bearer "+endpointToken)
	iceQueryRec := httptest.NewRecorder()
	mux.ServeHTTP(iceQueryRec, iceQueryReq)
	if iceQueryRec.Code != http.StatusOK {
		t.Fatalf("ice query status=%d body=%s", iceQueryRec.Code, iceQueryRec.Body.String())
	}
	var iceQueryResp GridICEQueryResponse
	if err := json.Unmarshal(iceQueryRec.Body.Bytes(), &iceQueryResp); err != nil {
		t.Fatalf("parse ice query response failed: %v", err)
	}
	if !iceQueryResp.Success || len(iceQueryResp.Candidates) == 0 {
		t.Fatalf("unexpected ice query response: %+v", iceQueryResp)
	}

	iceSessionIssueReq := httptest.NewRequest(http.MethodPost, "/.grid/ice/session/issue", bytes.NewReader([]byte(`{"node_id":"node-a","ttl_seconds":30}`)))
	iceSessionIssueReq.Header.Set("Authorization", "Bearer "+endpointToken)
	iceSessionIssueRec := httptest.NewRecorder()
	mux.ServeHTTP(iceSessionIssueRec, iceSessionIssueReq)
	if iceSessionIssueRec.Code != http.StatusOK {
		t.Fatalf("ice session issue status=%d body=%s", iceSessionIssueRec.Code, iceSessionIssueRec.Body.String())
	}
	var iceSessionIssueResp GridICEIssueSessionResponse
	if err := json.Unmarshal(iceSessionIssueRec.Body.Bytes(), &iceSessionIssueResp); err != nil {
		t.Fatalf("parse ice session issue response failed: %v", err)
	}
	if !iceSessionIssueResp.Success || iceSessionIssueResp.Session == nil || iceSessionIssueResp.Session.SessionID == "" {
		t.Fatalf("unexpected ice session issue response: %+v", iceSessionIssueResp)
	}

	iceSessionRefreshReq := httptest.NewRequest(http.MethodPost, "/.grid/ice/session/refresh", bytes.NewReader([]byte(`{"node_id":"node-a"}`)))
	iceSessionRefreshReq.Header.Set("Authorization", "Bearer "+endpointToken)
	iceSessionRefreshRec := httptest.NewRecorder()
	mux.ServeHTTP(iceSessionRefreshRec, iceSessionRefreshReq)
	if iceSessionRefreshRec.Code != http.StatusOK {
		t.Fatalf("ice session refresh status=%d body=%s", iceSessionRefreshRec.Code, iceSessionRefreshRec.Body.String())
	}
	var iceSessionRefreshResp GridICERefreshSessionResponse
	if err := json.Unmarshal(iceSessionRefreshRec.Body.Bytes(), &iceSessionRefreshResp); err != nil {
		t.Fatalf("parse ice session refresh response failed: %v", err)
	}
	if !iceSessionRefreshResp.Success || iceSessionRefreshResp.Session == nil || iceSessionRefreshResp.Session.SessionID == "" {
		t.Fatalf("unexpected ice session refresh response: %+v", iceSessionRefreshResp)
	}

	sessionRefreshReq := httptest.NewRequest(http.MethodPost, "/.grid/session/refresh", bytes.NewReader([]byte(`{"node_id":"node-a"}`)))
	sessionRefreshReq.Header.Set("Authorization", "Bearer "+endpointToken)
	sessionRefreshRec := httptest.NewRecorder()
	mux.ServeHTTP(sessionRefreshRec, sessionRefreshReq)
	if sessionRefreshRec.Code != http.StatusOK {
		t.Fatalf("session refresh status=%d body=%s", sessionRefreshRec.Code, sessionRefreshRec.Body.String())
	}
	var sessionRefreshResp GridRefreshTokenResponse
	if err := json.Unmarshal(sessionRefreshRec.Body.Bytes(), &sessionRefreshResp); err != nil {
		t.Fatalf("parse session refresh response failed: %v", err)
	}
	if !sessionRefreshResp.Success || sessionRefreshResp.Token == nil || sessionRefreshResp.Token.Token == "" {
		t.Fatalf("unexpected session refresh response: %+v", sessionRefreshResp)
	}
	refreshedToken := sessionRefreshResp.Token.Token

	oldTokenQueryReq := httptest.NewRequest(http.MethodPost, "/.grid/ice/query", bytes.NewReader([]byte(`{"node_id":"node-a"}`)))
	oldTokenQueryReq.Header.Set("Authorization", "Bearer "+endpointToken)
	oldTokenQueryRec := httptest.NewRecorder()
	mux.ServeHTTP(oldTokenQueryRec, oldTokenQueryReq)
	if oldTokenQueryRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected rotated old token to be unauthorized, got %d", oldTokenQueryRec.Code)
	}

	newTokenQueryReq := httptest.NewRequest(http.MethodPost, "/.grid/ice/query", bytes.NewReader([]byte(`{"node_id":"node-a"}`)))
	newTokenQueryReq.Header.Set("Authorization", "Bearer "+refreshedToken)
	newTokenQueryRec := httptest.NewRecorder()
	mux.ServeHTTP(newTokenQueryRec, newTokenQueryReq)
	if newTokenQueryRec.Code != http.StatusOK {
		t.Fatalf("expected refreshed token to be accepted, got %d", newTokenQueryRec.Code)
	}

	if _, err := cp.MarkNodeOffline(unauthorizedIssueReq.Context(), "node-a", "test-offline"); err != nil {
		t.Fatalf("mark node offline failed: %v", err)
	}
	eventsPullReq := httptest.NewRequest(http.MethodPost, "/.grid/events/pull", bytes.NewReader([]byte(`{"node_id":"node-a","cursor":0}`)))
	eventsPullReq.Header.Set("Authorization", "Bearer "+refreshedToken)
	eventsPullRec := httptest.NewRecorder()
	mux.ServeHTTP(eventsPullRec, eventsPullReq)
	if eventsPullRec.Code != http.StatusOK {
		t.Fatalf("events pull status=%d body=%s", eventsPullRec.Code, eventsPullRec.Body.String())
	}
	var eventsPullResp GridEventsPullResponse
	if err := json.Unmarshal(eventsPullRec.Body.Bytes(), &eventsPullResp); err != nil {
		t.Fatalf("parse events pull response failed: %v", err)
	}
	if !eventsPullResp.Success {
		t.Fatalf("events pull not successful: %+v", eventsPullResp)
	}

	topologyReq := httptest.NewRequest(http.MethodGet, "/.grid/topology", nil)
	topologyReq.Header.Set("Authorization", "Bearer "+adminToken)
	topologyRec := httptest.NewRecorder()
	mux.ServeHTTP(topologyRec, topologyReq)
	if topologyRec.Code != http.StatusOK {
		t.Fatalf("topology status=%d body=%s", topologyRec.Code, topologyRec.Body.String())
	}
	var topologyResp GridTopologyResponse
	if err := json.Unmarshal(topologyRec.Body.Bytes(), &topologyResp); err != nil {
		t.Fatalf("parse topology response failed: %v", err)
	}
	if !topologyResp.Success {
		t.Fatalf("topology response not successful: %+v", topologyResp)
	}

	revokeReqBody := []byte(`{"token":"` + refreshedToken + `"}`)
	revokeReq := httptest.NewRequest(http.MethodPost, "/.grid/session/revoke", bytes.NewReader(revokeReqBody))
	revokeReq.Header.Set("Authorization", "Bearer "+adminToken)
	revokeRec := httptest.NewRecorder()
	mux.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revokeRec.Code, revokeRec.Body.String())
	}
	var revokeResp GridRevokeTokenResponse
	if err := json.Unmarshal(revokeRec.Body.Bytes(), &revokeResp); err != nil {
		t.Fatalf("parse revoke response failed: %v", err)
	}
	if !revokeResp.Success {
		t.Fatalf("unexpected revoke response: %+v", revokeResp)
	}

	revokedIceQueryReq := httptest.NewRequest(http.MethodPost, "/.grid/ice/query", bytes.NewReader([]byte(`{"node_id":"node-a"}`)))
	revokedIceQueryReq.Header.Set("Authorization", "Bearer "+refreshedToken)
	revokedIceQueryRec := httptest.NewRecorder()
	mux.ServeHTTP(revokedIceQueryRec, revokedIceQueryReq)
	if revokedIceQueryRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected revoked token to be unauthorized, got %d", revokedIceQueryRec.Code)
	}
}
