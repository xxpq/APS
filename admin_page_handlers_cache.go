package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// handleCacheConfig handles getting and setting cache configuration
func (h *AdminHandlers) handleCacheConfig(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	h.configMux.Lock()
	defer h.configMux.Unlock()

	if r.Method == http.MethodGet {
		if h.config.StaticCache == nil {
			// Return default empty config if nil
			json.NewEncoder(w).Encode(&StaticCacheConfig{Enabled: false})
			return
		}
		json.NewEncoder(w).Encode(h.config.StaticCache)
		return
	}

	if r.Method == http.MethodPost {
		var newConfig StaticCacheConfig
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Update config
		h.config.StaticCache = &newConfig

		// Save config to file
		if err := h.saveConfigLocked(); err != nil {
			http.Error(w, fmt.Sprintf("Failed to save config: %v", err), http.StatusInternalServerError)
			return
		}

		// Trigger hot reload (if watcher is active, it might pick it up, but we can also manually update if needed)
		// For now, saving to file is sufficient as the watcher should handle it.

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Cache configuration updated"))
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleCacheRefresh handles batch cache refresh
func (h *AdminHandlers) handleCacheRefresh(w http.ResponseWriter, r *http.Request) {
	if !isAdminRequest(r, h.config) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URLs []string `json:"urls"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if h.staticCache == nil {
		http.Error(w, "Static cache manager not initialized", http.StatusInternalServerError)
		return
	}

	var errs []string
	for _, u := range req.URLs {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if err := h.staticCache.Refresh(u); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", u, err))
		}
	}

	if len(errs) > 0 {
		http.Error(w, fmt.Sprintf("Some refreshes failed: %s", strings.Join(errs, "; ")), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Cache refreshed successfully"))
}
