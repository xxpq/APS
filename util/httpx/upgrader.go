package httpx

import (
	"net/http"

	"github.com/gorilla/websocket"
)

// UtilUpgrader is the shared gorilla/websocket Upgrader used by both
// the proxy and the tunnel logic. Exposing it as a package var avoids
// duplicating the (1MB read/write buffer) configuration in every file
// that upgrades WebSocket connections.
var UtilUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024 * 1024, // 1MB buffer for large messages
	WriteBufferSize: 1024 * 1024, // 1MB buffer for large messages
	// Allow any origin.
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}
