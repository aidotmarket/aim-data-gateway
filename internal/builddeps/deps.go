// Package builddeps keeps the B0 approved SQLite and WebSocket libraries in
// the compiled dependency budget before later chunks start using them.
package builddeps

import (
	_ "github.com/coder/websocket"
	_ "modernc.org/sqlite"
)
