package channel

import "time"

// SetTestHeartbeat configures the channel for external integration tests only.
func SetTestHeartbeat(c *Client, interval time.Duration) { c.heartbeatEvery = interval }
