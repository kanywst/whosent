package chain

import (
	"fmt"
	"time"
)

// Human formats a duration as a compact countdown: 45s, 12m, 3h05m, 2d4h.
// Adapters and the view use it so that a time left reads the same
// everywhere.
func Human(d time.Duration) string {
	neg := d < 0
	if neg {
		d = -d
	}
	var s string
	switch {
	case d < time.Minute:
		s = fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		s = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		s = fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		s = fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	}
	if neg {
		return "-" + s
	}
	return s
}
