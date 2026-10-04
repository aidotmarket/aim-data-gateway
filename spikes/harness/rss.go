package harness

import (
	"os"
	"strconv"
	"strings"
)

// VmHWM is process lifetime, including earlier warm invocations; never reset.
func peakRSS() (uint64, bool) {
	b, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return 0, false
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 3 && f[0] == "VmHWM:" {
			n, e := strconv.ParseUint(f[1], 10, 64)
			return n * 1024, e == nil
		}
	}
	return 0, false
}
