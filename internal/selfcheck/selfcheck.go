package selfcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func Run() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("start-up self-check: Linux required")
	}
	return Check("/", os.Getuid(), os.Geteuid())
}

// Check accepts a filesystem root so tests can supply proc and socket fixtures.
func Check(root string, uid, euid int) error {
	var failed []string
	if uid == 0 || euid == 0 {
		failed = append(failed, "root UID")
	}
	mounts, mountErr := os.ReadFile(filepath.Join(root, "proc/self/mountinfo"))
	if mountErr != nil {
		failed = append(failed, "mountinfo unavailable")
	} else {
		foundRoot := false
		for _, line := range strings.Split(string(mounts), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			if fields[4] == "/" {
				foundRoot = true
				if strings.Contains(","+fields[5]+",", ",rw,") {
					failed = append(failed, "writable root filesystem")
				}
			}
			if strings.HasSuffix(fields[4], "docker.sock") {
				failed = append(failed, "Docker socket mount")
			}
		}
		if !foundRoot {
			failed = append(failed, "root mount missing")
		}
	}
	status, statusErr := os.ReadFile(filepath.Join(root, "proc/self/status"))
	if statusErr != nil {
		failed = append(failed, "status unavailable")
	} else {
		seen := map[string]bool{}
		for _, line := range strings.Split(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			key := strings.TrimSuffix(fields[0], ":")
			switch key {
			case "CapEff", "CapPrm", "CapBnd":
				seen[key] = true
				if strings.TrimLeft(fields[1], "0") != "" {
					failed = append(failed, key+" nonzero")
				}
			case "NoNewPrivs":
				seen[key] = true
				if fields[1] != "1" {
					failed = append(failed, "NoNewPrivs disabled")
				}
			}
		}
		for _, key := range []string{"CapEff", "CapPrm", "CapBnd", "NoNewPrivs"} {
			if !seen[key] {
				failed = append(failed, key+" missing")
			}
		}
	}
	for _, path := range []string{"var/run/docker.sock", "run/docker.sock"} {
		if _, err := os.Lstat(filepath.Join(root, path)); err == nil {
			failed = append(failed, "Docker socket present")
		} else if !os.IsNotExist(err) {
			failed = append(failed, "Docker socket check failed")
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("start-up self-check: %s", strings.Join(failed, ", "))
	}
	return nil
}
