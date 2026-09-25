package selfcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	} else if uid != 65532 || euid != 65532 {
		failed = append(failed, "UID must be 65532")
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
			mount, err := decodeMount(fields[4])
			if err != nil {
				failed = append(failed, "invalid mount point")
				continue
			}
			if mount == "/" {
				foundRoot = true
				if strings.Contains(","+fields[5]+",", ",rw,") {
					failed = append(failed, "writable root filesystem")
				}
			}
			if strings.HasSuffix(mount, "docker.sock") {
				failed = append(failed, "Docker socket mount")
			}
			if info, err := os.Lstat(filepath.Join(root, strings.TrimPrefix(mount, "/"))); err == nil {
				if info.Mode()&os.ModeSocket != 0 {
					failed = append(failed, "host socket mount "+mount)
				}
			} else if !os.IsNotExist(err) {
				failed = append(failed, "mount point check failed "+mount)
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

func decodeMount(path string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] == '\\' {
			if i+3 >= len(path) {
				return "", fmt.Errorf("short mount escape")
			}
			n, err := strconv.ParseUint(path[i+1:i+4], 8, 8)
			if err != nil {
				return "", err
			}
			out.WriteByte(byte(n))
			i += 3
		} else {
			out.WriteByte(path[i])
		}
	}
	return out.String(), nil
}
