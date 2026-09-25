package selfcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChecks(t *testing.T) {
	goodMount := "1 0 0:1 / / ro,relatime - overlay overlay ro\n"
	goodStatus := "CapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\n"
	for _, tc := range []struct {
		name, mount, status, socket, want string
		uid, euid                         int
	}{
		{name: "good", mount: goodMount, status: goodStatus, uid: 65532, euid: 65532},
		{name: "root uid", mount: goodMount, status: goodStatus, uid: 0, euid: 65532, want: "root UID"},
		{name: "root euid", mount: goodMount, status: goodStatus, uid: 65532, euid: 0, want: "root UID"},
		{name: "writable", mount: strings.Replace(goodMount, "ro,relatime", "rw,relatime", 1), status: goodStatus, uid: 65532, euid: 65532, want: "writable root"},
		{name: "CapEff", mount: goodMount, status: strings.Replace(goodStatus, "CapEff:\t0000000000000000", "CapEff:\t0000000000000001", 1), uid: 65532, euid: 65532, want: "CapEff"},
		{name: "CapPrm", mount: goodMount, status: strings.Replace(goodStatus, "CapPrm:\t0000000000000000", "CapPrm:\t0000000000000001", 1), uid: 65532, euid: 65532, want: "CapPrm"},
		{name: "CapBnd", mount: goodMount, status: strings.Replace(goodStatus, "CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001", 1), uid: 65532, euid: 65532, want: "CapBnd"},
		{name: "NoNewPrivs", mount: goodMount, status: strings.Replace(goodStatus, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), uid: 65532, euid: 65532, want: "NoNewPrivs"},
		{name: "socket file", mount: goodMount, status: goodStatus, socket: "var/run/docker.sock", uid: 65532, euid: 65532, want: "Docker socket"},
		{name: "socket mount", mount: goodMount + "2 1 0:2 / /run/docker.sock ro - tmpfs tmpfs ro\n", status: goodStatus, uid: 65532, euid: 65532, want: "Docker socket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "proc/self"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "proc/self/mountinfo"), []byte(tc.mount), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "proc/self/status"), []byte(tc.status), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.socket != "" {
				path := filepath.Join(root, tc.socket)
				os.MkdirAll(filepath.Dir(path), 0700)
				os.WriteFile(path, nil, 0600)
			}
			err := Check(root, tc.uid, tc.euid)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("want %q: %v", tc.want, err)
			}
		})
	}
}
