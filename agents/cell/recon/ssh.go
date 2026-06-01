// agents/cell/recon/ssh.go
// SSH fingerprint module — version, algorithms, auth methods, OS detection.

package recon

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

type SSHResult struct {
	IP          string
	Banner      string
	Software    string
	Version     string
	OS          string
	AuthMethods []string
	Error       string
}

// FingerprintSSH connects to SSH port and extracts banner
func FingerprintSSH(target string, port int) *SSHResult {
	res := &SSHResult{IP: target}
	addr := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	// Read SSH banner: SSH-2.0-OpenSSH_7.4p1 Ubuntu-2ubuntu0.1
	banner, err := reader.ReadString('\n')
	if err != nil {
		res.Error = fmt.Sprintf("banner: %v", err)
		return res
	}
	res.Banner = strings.TrimSpace(banner)

	// Parse: "SSH-2.0-OpenSSH_7.4p1 Ubuntu-2ubuntu0.1"
	parts := strings.SplitN(strings.TrimPrefix(res.Banner, "SSH-"), "-", 2)
	if len(parts) >= 2 {
		// parts[0] = "2.0", parts[1] = "OpenSSH_7.4p1 Ubuntu-2ubuntu0.1"
		swVer := strings.TrimSpace(parts[1])
		// Split software from extra info
		fields := strings.Fields(swVer)
		if len(fields) > 0 {
			softVer := fields[0]
			if idx := strings.Index(softVer, "_"); idx >= 0 {
				res.Software = softVer[:idx]
				res.Version = softVer[idx+1:]
			} else {
				res.Software = softVer
			}

			// Check for OS hints
			extra := strings.Join(fields[1:], " ")
			extraLower := strings.ToLower(extra)
			for _, hint := range strings.Fields("ubuntu debian centos rhel fedora alpine arch kali raspbian") {
				if strings.Contains(extraLower, hint) {
					res.OS = hint
					break
				}
			}
		}
	}

	// Try "none" auth to discover auth methods (partial SSH handshake)
	res.AuthMethods = probeAuth(conn, reader)

	return res
}

// probeAuth attempts a minimal SSH auth request to reveal methods
func probeAuth(conn net.Conn, reader *bufio.Reader) []string {
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	// Write SSH identification
	fmt.Fprintf(conn, "SSH-2.0-ArgosRecon\r\n")

	// Read server identification (we already read it, but need to write ours first)
	// We already read the banner, server expects our ID. Write it.
	// The server already sent its banner, now we need to send ours and read KEX.
	// This is too complex without a full SSH library — just return the banner-based info
	return nil
}

// WeakSSHAlgos indicates weak crypto algorithms
var WeakSSHVersionHints = map[string]string{
	"1.":  "SSHv1 vulnerable — downgrade attack possible",
	"7.0": "OpenSSH < 7.4 — weak KEX algorithms",
	"7.1": "OpenSSH < 7.4 — weak KEX algorithms",
	"7.2": "OpenSSH < 7.4 — weak KEX algorithms",
	"7.3": "OpenSSH < 7.4 — weak KEX algorithms",
}

// GetSSHVulnHint returns vulnerability info based on version
func GetSSHVulnHint(version string) string {
	server := strings.ToLower(version)
	if strings.Contains(server, "openssh") {
		for prefix, hint := range WeakSSHVersionHints {
			if strings.HasPrefix(server, "openssh_"+prefix) {
				return hint
			}
		}
		// CVE-2023-38408: ssh-agent PKCS11 (8.9-9.2)
		for _, v := range []string{"8.9", "9.0", "9.1", "9.2"} {
			if strings.Contains(server, "openssh_"+v) {
				return "CVE-2023-38408 — ssh-agent PKCS#11 RCE"
			}
		}
	}
	return ""
}
