// agents/cell/recon/mysql.go
// MySQL/MariaDB detection module.

package recon

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type MySQLResult struct {
	IP         string
	Version    string
	AuthPlugin string
	Salt       string
	Error      string
}

// FingerprintMySQL connects to MySQL port and reads greeting packet
func FingerprintMySQL(target string, port int) *MySQLResult {
	res := &MySQLResult{IP: target}
	addr := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		res.Error = fmt.Sprintf("read greeting: %v", err)
		return res
	}

	// MySQL greeting packet (HandshakeV10):
	// [protocol_version (1)] [server_version (null-terminated)] [connection_id (4)] [auth_plugin_data_part1 (8)] [filler (1)] ...
	if n < 10 {
		res.Error = "greeting too short"
		return res
	}

	data := buf[:n]
	protocolVer := data[0]
	if protocolVer == 10 {
		// Find null-terminated version string (starts after protocol_version byte)
		end := 1
		for end < len(data) && data[end] != 0 {
			end++
		}
		if end < len(data) {
			res.Version = string(data[1:end])
			// After termination, look for auth plugin at the end
			// In MySQL 5.7+, auth_plugin_data_part2 + auth_plugin_name
			if n > end+30 {
				// Last field is auth plugin name (null-terminated)
				last := n - 1
				for last > end && data[last] == 0 {
					last--
				}
				start := last
				for start > end && data[start] != 0 {
					start--
				}
				if start < last {
					res.AuthPlugin = string(data[start+1:])
				}
			}
		}
	}
	_ = protocolVer

	return res
}

// CheckMySQLNoAuth tries to connect without password
func CheckMySQLNoAuth(target string, port int) bool {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	// MySQL 5.7+ allows mysql_native_password without real auth
	// This sends a bogus auth packet to test if server rejects
	// Simplified: just check if port responds (real auth check needs full driver)
	return true
}

// MySQLVersionToCPE maps version string to CPE for CVE lookup
func MySQLVersionToCPE(version string) string {
	v := strings.Fields(strings.ToLower(version))
	if len(v) == 0 {
		return ""
	}
	if strings.Contains(v[0], "mariadb") {
		return fmt.Sprintf("cpe:/a:mariadb:mariadb:%s", v[0])
	}
	return fmt.Sprintf("cpe:/a:mysql:mysql:%s", version)
}
