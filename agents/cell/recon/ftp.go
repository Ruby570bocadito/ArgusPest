// agents/cell/recon/ftp.go
// FTP banner and anonymous login detection.

package recon

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

type FTPResult struct {
	IP          string
	Banner      string
	Anonymous   bool
	Software    string
	Version     string
	Error       string
}

// FingerprintFTP connects to FTP port and reads banner + tests anonymous login
func FingerprintFTP(target string, port int) *FTPResult {
	res := &FTPResult{IP: target}
	addr := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(conn, 1024)

	// Read banner: "220 ProFTPD 1.3.5 Server ..."
	line, err := reader.ReadString('\n')
	if err != nil {
		res.Error = fmt.Sprintf("banner: %v", err)
		return res
	}
	res.Banner = strings.TrimSpace(line)

	// Parse software and version from banner
	res.Software, res.Version = parseFTPBanner(res.Banner)

	// Test anonymous login
	res.Anonymous = testAnonymousLogin(conn, reader)

	return res
}

func parseFTPBanner(banner string) (string, string) {
	// "220 ProFTPD 1.3.5 Server" -> software=ProFTPD version=1.3.5
	// "220 (vsFTPd 2.3.4)" -> software=vsFTPd version=2.3.4
	for _, prefix := range []string{"ProFTPD", "vsFTPd", "vsftpd", "Pure-FTPd", "Microsoft FTP"} {
		lower := strings.ToLower(banner)
		lowerPrefix := strings.ToLower(prefix)
		if idx := strings.Index(lower, lowerPrefix); idx >= 0 {
			rest := banner[idx+len(prefix):]
			fields := strings.Fields(rest)
			for _, f := range fields {
				f = strings.Trim(f, "().,")
				if len(f) > 0 && (f[0] >= '0' && f[0] <= '9') {
					return prefix, f
				}
			}
			return prefix, ""
		}
	}
	return "unknown", ""
}

func testAnonymousLogin(conn net.Conn, reader *bufio.Reader) bool {
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))

	// USER anonymous
	fmt.Fprintf(conn, "USER anonymous\r\n")
	resp, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	if !strings.HasPrefix(resp, "331") && !strings.HasPrefix(resp, "230") {
		return false
	}

	// PASS anonymous
	fmt.Fprintf(conn, "PASS anonymous\r\n")
	resp, err = reader.ReadString('\n')
	if err != nil {
		return false
	}
	return strings.HasPrefix(resp, "230") || strings.HasPrefix(resp, "220")
}
