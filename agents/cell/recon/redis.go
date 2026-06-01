// agents/cell/recon/redis.go
// Redis detection — no-auth check, INFO gathering.

package recon

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

type RedisResult struct {
	IP      string
	NoAuth  bool
	Version string
	OS      string
	Mode    string
	Error   string
}

// FingerprintRedis connects to Redis and checks auth + extracts INFO
func FingerprintRedis(target string, port int) *RedisResult {
	res := &RedisResult{IP: target}
	addr := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	// Send PING to test auth
	if _, err := rw.WriteString("PING\r\n"); err != nil {
		res.Error = fmt.Sprintf("write: %v", err)
		return res
	}
	rw.Flush()

	line, err := rw.ReadString('\n')
	if err != nil {
		res.Error = fmt.Sprintf("read: %v", err)
		return res
	}

	// +PONG = no auth, -NOAUTH = requires auth, -ERR = error
	if strings.HasPrefix(line, "+") {
		res.NoAuth = true
	} else if strings.HasPrefix(line, "-NOAUTH") {
		return res // requires auth, no further info
	} else {
		res.Error = strings.TrimSpace(line)
		return res
	}

	// Send INFO server
	if _, err := rw.WriteString("INFO server\r\n"); err != nil {
		return res
	}
	rw.Flush()

	// Read bulk response ($N...)
	infoLine, err := rw.ReadString('\n')
	if err != nil {
		return res
	}
	if !strings.HasPrefix(infoLine, "$") {
		return res
	}

	// Read bulk data
	info := make([]byte, 4096)
	n, _ := rw.Read(info)
	infoStr := string(info[:n])

	for _, line := range strings.Split(infoStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redis_version:") {
			res.Version = strings.TrimPrefix(line, "redis_version:")
		}
		if strings.HasPrefix(line, "os:") {
			res.OS = strings.TrimPrefix(line, "os:")
		}
		if strings.HasPrefix(line, "redis_mode:") {
			res.Mode = strings.TrimPrefix(line, "redis_mode:")
		}
	}

	return res
}
