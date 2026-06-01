// agents/cell/recon/scanner.go
// ────────────────────────────
// Motor de escaneo de puertos concurrente en Go.

package recon

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ScanResult representa el resultado del escaneo de un único host
type ScanResult struct {
	IP          string
	OpenPorts   []int
	Services    map[int]string           // port -> service name
	Fingerprints map[int]*ServiceFingerprint // port -> enriched service info (deep scan)
}

// PortScanner realiza escaneos de puertos TCP
type PortScanner struct {
	Timeout     time.Duration
	Concurrency int
}

func NewPortScanner(timeoutMs int, concurrency int) *PortScanner {
	if concurrency <= 0 {
		concurrency = 100 // default
	}
	if timeoutMs <= 0 {
		timeoutMs = 500 // default 500ms per port
	}
	return &PortScanner{
		Timeout:     time.Duration(timeoutMs) * time.Millisecond,
		Concurrency: concurrency,
	}
}

// ScanPorts escanea una lista de puertos en una IP objetivo
func (ps *PortScanner) ScanPorts(ip string, ports []int) ScanResult {
	result := ScanResult{
		IP:       ip,
		OpenPorts: make([]int, 0),
		Services:  make(map[int]string),
	}

	var wg sync.WaitGroup
	portChan := make(chan int, len(ports))
	resultChan := make(chan int, len(ports))

	// Iniciar workers
	for i := 0; i < ps.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				target := fmt.Sprintf("%s:%d", ip, port)
				conn, err := net.DialTimeout("tcp", target, ps.Timeout)
				if err == nil {
					conn.Close()
					resultChan <- port
				}
			}
		}()
	}

	// Enviar puertos a los workers
	go func() {
		for _, port := range ports {
			portChan <- port
		}
		close(portChan)
	}()

	// Esperar en un goroutine separado para cerrar el canal de resultados
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Recolectar resultados
	for port := range resultChan {
		result.OpenPorts = append(result.OpenPorts, port)
		result.Services[port] = ps.guessService(port)
	}

	return result
}

// guessService devuelve un nombre de servicio probable basado en el puerto
func (ps *PortScanner) guessService(port int) string {
	commonPorts := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		88:   "kerberos",
		110:  "pop3",
		135:  "msrpc",
		139:  "netbios-ssn",
		143:  "imap",
		389:  "ldap",
		443:  "https",
		445:  "smb",
		1433: "mssql",
		1521: "oracle",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		5900: "vnc",
		6379: "redis",
		8080: "http-proxy",
		8443: "https-alt",
	}

	if name, ok := commonPorts[port]; ok {
		return name
	}
	return "unknown"
}

// GetTopPorts devuelve una lista de los puertos más comunes para escanear
func GetTopPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 161, 389, 443, 445,
		873, 993, 995, 1433, 1521, 2222, 3306, 3389, 5432, 5900, 5985, 5986,
		6379, 8080, 8443, 8888, 9090, 27017,
	}
}

// DeepScan performs banner grabbing and service fingerprinting on all open ports.
func (ps *PortScanner) DeepScan(result *ScanResult) {
	if result.Fingerprints == nil {
		result.Fingerprints = make(map[int]*ServiceFingerprint)
	}
	for _, port := range result.OpenPorts {
		svcName := result.Services[port]
		if svcName == "" || svcName == "unknown" {
			svcName = ps.guessService(port)
		}
		fp := FingerprintService(result.IP, port, svcName)
		result.Fingerprints[port] = fp
		// Update service name with fingerprinted version
		if fp.Version != "" {
			result.Services[port] = fp.Name + " " + fp.Version
		}
	}
}
