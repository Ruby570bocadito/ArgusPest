// agents/cell/recon/fingerprint.go
// Central fingerprint dispatcher — routes ports to appropriate fingerprint modules.

package recon

import (
	"fmt"
	"strings"
)

// ServiceFingerprint holds the enriched service information from fingerprinting
type ServiceFingerprint struct {
	Port     int
	Protocol string
	Name     string
	Version  string
	Banner   string
	Details  map[string]string // Extra info (OS, auth plugin, tech stack, etc.)
}

// FingerprintService dispatches to the correct fingerprint module based on port/service
func FingerprintService(target string, port int, serviceName string) *ServiceFingerprint {
	sf := &ServiceFingerprint{
		Port:     port,
		Protocol: "tcp",
		Name:     serviceName,
		Details:  make(map[string]string),
	}

	svc := strings.ToLower(serviceName)

	switch {
	case svc == "http" || svc == "https" || port == 80 || port == 443 || port == 8080 || port == 8443:
		r := FingerprintHTTP(target, port, port == 443 || port == 8443)
		if r.Error == "" {
			sf.Version = r.Server
			sf.Banner = r.Title
			sf.Details["status_code"] = fmt.Sprintf("%d", r.StatusCode)
			sf.Details["x_powered_by"] = r.XPoweredBy
			sf.Details["technologies"] = strings.Join(r.Technologies, ",")
			if r.WWWAuth != "" {
				sf.Details["auth"] = r.WWWAuth
			}
		}

	case svc == "ssh" || svc == "openssh" || port == 22 || port == 2222:
		r := FingerprintSSH(target, port)
		if r.Error == "" {
			sf.Banner = r.Banner
			sf.Name = fmt.Sprintf("%s_%s", r.Software, strings.ReplaceAll(r.Version, ".", "_"))
			if r.OS != "" {
				sf.Details["os"] = r.OS
			}
		}

	case svc == "mysql" || svc == "mariadb" || port == 3306:
		r := FingerprintMySQL(target, port)
		if r.Error == "" {
			sf.Version = r.Version
			if r.AuthPlugin != "" {
				sf.Details["auth_plugin"] = r.AuthPlugin
			}
		}

	case svc == "ftp" || svc == "vsftpd" || svc == "proftpd" || port == 21:
		r := FingerprintFTP(target, port)
		if r.Error == "" {
			sf.Banner = r.Banner
			sf.Name = r.Software + " FTP"
			sf.Version = r.Version
			if r.Anonymous {
				sf.Details["anonymous"] = "true"
			}
		}

	case svc == "rdp" || port == 3389:
		r := FingerprintRDP(target, port)
		if r.Error == "" {
			sf.Name = "rdp"
			if r.NLA {
				sf.Details["nla"] = "true"
			}
			if r.OS != "" {
				sf.Details["os"] = r.OS
			}
		}

	case svc == "redis" || port == 6379:
		r := FingerprintRedis(target, port)
		if r.Error == "" {
			sf.Version = r.Version
			if r.NoAuth {
				sf.Details["no_auth"] = "true"
			}
			if r.OS != "" {
				sf.Details["os"] = r.OS
			}
			if r.Mode != "" {
				sf.Details["mode"] = r.Mode
			}
		}

	case svc == "snmp" || port == 161 || port == 162:
		r := FingerprintSNMP(target, port)
		if r.Error == "" {
			sf.Details["community"] = r.Community
			sf.Banner = r.SysDescr
		}

	case port == 445: // SMB — already handled via smb.go, integrate here
		smb := CheckSMB(target, 2000)
		if smb.IsOpen {
			sf.Name = "smb"
			sf.Version = smb.OSVersion
			sf.Banner = smb.OSVersion
			if smb.OSVersion != "" {
				sf.Details["os"] = smb.OSVersion
			}
		}
	}

	return sf
}
