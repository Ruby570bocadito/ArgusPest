// agents/cell/recon/snmp.go
// SNMP detection — community string enumeration, system info extraction.

package recon

import (
	"fmt"
	"net"
	"time"
)

type SNMPResult struct {
	IP        string
	Community string
	SysDescr  string
	SysName   string
	Error     string
}

// Common SNMP community strings
var snmpCommunities = []string{"public", "private", "manager", "community", "admin", "cisco", "default"}

// SNMP GET request for sysDescr.0 (1.3.6.1.2.1.1.1.0)
var snmpGetSysDescr = []byte{
	0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
	0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
	0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06,
	0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
}

// FingerprintSNMP tries common community strings via UDP SNMP GET
func FingerprintSNMP(target string, port int) *SNMPResult {
	res := &SNMPResult{IP: target}
	addr := fmt.Sprintf("%s:%d", target, port)

	for _, community := range snmpCommunities {
		// Build SNMP GET request with this community
		req := buildSNMPGet(community, snmpGetSysDescr)

		conn, err := net.DialTimeout("udp", addr, 2*time.Second)
		if err != nil {
			res.Error = err.Error()
			return res
		}

		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(req); err != nil {
			conn.Close()
			continue
		}

		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			continue
		}

		// Check if response is valid SNMP
		if n > 2 && buf[0] == 0x30 {
			res.Community = community
			res.SysDescr = parseSNMPResponse(buf[:n])
			return res
		}
	}

	res.Error = "no valid SNMP community found"
	return res
}

func buildSNMPGet(community string, template []byte) []byte {
	// SNMP template structure:
	// 0x30, 0x26,           -- SEQUENCE, length (offset 1)
	// 0x02, 0x01, 0x01,     -- INTEGER version v1
	// 0x04, 0x06,           -- OCTET STRING, length (offset 6), value "public" (offset 7-12)
	// ... rest of packet
	commLen := len(community)
	origCommLen := 6 // "public"
	offsetDiff := commLen - origCommLen

	// Rebuild packet with correct lengths
	newLen := len(template) + offsetDiff
	payload := make([]byte, newLen)

	// Copy header up to community length field
	copy(payload, template[:7])
	// Update community string length
	payload[6] = byte(commLen)
	// Insert community string
	copy(payload[7:], community)
	// Copy rest of packet after original community
	copy(payload[7+commLen:], template[7+origCommLen:])

	// Update outer SEQUENCE length (offset 1)
	payload[1] = byte(newLen - 2)

	return payload
}

func parseSNMPResponse(data []byte) string {
	// Simplified OID extraction: look for OID marker 0x06 + length
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0x06 && data[i+1] == 0x08 &&
			data[i+2] == 0x2b && data[i+3] == 0x06 &&
			data[i+4] == 0x01 && data[i+5] == 0x02 {
			// Found sysDescr OID, value follows after 0x04 (octet string)
			for j := i + 6; j < len(data)-1; j++ {
				if data[j] == 0x04 {
					length := int(data[j+1])
					if j+2+length <= len(data) {
						return string(data[j+2 : j+2+length])
					}
				}
			}
		}
	}
	return ""
}
