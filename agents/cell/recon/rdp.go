// agents/cell/recon/rdp.go
// RDP detection — version, NLA status, OS hint.

package recon

import (
	"fmt"
	"net"
	"time"
)

type RDPResult struct {
	IP       string
	NLA      bool
	OS       string
	Error    string
}

// RDP negotiation request (packet from xrdp/nmap)
var rdpNegotiateRequest = []byte{
	0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
	0x00, 0x00, 0x00,
}

// FingerprintRDP connects to RDP port and parses Negotiate Response
func FingerprintRDP(target string, port int) *RDPResult {
	res := &RDPResult{IP: target}
	addr := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Send RDP Negotiation Request (TPKT + COTP + RDP NEG_REQ)
	if _, err := conn.Write(rdpNegotiateRequest); err != nil {
		res.Error = fmt.Sprintf("write: %v", err)
		return res
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		res.Error = fmt.Sprintf("read: %v", err)
		return res
	}

	// Parse Negotiation Response
	data := buf[:n]
	if len(data) >= 8 {
		res.NLA = parseRDPNegotiation(data)
		res.OS = parseRDPOS(data)
	}

	return res
}

func parseRDPNegotiation(data []byte) bool {
	// Look for RDP Negotiation Response type
	// TYPE_RDP_NEG_RSP = 0x02
	// Selected Protocol: 0 = RDP, 1 = SSL, 2 = NLA (CredSSP)
	for i := 0; i < len(data)-3; i++ {
		if data[i] == 0x02 && data[i+1] == 0x00 && data[i+2] == 0x00 && data[i+3] == 0x00 {
			if i+8 < len(data) {
				// protocol octet is at fixed offset after NEG_RSP
				prot := data[i+7]
				return prot == 2 // NLA = CredSSP
			}
		}
	}
	return false
}

func parseRDPOS(data []byte) string {
	// Simplified: most RDP servers include OS info in the SSL cert CN
	// which requires SSL handshake. Skip for now, return basic detection.
	return "Windows (RDP detected)"
}
