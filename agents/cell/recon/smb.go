// agents/cell/recon/smb.go
// ──────────────────────────
// Enumeración básica de SMB (puerto 445).

package recon

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

type SMBResult struct {
	IP             string
	IsOpen         bool
	OSVersion      string
	NullSession    bool
	Error          string
}

// CheckSMB realiza un chequeo básico del puerto 445 y opcionalmente
// envía un paquete de negociación SMBv1/v2 para obtener la firma del OS.
func CheckSMB(ip string, timeoutMs int) SMBResult {
	res := SMBResult{IP: ip, IsOpen: false}
	target := fmt.Sprintf("%s:445", ip)
	
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	res.IsOpen = true

	// Intentar Negotiate Protocol Request (SMB1/SMB2)
	// Esto es un payload crudo muy simplificado para trigger de respuesta.
	negotiatePayload := []byte{
		0x00, 0x00, 0x00, 0x54, // NetBIOS Session Service (Length: 84)
		0xff, 0x53, 0x4d, 0x42, // SMB Header: \xffSMB
		0x72, 0x00, 0x00, 0x00, // Command: Negotiate Protocol (0x72)
		0x00, 0x18, 0x01, 0x28, // Status, Flags, Flags2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Tree ID, Process ID
		0x00, 0x00, 0x00, 0x00, // User ID, Multiplex ID
		0x00, 0x31, 0x00,       // Word Count, Byte Count (49)
		0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, // LANMAN1.0
		0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, // LM1.2X002
		0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30, 0x00, // NT LANMAN 1.0
		0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, // NT LM 0.12
	}

	conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
	_, err = conn.Write(negotiatePayload)
	if err != nil {
		res.Error = "write error: " + err.Error()
		return res
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil || n < 4 {
		res.Error = "read error"
		return res
	}

	// Analizar respuesta básica (solo extraer si responde con \xffSMB)
	if bytes.Contains(resp, []byte{0xff, 0x53, 0x4d, 0x42}) {
		// La respuesta a un Negotiate de NT LM 0.12 contiene el Security Blob.
		// Extraer el OS banner es complejo sin una librería completa de SMB (como go-smb2),
		// por lo que aquí marcaremos que el servicio responde activamente.
		res.OSVersion = "Windows (SMB Service Active)"
	} else if bytes.Contains(resp, []byte{0xfe, 0x53, 0x4d, 0x42}) {
		res.OSVersion = "Windows (SMB2/3 Active)"
	}

	// Comprobación rápida de sesión nula (simulada)
	// En un caso real, haríamos un Session Setup Request con null credentials.
	res.NullSession = checkNullSession(conn)

	return res
}

func checkNullSession(conn net.Conn) bool {
	// Stub para comprobación de sesión nula.
	// En fase de desarrollo, si el servicio SMB está activo, no asumimos null session
	// a menos que podamos enviar el payload exacto de NTLMSSP.
	return false
}

// ConvertToPortScan formattea el resultado para unirlo al scan principal
func (r *SMBResult) MergeInto(sr *ScanResult) {
	if r.IsOpen {
		found := false
		for _, p := range sr.OpenPorts {
			if p == 445 {
				found = true
				break
			}
		}
		if !found {
			sr.OpenPorts = append(sr.OpenPorts, 445)
		}
		if r.OSVersion != "" {
			sr.Services[445] = "smb (" + r.OSVersion + ")"
		} else {
			sr.Services[445] = "smb"
		}
	}
}
