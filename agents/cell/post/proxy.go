package post

import (
	"fmt"
	"io"
	"log"
	"net"
)

// ProxySOCKS5 implementa un servidor SOCKS5 básico para pivoteo de red
func ProxySOCKS5(port int) error {
	address := fmt.Sprintf("0.0.0.0:%d", port)
	server, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("error iniciando proxy SOCKS5 en %s: %v", address, err)
	}

	log.Printf("[SOCKS5] Escuchando en %s", address)

	go func() {
		for {
			client, err := server.Accept()
			if err != nil {
				log.Printf("[SOCKS5] Error aceptando conexion: %v", err)
				continue
			}
			go handleSOCKS5Client(client)
		}
	}()

	return nil
}

func handleSOCKS5Client(client net.Conn) {
	defer client.Close()

	// 1. Handshake SOCKS5
	buf := make([]byte, 256)
	_, err := client.Read(buf)
	if err != nil || buf[0] != 0x05 {
		return // Solo soportamos SOCKS5
	}

	// Responder handshake (No auth required)
	client.Write([]byte{0x05, 0x00})

	// 2. Request details
	n, err := client.Read(buf)
	if err != nil || n < 7 {
		return
	}

	cmd := buf[1]
	if cmd != 0x01 {
		// Solo soportamos CONNECT
		return
	}

	addrType := buf[3]
	var destAddr string

	switch addrType {
	case 0x01: // IPv4
		destAddr = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
	case 0x03: // FQDN
		fqdnLen := int(buf[4])
		destAddr = string(buf[5 : 5+fqdnLen])
	default:
		return // IPv6 no implementado por simplicidad
	}

	destPort := (int(buf[n-2]) << 8) | int(buf[n-1])
	target := fmt.Sprintf("%s:%d", destAddr, destPort)

	// 3. Conectar al destino real
	dest, err := net.Dial("tcp", target)
	if err != nil {
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Connection refused
		return
	}
	defer dest.Close()

	// Responder Connection Granted
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// 4. Copiar los streams
	go io.Copy(dest, client)
	io.Copy(client, dest)
}
