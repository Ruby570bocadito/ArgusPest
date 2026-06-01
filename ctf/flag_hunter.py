"""
ctf/flag_hunter.py
──────────────────
Flag Hunter — Búsqueda activa de flags en el sistema objetivo.
Soporta búsqueda por regex en disco, variables de entorno, memoria de procesos.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Callable, List, Optional

log = logging.getLogger("argos.flag_hunter")

# ─────────────────────────── COMMON FLAG FORMATS ─────────────────

DEFAULT_PATTERNS = [
    r"CTF\{[^}]+\}",               # CTF{...}
    r"FLAG\{[^}]+\}",              # FLAG{...}
    r"HTB\{[^}]+\}",               # HTB{...} — HackTheBox
    r"THM\{[^}]+\}",               # THM{...} — TryHackMe
    r"picoCTF\{[^}]+\}",           # picoCTF
    r"DUCTF\{[^}]+\}",             # DownUnderCTF
    r"flag\{[^}]+\}",              # lowercase
    r"flag\.[a-zA-Z0-9+/=]{20,}",  # flag.base64
    r"[0-9a-f]{32}",               # MD5-like (sin contexto, cuidado con FP)
]

# Directorios a buscar por defecto en Linux
DEFAULT_SEARCH_PATHS = [
    "/",
    "/root",
    "/home",
    "/var/www",
    "/opt",
    "/srv",
    "/tmp",
    "/etc",
]

# Directorios a buscar en Windows
DEFAULT_SEARCH_PATHS_WIN = [
    "C:\\Users",
    "C:\\inetpub",
    "C:\\xampp",
    "C:\\wamp",
    "C:\\flag",
    "C:\\",
]


class FlagHunter:
    """
    Busca flags en el sistema de archivos, variables de entorno y procesos.
    Diseñado para ejecutar dentro del agente en el host objetivo.
    """

    def __init__(
        self,
        patterns:        Optional[List[str]] = None,
        callback:        Optional[Callable]  = None,
        max_file_size:   int = 10 * 1024 * 1024,  # 10 MB
        search_paths:    Optional[List[str]] = None,
    ) -> None:
        self.patterns   = [re.compile(p, re.IGNORECASE) for p in (patterns or DEFAULT_PATTERNS)]
        self.callback   = callback or (lambda f, src: log.info(f"[FlagHunter] 🚩 {f} — {src}"))
        self.max_file_size = max_file_size
        self.found:     List[dict] = []
        is_win = os.name == "nt"
        self.search_paths = search_paths or (DEFAULT_SEARCH_PATHS_WIN if is_win else DEFAULT_SEARCH_PATHS)

    # ─── PUBLIC API ───────────────────────────────────────────────

    def hunt_all(self) -> List[dict]:
        """Lanza todos los métodos de búsqueda."""
        self.hunt_env_vars()
        self.hunt_filesystem()
        self.hunt_common_files()
        return self.found

    def hunt_env_vars(self) -> List[dict]:
        """Busca flags en variables de entorno."""
        for key, value in os.environ.items():
            matches = self._search_text(value)
            for flag in matches:
                self._register(flag, f"env:{key}")
        return self.found

    def hunt_filesystem(
        self,
        paths:      Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
    ) -> List[dict]:
        """Busca flags en el sistema de archivos."""
        target_paths = paths or self.search_paths
        target_exts  = set(extensions or [
            ".txt", ".log", ".md", ".json", ".xml", ".yaml", ".yml",
            ".html", ".php", ".py", ".sh", ".bat", ".ps1", ".cfg",
            ".conf", ".ini", ".env", ".key", ".pem", ".flag", "",
        ])

        for base in target_paths:
            base_path = Path(base)
            if not base_path.exists():
                continue
            try:
                self._walk_and_search(base_path, target_exts)
            except PermissionError:
                pass

        return self.found

    def hunt_common_files(self) -> List[dict]:
        """Busca en archivos/ubicaciones comunes de CTF."""
        common = [
            "/root/root.txt", "/root/flag.txt",
            "/home/user/user.txt", "/home/flag/flag.txt",
            "/var/www/html/flag.txt", "/flag.txt", "/flag",
            r"C:\Users\Administrator\Desktop\root.txt",
            r"C:\flag.txt", r"C:\Users\user\Desktop\flag.txt",
        ]
        for path in common:
            p = Path(path)
            try:
                if p.exists() and p.is_file():
                    content = p.read_text(encoding="utf-8", errors="ignore")
                    for flag in self._search_text(content):
                        self._register(flag, str(p))
                    # Si el contenido parece ser una flag completa
                    stripped = content.strip()
                    if 10 < len(stripped) < 200 and "\n" not in stripped:
                        self._register(stripped, str(p))
            except Exception:
                pass
        return self.found

    def search_string(self, text: str, source: str = "manual") -> List[str]:
        """Busca flags en un string dado."""
        found = self._search_text(text)
        for f in found:
            self._register(f, source)
        return found

    # ─── INTERNAL ─────────────────────────────────────────────────

    def _walk_and_search(self, base: Path, extensions: set) -> None:
        try:
            for item in base.rglob("*"):
                if item.is_file():
                    suffix = item.suffix.lower()
                    if suffix not in extensions:
                        continue
                    try:
                        if item.stat().st_size > self.max_file_size:
                            continue
                        content = item.read_text(encoding="utf-8", errors="ignore")
                        for flag in self._search_text(content):
                            self._register(flag, str(item))
                    except (PermissionError, OSError):
                        pass
        except (PermissionError, OSError):
            pass

    def _search_text(self, text: str) -> List[str]:
        found = []
        for pattern in self.patterns:
            for match in pattern.finditer(text):
                flag = match.group(0)
                if flag not in [f["value"] for f in self.found]:
                    found.append(flag)
        return found

    def _register(self, flag_value: str, source: str) -> None:
        # Evitar duplicados
        existing = [f["value"] for f in self.found]
        if flag_value in existing:
            return
        entry = {"value": flag_value, "source": source}
        self.found.append(entry)
        self.callback(flag_value, source)


# ─────────────────────────── AUTO SUBMITTER ──────────────────────

class AutoSubmitter:
    """
    Envío automático de flags a plataformas CTF.
    Soporta CTFd y plataformas compatibles.
    """

    def __init__(self, platform_url: str, api_token: str) -> None:
        self.platform_url = platform_url.rstrip("/")
        self.api_token    = api_token
        self.submitted:   List[str] = []

    async def submit(self, flag_value: str, challenge_id: Optional[int] = None) -> dict:
        """Envía una flag a la plataforma CTF."""
        try:
            import httpx
            headers = {
                "Authorization": f"Token {self.api_token}",
                "Content-Type":  "application/json",
            }
            payload = {"submission": flag_value}
            if challenge_id:
                payload["challenge_id"] = challenge_id

            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                resp = await client.post(
                    f"{self.platform_url}/api/v1/challenges/attempt",
                    json=payload, headers=headers,
                )
                result = resp.json()
                status = result.get("data", {}).get("status", "unknown")
                if status == "correct":
                    self.submitted.append(flag_value)
                    log.info(f"[AutoSubmitter] ✅ Flag CORRECTA: {flag_value}")
                else:
                    log.warning(f"[AutoSubmitter] ❌ Flag incorrecta: {flag_value} ({status})")
                return result
        except Exception as exc:
            log.error(f"[AutoSubmitter] Error al enviar flag: {exc}")
            return {"error": str(exc)}

    async def submit_all(self, flags: List[str]) -> List[dict]:
        results = []
        for flag in flags:
            if flag not in self.submitted:
                result = await self.submit(flag)
                results.append(result)
        return results
