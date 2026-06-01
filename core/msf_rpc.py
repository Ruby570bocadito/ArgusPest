"""
core/msf_rpc.py
───────────────
Metasploit RPC Client — Permite a Argos utilizar Metasploit como motor de explotación.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

log = logging.getLogger("argos.msf")

try:
    from pymetasploit3.msfrpc import MsfRpcClient
    MSF_AVAILABLE = True
except ImportError:
    MSF_AVAILABLE = False
    log.warning("[MSF] pymetasploit3 no instalado. Integración con Metasploit desactivada.")


class MetasploitIntegration:
    """
    Gestiona la conexión y ejecución de módulos contra una instancia de Metasploit.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 55553, password: str = "changeme", ssl: bool = False):
        self.host = host
        self.port = port
        self.password = password
        self.ssl = ssl
        self.client: Optional['MsfRpcClient'] = None
        self.connected = False

    def connect(self) -> bool:
        if not MSF_AVAILABLE:
            return False

        try:
            self.client = MsfRpcClient(
                self.password,
                server=self.host,
                port=self.port,
                ssl=self.ssl
            )
            self.connected = True
            log.info(f"[MSF] ✅ Conectado a Metasploit RPC en {self.host}:{self.port}")
            return True
        except Exception as exc:
            log.error(f"[MSF] ❌ Error conectando a Metasploit: {exc}")
            self.connected = False
            return False

    async def execute_exploit(self, module_name: str, payload_name: str, options: Dict[str, Any]) -> dict:
        """
        Ejecuta un módulo de Metasploit asíncronamente.
        Retorna el estado de la sesión si tiene éxito.
        """
        if not self.connected:
            return {"success": False, "error": "No conectado a MSF"}

        log.info(f"[MSF] Preparando exploit: {module_name} con payload: {payload_name}")

        try:
            # Obtener el módulo
            exploit = self.client.modules.use('exploit', module_name)

            # Configurar opciones
            for key, value in options.items():
                if key in exploit.options:
                    exploit[key] = value

            # Configurar payload si es necesario (ej. windows/meterpreter/reverse_tcp)
            if payload_name:
                payload = self.client.modules.use('payload', payload_name)
                # Configurar LHOST/LPORT si existen en las opciones generales
                if 'LHOST' in options and 'LHOST' in payload.options:
                    payload['LHOST'] = options['LHOST']
                if 'LPORT' in options and 'LPORT' in payload.options:
                    payload['LPORT'] = options['LPORT']

                # Ejecutar
                job = exploit.execute(payload=payload)
            else:
                job = exploit.execute()

            job_id = job.get('job_id')
            if job_id is None:
                return {"success": False, "error": "Fallo al iniciar el Job en MSF"}

            log.info(f"[MSF] Exploit lanzado (Job ID: {job_id}). Esperando sesión...")

            # Bucle asíncrono para esperar la sesión (timeout 60s)
            for _ in range(30):
                await asyncio.sleep(2)
                sessions = self.client.sessions.list

                # Comprobar si hay una sesión nueva vinculada a nuestro target
                for sid, sinfo in sessions.items():
                    if sinfo.get('target_host') == options.get('RHOSTS'):
                        log.info(f"[MSF] ✅ ¡Sesión {sid} obtenida en {options['RHOSTS']}!")
                        return {
                            "success": True,
                            "session_id": sid,
                            "type": sinfo.get('type'),
                            "info": sinfo.get('info')
                        }

            return {"success": False, "error": "Timeout esperando sesión de MSF"}

        except Exception as exc:
            log.error(f"[MSF] Error ejecutando {module_name}: {exc}")
            return {"success": False, "error": str(exc)}
