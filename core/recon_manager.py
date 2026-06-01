"""
core/recon_manager.py
─────────────────────
Gestor de Reconocimiento — Coordina los escaneos delegados a los agentes.
Se suscribe a eventos del Grafo Vivo para disparar escaneos automáticos.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from core.director import Director
from core.event_bus import Event, EventBus

log = logging.getLogger("argos.recon")

class ReconManager:
    """
    Orquesta las tareas de escaneo de los agentes.
    
    Flujo automático:
    1. Evento HOST_DISCOVERED se dispara.
    2. ReconManager comprueba si ya hemos escaneado este host.
    3. Si no, encola un comando 'port_scan' para el agente más cercano.
    """

    def __init__(self, director: Director, bus: EventBus) -> None:
        self.director = director
        self.bus = bus
        self._scanned_hosts: set[str] = set()

        # Suscribirse a eventos
        self.bus.subscribe(Event.HOST_DISCOVERED, self._on_host_discovered)
        self.bus.subscribe(Event.AGENT_REGISTERED, self._on_agent_registered)

        log.info("[ReconManager] Inicializado — listo para coordinar escaneos.")

    async def _on_host_discovered(self, data: Dict[str, Any]) -> None:
        """Cuando se descubre un nuevo host, iniciar escaneo si es necesario."""
        host_id = data.get("host_id")
        ip = data.get("ip")

        if not host_id or not ip:
            return

        if host_id in self._scanned_hosts:
            return

        # Marcar como escaneado para evitar bucles
        self._scanned_hosts.add(host_id)
        log.info(f"[ReconManager] Nuevo host descubierto: {ip}. Programando escaneo...")

        # Buscar el mejor agente para hacer el escaneo (idealmente en la misma subred)
        # Por ahora, cogemos el primer agente vivo.
        agent_id = self._get_best_agent()
        if not agent_id:
            log.warning("[ReconManager] No hay agentes disponibles para escanear.")
            return

        # Construir y enviar comando al agente
        cmd = {
            "type": "SCAN",
            "action": "port_scan",
            "params": {"target": ip, "ports": "top20"},
            "agent_id": agent_id,
        }

        await self._dispatch_scan(cmd)

    async def _on_agent_registered(self, data: Dict[str, Any]) -> None:
        """Cuando un agente se registra, ordenar que escanee su propia IP (localhost) 
        o la red local como punto de partida."""
        agent_id = data.get("agent_id")
        ip = data.get("ip")

        if not agent_id or not ip:
            return

        log.info(f"[ReconManager] Agente {agent_id[:8]} registrado. Solicitando auto-escaneo.")
        cmd = {
            "type": "SCAN",
            "action": "port_scan",
            "params": {"target": ip, "ports": "top20"},
            "agent_id": agent_id,
        }
        await self._dispatch_scan(cmd)

    def _get_best_agent(self) -> str | None:
        """Devuelve el ID del agente más adecuado para ejecutar el escaneo."""
        for aid, record in self.director.agents.items():
            if record.is_alive:
                return aid
        return None

    async def _dispatch_scan(self, cmd: dict) -> None:
        """Encola el comando de escaneo para que el Beacon stream lo entregue al agente."""
        agent_id = cmd["agent_id"]
        command = {
            "type":      "SCAN",
            "action":    "port_scan",
            "params":    {"target": cmd["params"]["target"], "ports": cmd["params"]["ports"]},
            "agent_id":  agent_id,
        }
        await self.director.queue_command(agent_id, command)
        log.debug(f"[ReconManager] Comando encolado para {agent_id[:8]} -> {cmd['params']['target']}")
