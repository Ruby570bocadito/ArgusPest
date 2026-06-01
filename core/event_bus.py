"""
core/event_bus.py
─────────────────
Bus de Eventos interno — Pub/Sub asíncrono para comunicación entre componentes.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any, Callable, Coroutine, Dict, List, Optional

log = logging.getLogger("argos.event_bus")

# ─────────────────────────── EVENT TYPES ─────────────────────────

class Event:
    # Agentes
    AGENT_REGISTERED   = "agent.registered"
    AGENT_HEARTBEAT    = "agent.heartbeat"
    AGENT_LOST         = "agent.lost"
    AGENT_OWNED_HOST   = "agent.owned_host"

    # Descubrimiento
    HOST_DISCOVERED    = "host.discovered"
    SERVICE_DISCOVERED = "service.discovered"
    VULN_DISCOVERED    = "vuln.discovered"

    # Explotación
    EXPLOIT_SUCCESS    = "exploit.success"
    EXPLOIT_FAILED     = "exploit.failed"
    CRED_CAPTURED      = "cred.captured"
    FLAG_CAPTURED      = "flag.captured"

    # Defensa
    DEFENSE_DETECTED   = "defense.detected"
    GDS_UPDATED        = "gds.updated"
    KILL_SWITCH        = "kill_switch"

    # Director
    DECISION_CREATED   = "decision.created"
    DECISION_APPROVED  = "decision.approved"
    DECISION_REJECTED  = "decision.rejected"
    MISSION_STARTED    = "mission.started"
    MISSION_PAUSED     = "mission.paused"
    MISSION_STOPPED    = "mission.stopped"

    # Arsenal
    ARSENAL_BUILT      = "arsenal.built"
    MODULE_DEPLOYED    = "module.deployed"

    # CTF
    FLAG_SUBMITTED     = "flag.submitted"


Handler = Callable[..., Coroutine]


# ─────────────────────────── EVENT BUS ───────────────────────────

class EventBus:
    """
    Bus de eventos asíncrono (asyncio).
    Permite que cualquier componente publique y suscriba eventos
    sin acoplamientos directos entre módulos.

    Uso:
        bus = EventBus()

        @bus.on(Event.HOST_DISCOVERED)
        async def handle_host(data):
            print(f"Nuevo host: {data['ip']}")

        await bus.emit(Event.HOST_DISCOVERED, {"ip": "10.0.0.1"})
    """

    def __init__(self) -> None:
        self._handlers: Dict[str, List[Handler]] = defaultdict(list)
        self._history:  List[dict]               = []
        self._max_history = 1000
        log.info("[EventBus] Inicializado")

    # ─── SUBSCRIPTION ─────────────────────────────────────────────

    def on(self, event_type: str):
        """Decorador para suscribir un handler a un tipo de evento."""
        def decorator(fn: Handler) -> Handler:
            self.subscribe(event_type, fn)
            return fn
        return decorator

    def subscribe(self, event_type: str, handler: Handler) -> None:
        self._handlers[event_type].append(handler)
        log.debug(f"[EventBus] Suscrito: {event_type} → {handler.__name__}")

    def unsubscribe(self, event_type: str, handler: Handler) -> None:
        if handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)

    # ─── PUBLISH ──────────────────────────────────────────────────

    async def emit(self, event_type: str, data: Any = None) -> None:
        """Emite un evento y notifica a todos los suscriptores de forma asíncrona."""
        record = {"type": event_type, "data": data}
        self._history.append(record)
        if len(self._history) > self._max_history:
            self._history.pop(0)

        handlers = list(self._handlers.get(event_type, []))
        # Wildcard handlers
        handlers += list(self._handlers.get("*", []))

        if not handlers:
            log.debug(f"[EventBus] Sin handlers para: {event_type}")
            return

        tasks = []
        for handler in handlers:
            try:
                tasks.append(asyncio.create_task(handler(data)))
            except Exception as exc:
                log.error(f"[EventBus] Error al crear tarea {handler.__name__}: {exc}")

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    log.error(f"[EventBus] Handler error: {r}")

    def emit_sync(self, event_type: str, data: Any = None) -> None:
        """Versión síncrona para llamar desde código no-async."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.emit(event_type, data))
        except RuntimeError:
            # No hay loop corriendo — crear uno temporal
            try:
                asyncio.run(self.emit(event_type, data))
            except Exception as exc:
                log.error(f"[EventBus] emit_sync error: {exc}")
        except Exception as exc:
            log.error(f"[EventBus] emit_sync error: {exc}")

    # ─── QUERY ────────────────────────────────────────────────────

    def get_history(self, event_type: Optional[str] = None, limit: int = 50) -> list:
        if event_type:
            filtered = [e for e in self._history if e["type"] == event_type]
        else:
            filtered = self._history
        return filtered[-limit:]

    def handler_count(self, event_type: str) -> int:
        return len(self._handlers.get(event_type, []))


# ─────────────────────────── SINGLETON ───────────────────────────

_bus: Optional[EventBus] = None

def get_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus
