"""
core/director.py
────────────────
Director — Orquestador central de Argos.
Gestiona misiones, agentes, decisiones y el bucle de eventos principal.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.cbr import CaseBasedReasoner, seed_default_cases
from core.decision_fusion import Decision, DecisionFusion
from core.event_bus import Event, EventBus, get_bus
from core.knowledge_tree import (
    CredentialNode,
    DefenseNode,
    FlagNode,
    HostNode,
    KnowledgeTree,
    ServiceNode,
)
from core.planner import AStarPlanner
from core.rules_engine import RulesEngine

log = logging.getLogger("argos.director")


# ─────────────────────────── MISSION CONFIG ──────────────────────

@dataclass
class MissionConfig:
    target:      str = "10.0.0.0/24"
    goal:        str = "domain_admin"    # domain_admin | flag:CTF{*} | host:<ip> | exfil:<path>
    profile:     str = "balanced"        # ghost | balanced | blitz
    mode:        str = "pentest"         # pentest | ctf
    parallel:    int = 3                 # max agentes simultáneos
    use_msf:     bool = False
    auto_decide: bool = False            # no preguntar nunca
    output_dir:  str  = "./missions"
    mission_id:  str  = field(default_factory=lambda: str(uuid.uuid4())[:8])
    started_at:  str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─────────────────────────── AGENT REGISTRY ──────────────────────

@dataclass
class AgentRecord:
    agent_id:   str
    hostname:   str
    ip:         str
    os:         str
    arch:       str
    registered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen:  str = ""
    is_alive:   bool = True
    host_id:    Optional[str] = None
    profile:    str = "balanced"


# ─────────────────────────── DECISION QUEUE ──────────────────────

@dataclass
class PendingDecision:
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    agent_id:    str = ""
    host_id:     str = ""
    decision:    Optional[Decision] = None
    created_at:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved:    bool = False
    approved:    Optional[bool] = None
    custom_cmd:  Optional[str] = None


# ─────────────────────────── DIRECTOR ────────────────────────────

class Director:
    """
    Orquestador central de Argos.

    Responsabilidades:
    - Mantener el estado de la misión activa.
    - Gestionar el registro y ciclo de vida de los agentes.
    - Procesar los eventos entrantes (findings) y actualizar el Grafo Vivo.
    - Invocar el Motor de Decisión para cada nuevo hallazgo.
    - Gestionar la cola de decisiones pendientes (Human-in-the-Loop).
    - Despachar comandos a los agentes.
    """

    def __init__(
        self,
        config: MissionConfig,
        bus:    Optional[EventBus] = None,
    ) -> None:
        self.config  = config
        self.bus     = bus or get_bus()

        # Core components
        self.kt      = KnowledgeTree()
        self.cbr     = CaseBasedReasoner(db_path=f"{config.output_dir}/qdrant")
        self.planner = AStarPlanner(self.kt)
        self.rules   = RulesEngine()
        self.fusion  = DecisionFusion(self.planner, self.cbr, self.rules)

        # State
        self.agents:    Dict[str, AgentRecord]    = {}
        self.decisions: Dict[str, PendingDecision] = {}
        self.running:   bool = False
        self._cmd_queue: asyncio.Queue = asyncio.Queue()
        self._pending_commands: Dict[str, asyncio.Queue] = {}  # cola de comandos por agent_id

        # Recon Manager (Fase 2)
        from core.recon_manager import ReconManager
        self.recon_manager = ReconManager(self, self.bus)

        # Exploit Manager (Fase 3)
        from core.exploit_manager import ExploitManager
        self.exploit_manager = ExploitManager(self, self.bus)

        # Seed CBR with default knowledge — solo si la colección está vacía,
        # para no duplicar casos al re-instanciar el Director sobre el mismo output_dir.
        cbr_stats = self.cbr.stats()
        if cbr_stats.get("enabled") and cbr_stats.get("total_cases", 0) == 0:
            seed_default_cases(self.cbr)

        # Register GDS kill-switch listener
        self.kt.gds.register_listener(self._on_kill_switch)

        # Subscribe to internal events
        self._register_handlers()

        log.info(
            f"[Director] 🚀 Inicializado — Misión: {config.mission_id} | "
            f"Target: {config.target} | Goal: {config.goal} | Profile: {config.profile}"
        )

    # ─── LIFECYCLE ────────────────────────────────────────────────

    async def start(self) -> None:
        """Arranca el bucle principal del director."""
        self.running = True
        # Initialize MSF connection now that event loop is running
        await self.exploit_manager.ensure_msf_connected()
        await self.bus.emit(Event.MISSION_STARTED, {
            "mission_id": self.config.mission_id,
            "target":     self.config.target,
            "goal":       self.config.goal,
            "profile":    self.config.profile,
        })
        log.info(f"[Director] ▶️  Misión {self.config.mission_id} INICIADA")

        # Bucle principal: procesa comandos de la cola
        while self.running:
            try:
                coro = await asyncio.wait_for(self._cmd_queue.get(), timeout=1.0)
                await coro
            except asyncio.TimeoutError:
                await self._maintenance_tick()
            except Exception as exc:
                log.error(f"[Director] Error en bucle principal: {exc}", exc_info=True)

    async def pause(self) -> None:
        self.running = False
        await self.bus.emit(Event.MISSION_PAUSED, {"mission_id": self.config.mission_id})
        log.info("[Director] ⏸  Misión PAUSADA")

    async def stop(self) -> None:
        self.running = False
        await self.bus.emit(Event.MISSION_STOPPED, {"mission_id": self.config.mission_id})
        log.info("[Director] ⏹  Misión DETENIDA")

    # ─── COMMAND PIPELINE ──────────────────────────────────────────

    async def queue_command(self, agent_id: str, command: dict) -> None:
        """Encola un comando para que el Beacon stream lo entregue al agente."""
        if agent_id not in self._pending_commands:
            self._pending_commands[agent_id] = asyncio.Queue(maxsize=20)
        try:
            self._pending_commands[agent_id].put_nowait(command)
            log.debug(f"[Director] Comando encolado para {agent_id[:8]}: {command.get('action', command.get('type', '?'))}")
        except asyncio.QueueFull:
            log.warning(f"[Director] Cola llena para {agent_id[:8]}, comando descartado")

    async def get_pending_command(self, agent_id: str) -> Optional[dict]:
        """El Beacon stream llama esto para obtener el siguiente comando (no bloqueante)."""
        q = self._pending_commands.get(agent_id)
        if not q:
            return None
        try:
            return await asyncio.wait_for(q.get(), timeout=0.5)
        except asyncio.TimeoutError:
            return None

    # ─── AGENT MANAGEMENT ─────────────────────────────────────────

    async def register_agent(self, info: dict) -> dict:
        """
        Registra un agente y crea/actualiza el nodo host en el Grafo Vivo.
        Devuelve RegisterAck data.
        """
        agent_id = info.get("agent_id") or str(uuid.uuid4())
        ip       = info.get("ip", "0.0.0.0")

        host = HostNode(
            ip        = ip,
            hostname  = info.get("hostname"),
            os        = info.get("os"),
            arch      = info.get("arch"),
            agent_id  = agent_id,
        )
        host_id = self.kt.add_host(host)

        record = AgentRecord(
            agent_id  = agent_id,
            hostname  = info.get("hostname", "unknown"),
            ip        = ip,
            os        = info.get("os", "unknown"),
            arch      = info.get("arch", "unknown"),
            host_id   = host_id,
            profile   = self.config.profile,
        )
        self.agents[agent_id] = record

        await self.bus.emit(Event.AGENT_REGISTERED, {
            "agent_id": agent_id, "ip": ip, "host_id": host_id
        })
        log.info(f"[Director] 🤖 Agente registrado: {agent_id[:8]} @ {ip}")

        return {
            "success":            True,
            "beacon_interval_sec": self._beacon_interval(),
            "mission_id":         self.config.mission_id,
            "director_version":   "2.0.0",
            "profile":            self.config.profile,
        }

    async def process_heartbeat(self, agent_id: str, data: dict) -> None:
        if agent_id in self.agents:
            self.agents[agent_id].last_seen = datetime.now(timezone.utc).isoformat()
            self.agents[agent_id].is_alive  = True
        await self.bus.emit(Event.AGENT_HEARTBEAT, {"agent_id": agent_id, **data})

    # ─── FINDING PROCESSING ───────────────────────────────────────

    async def process_finding(self, agent_id: str, finding: dict) -> Optional[dict]:
        """
        Procesa un hallazgo de un agente:
        1. Actualiza el Grafo Vivo
        2. Invoca el Motor de Decisión
        3. Encola la decisión (o la ejecuta si auto_decide)
        Retorna el comando a ejecutar (o None si espera aprobación).
        """
        ftype = finding.get("type", "")
        agent_record = self.agents.get(agent_id)
        host_id = agent_record.host_id if agent_record else None

        if ftype == "HOST_DISCOVERED":
            await self._handle_host_discovered(finding, agent_id)

        elif ftype == "SERVICE_OPEN":
            svc_node = await self._handle_service_discovered(finding, host_id)
            if svc_node:
                return await self._decide_next_action(agent_id, host_id, finding)

        elif ftype == "CREDENTIAL":
            await self._handle_credential(finding, host_id)

        elif ftype == "FLAG":
            await self._handle_flag(finding, host_id)

        elif ftype == "DEFENSE_DETECTED":
            await self._handle_defense(finding, host_id)

        elif ftype == "EXPLOIT_SUCCESS":
            await self._handle_exploit_success(finding, agent_id, host_id)

        return None

    # ─── DECISION MANAGEMENT ──────────────────────────────────────

    async def _decide_next_action(
        self, agent_id: str, host_id: str, context: dict
    ) -> Optional[dict]:
        """Invoca el motor de decisión y gestiona la aprobación."""
        host  = self.kt.get_all_hosts()
        host_node = next((h for h in host if h.id == host_id), None)

        service = {
            "name":    context.get("service_name", "unknown"),
            "port":    context.get("port", 0),
            "version": context.get("version", ""),
            "banner":  context.get("banner", ""),
        }

        # Nivel de defensa basado en GDS
        gds_score = self.kt.gds.score
        if gds_score < 0.3:
            defense_level = "none"
        elif gds_score < 0.5:
            defense_level = "low"
        elif gds_score < 0.7:
            defense_level = "medium"
        else:
            defense_level = "high"

        decision = self.fusion.fuse(
            service        = service,
            source_host_id = host_id,
            goal           = self.config.goal,
            profile        = self.config.profile,
            defense_level  = defense_level,
            os_type        = host_node.os if host_node else "unknown",
            owned          = host_node.owned if host_node else False,
        )

        await self.bus.emit(Event.DECISION_CREATED, {
            "agent_id":  agent_id,
            "host_id":   host_id,
            "decision":  decision.to_dict(),
        })

        # Auto-decide o Human-in-the-Loop
        if self.config.auto_decide and not decision.needs_approval:
            log.info(f"[Director] ⚡ Auto-ejecutando: '{decision.action}'")
            await self.bus.emit(Event.DECISION_APPROVED, {"decision": decision.to_dict()})
            return self._build_command(decision, agent_id)

        # Encolar para aprobación humana
        pending = PendingDecision(
            agent_id = agent_id,
            host_id  = host_id,
            decision = decision,
        )
        self.decisions[pending.decision_id] = pending
        log.info(
            f"[Director] 🔔 Decisión encolada [{pending.decision_id}]: "
            f"'{decision.action}' conf={decision.confidence:.2%}"
        )
        return None   # El CLI/TUI mostrará la cola al operador

    async def approve_decision(self, decision_id: str, custom_cmd: Optional[str] = None) -> Optional[dict]:
        """Aprueba una decisión pendiente y retorna el comando a ejecutar."""
        pending = self.decisions.get(decision_id)
        if not pending or pending.resolved:
            log.warning(f"[Director] Decisión {decision_id} no encontrada o ya resuelta")
            return None

        pending.resolved = True
        pending.approved = True
        pending.custom_cmd = custom_cmd

        await self.bus.emit(Event.DECISION_APPROVED, {
            "decision_id": decision_id,
            "custom_cmd":  custom_cmd,
        })

        if custom_cmd:
            return {"type": "MANUAL", "command": custom_cmd, "agent_id": pending.agent_id}

        return self._build_command(pending.decision, pending.agent_id)

    async def reject_decision(self, decision_id: str) -> None:
        """Rechaza una decisión pendiente."""
        pending = self.decisions.get(decision_id)
        if pending:
            pending.resolved = True
            pending.approved = False
            await self.bus.emit(Event.DECISION_REJECTED, {"decision_id": decision_id})
            log.info(f"[Director] ❌ Decisión {decision_id} RECHAZADA")

    def list_pending_decisions(self) -> List[dict]:
        return [
            {
                "decision_id": did,
                "agent_id":    p.agent_id,
                "action":      p.decision.action if p.decision else "?",
                "confidence":  p.decision.confidence if p.decision else 0.0,
                "explanation": p.decision.explanation if p.decision else "",
                "created_at":  p.created_at,
            }
            for did, p in self.decisions.items()
            if not p.resolved
        ]

    # ─── INTERNAL HANDLERS ────────────────────────────────────────

    async def _handle_host_discovered(self, finding: dict, agent_id: str) -> str:
        host = HostNode(
            ip       = finding.get("ip", "0.0.0.0"),
            hostname = finding.get("hostname"),
            os       = finding.get("os"),
        )
        host_id = self.kt.add_host(host)
        await self.bus.emit(Event.HOST_DISCOVERED, {"ip": host.ip, "host_id": host_id})
        return host_id

    async def _handle_service_discovered(self, finding: dict, host_id: str) -> Optional[ServiceNode]:
        if not host_id:
            return None
        svc = ServiceNode(
            host_id      = host_id,
            port         = finding.get("port", 0),
            protocol     = finding.get("protocol", "tcp"),
            service_name = finding.get("service_name", "unknown"),
            banner       = finding.get("banner"),
            version      = finding.get("version"),
        )
        self.kt.add_service(svc)
        await self.bus.emit(Event.SERVICE_DISCOVERED, {
            "host_id": host_id,
            "port":    svc.port,
            "service": svc.service_name,
        })
        return svc

    async def _handle_credential(self, finding: dict, host_id: str) -> None:
        cred = CredentialNode(
            username       = finding.get("username", ""),
            type           = finding.get("cred_type", "password"),
            value          = finding.get("value", ""),
            scope          = finding.get("scope", "local"),
            source_host_id = host_id,
        )
        self.kt.add_credential(cred)
        await self.bus.emit(Event.CRED_CAPTURED, {"username": cred.username, "type": cred.type})

    async def _handle_flag(self, finding: dict, host_id: str) -> None:
        flag = FlagNode(
            value   = finding.get("flag_value", ""),
            host_id = host_id or "",
            path    = finding.get("path"),
        )
        self.kt.add_flag(flag)
        await self.bus.emit(Event.FLAG_CAPTURED, {"value": flag.value})
        log.info(f"[Director] 🚩 FLAG CAPTURADA: {flag.value}")

    async def _handle_defense(self, finding: dict, host_id: str) -> None:
        defense = DefenseNode(
            host_id        = host_id or "",
            type           = finding.get("defense_type", "edr"),
            name           = finding.get("defense_name", "unknown"),
            aggressiveness = finding.get("severity", 0.5),
        )
        self.kt.add_defense(defense)
        await self.bus.emit(Event.DEFENSE_DETECTED, {
            "type": defense.type,
            "name": defense.name,
            "gds":  self.kt.gds.to_dict(),
        })

    async def _handle_exploit_success(self, finding: dict, agent_id: str, host_id: str) -> None:
        if host_id:
            session_id = finding.get("session_id", str(uuid.uuid4())[:8])
            self.kt.mark_owned(host_id, session_id, agent_id)
            await self.bus.emit(Event.AGENT_OWNED_HOST, {
                "agent_id": agent_id, "host_id": host_id, "session_id": session_id
            })
            # Guardar caso en CBR
            self.cbr.add_case(
                description = finding.get("context_description", finding.get("technique", "")),
                action      = finding.get("technique", "unknown"),
                success     = True,
                context     = {"agent_id": agent_id, "host_id": host_id},
            )

    # ─── KILL SWITCH ──────────────────────────────────────────────

    def _on_kill_switch(self, event: str) -> None:
        log.critical("[Director] 🔴 KILL SWITCH — Hibernando todos los agentes")
        self.bus.emit_sync(Event.KILL_SWITCH, {"reason": "GDS critical"})

    # ─── MAINTENANCE ──────────────────────────────────────────────

    async def _maintenance_tick(self) -> None:
        """Tareas de mantenimiento periódicas (cada segundo)."""
        # Decaimiento natural del GDS
        self.kt.gds.decay()

    # ─── HELPERS ──────────────────────────────────────────────────

    def _beacon_interval(self) -> int:
        return {"ghost": 120, "balanced": 60, "blitz": 15}.get(self.config.profile, 60)

    @staticmethod
    def _build_command(decision: Optional[Decision], agent_id: str) -> dict:
        if not decision:
            return {}
        return {
            "type":     "EXPLOIT",
            "action":   decision.action,
            "params":   decision.params,
            "agent_id": agent_id,
            "mitre_id": decision.mitre_id,
        }

    def _register_handlers(self) -> None:
        """Registra handlers internos en el bus de eventos."""
        @self.bus.on(Event.KILL_SWITCH)
        async def _on_kill(data):
            self.config.auto_decide = False
            log.critical("[Director] Auto-decide DESACTIVADO por Kill Switch")

    # ─── STATUS ───────────────────────────────────────────────────

    def status(self) -> dict:
        stats = self.kt.stats()
        return {
            "mission_id":       self.config.mission_id,
            "running":          self.running,
            "target":           self.config.target,
            "goal":             self.config.goal,
            "profile":          self.config.profile,
            "mode":             self.config.mode,
            "gds":              self.kt.gds.to_dict(),
            "agents_alive":     sum(1 for a in self.agents.values() if a.is_alive),
            "agents_total":     len(self.agents),
            "pending_decisions":len(self.list_pending_decisions()),
            "graph_stats":      stats,
            "cbr_stats":        self.cbr.stats(),
        }
