"""
api/grpc_server.py
──────────────────
Servidor gRPC de Argos — Recibe agentes y opera como C2.
Implementa los servicios AgentC2 y OperatorConsole del proto.
"""
from __future__ import annotations

import asyncio
import json as _json
import logging
import time

from grpc import aio as grpc_aio

from core.director import Director
from shared.proto import argos_pb2, argos_pb2_grpc

log = logging.getLogger("argos.grpc_server")


class ArgosAgentC2Servicer(argos_pb2_grpc.AgentC2Servicer):
    """Servicio AgentC2: registro + Beacon stream + reporte de hallazgos."""

    def __init__(self, director: Director) -> None:
        self.director = director

    async def Register(self, request: argos_pb2.AgentInfo, context) -> argos_pb2.RegisterAck:
        info = {
            "agent_id": request.agent_id,
            "hostname": request.hostname,
            "os":       request.os,
            "arch":     request.arch,
            "ip":       request.ip,
        }
        ack_data = await self.director.register_agent(info)
        log.info(f"[gRPC] Register <- {request.agent_id[:8]} @ {request.ip}")
        return argos_pb2.RegisterAck(
            success             = ack_data["success"],
            beacon_interval_sec = ack_data["beacon_interval_sec"],
            mission_id          = ack_data["mission_id"],
            director_version    = ack_data["director_version"],
        )

    async def Beacon(self, request_iterator, context):
        """Stream bidireccional: agente envía eventos, director responde con comandos."""
        agent_id = None
        async for event in request_iterator:
            agent_id = event.agent_id

            # Heartbeat
            if event.type == argos_pb2.HEARTBEAT:
                hb = event.hb if event.HasField("hb") else argos_pb2.Heartbeat()
                await self.director.process_heartbeat(agent_id, {
                    "cpu_usage": hb.cpu_usage,
                    "mem_usage": hb.mem_usage,
                    "elevated":  hb.is_elevated,
                })

            # Resultados de scan, exploit, cred, flag, defensa
            elif event.type in (
                argos_pb2.SCAN_RESULT, argos_pb2.EXPLOIT_RESULT,
                argos_pb2.CREDENTIAL_FOUND, argos_pb2.FLAG_CAPTURED,
                argos_pb2.DEFENSE_ALERT,
            ):
                finding = self._event_to_finding(event)
                if finding:
                    await self.director.process_finding(agent_id, finding)

            # Intentar entregar comando pendiente
            cmd = await self.director.get_pending_command(agent_id)
            if cmd:
                log.info(f"[gRPC] Beacon -> {agent_id[:8]} comando: {cmd.get('action', cmd.get('type', '?'))}")
                yield self._dict_to_director_command(cmd)

    async def ReportFinding(self, request: argos_pb2.Finding, context) -> argos_pb2.FindingAck:
        finding = {
            "type":        self._finding_type_name(request.type),
            "description": request.description,
            "flag_value":  request.flag_value,
        }
        await self.director.process_finding(request.agent_id, finding)
        return argos_pb2.FindingAck(accepted=True)

    # ─── HELPERS ──────────────────────────────────────────────────

    @staticmethod
    def _event_to_finding(event: argos_pb2.AgentEvent) -> dict | None:
        et = event.type
        if et == argos_pb2.SCAN_RESULT and event.HasField("scan"):
            s = event.scan
            svcs = []
            for svc in s.services:
                svcs.append({
                    "type": "SERVICE_OPEN", "ip": s.target_ip,
                    "port": svc.port, "protocol": svc.protocol,
                    "service_name": svc.name, "banner": svc.banner,
                    "version": svc.version,
                })
            return svcs[0] if svcs else None

        elif et == argos_pb2.EXPLOIT_RESULT and event.HasField("exploit"):
            ex = event.exploit
            return {
                "type": "EXPLOIT_SUCCESS" if ex.success else "EXPLOIT_FAILED",
                "technique": ex.cve_or_technique, "session_id": ex.session_id,
                "output": ex.output,
            }
        elif et == argos_pb2.CREDENTIAL_FOUND and event.HasField("cred"):
            c = event.cred
            return {"type": "CREDENTIAL", "username": c.username, "cred_type": c.type,
                    "value": c.value, "scope": c.scope}
        elif et == argos_pb2.FLAG_CAPTURED and event.HasField("flag"):
            f = event.flag
            return {"type": "FLAG", "flag_value": f.value, "path": f.path}
        elif et == argos_pb2.DEFENSE_ALERT and event.HasField("defense"):
            d = event.defense
            return {"type": "DEFENSE_DETECTED", "defense_type": d.type,
                    "defense_name": d.name, "severity": d.severity}
        return None

    @staticmethod
    def _stringify_params(params: dict) -> dict:
        """Protobuf `ExploitCommand.params` es `map<string, string>`.
        Convierte valores no-string (listas/tuplas/dicts de las reglas tácticas)
        a su representación JSON para evitar TypeError al serializar."""
        out = {}
        for key, value in (params or {}).items():
            if isinstance(value, str):
                out[key] = value
            elif isinstance(value, (int, float, bool)):
                out[key] = str(value)
            else:
                # listas/tuplas/dicts → JSON compacto
                try:
                    out[key] = _json.dumps(value, default=str)
                except (TypeError, ValueError):
                    out[key] = str(value)
        return out

    @staticmethod
    def _finding_type_name(type_int: int) -> str:
        return {0: "HOST_DISCOVERED", 1: "SERVICE_OPEN", 2: "CREDENTIAL",
                3: "VULNERABILITY", 4: "FLAG", 5: "DEFENSE_DETECTED"}.get(type_int, "UNKNOWN")

    @staticmethod
    def _dict_to_director_command(cmd: dict) -> argos_pb2.DirectorCommand:
        ctype = cmd.get("type", "EXPLOIT")
        type_map = {"SCAN": 0, "EXPLOIT": 1, "PERSIST": 2, "EXFIL": 3, "PIVOT": 4,
                     "CLEANUP": 5, "DEPLOY_MODULE": 6, "SLEEP": 7, "SELF_DESTRUCT": 8}

        # Build scan ports: handle string presets like "top20" or actual port lists
        raw_ports = cmd.get("params", {}).get("ports", [22, 80, 443, 445, 3306, 3389])
        if isinstance(raw_ports, str):
            # Preset strings are ignored here; agent will expand them
            scan_ports = []
        elif isinstance(raw_ports, list):
            scan_ports = [int(p) for p in raw_ports if str(p).isdigit()]
        else:
            scan_ports = []

        return argos_pb2.DirectorCommand(
            command_id = cmd.get("command_id", ""),
            type       = type_map.get(ctype, 1),
            timeout_s  = cmd.get("timeout", 120),
            exploit_cmd=argos_pb2.ExploitCommand(
                target_host = cmd.get("target_host", ""),
                technique   = cmd.get("action", ""),
                cve         = cmd.get("cve", ""),
                params      = ArgosAgentC2Servicer._stringify_params(cmd.get("params", {})),
            ) if ctype == "EXPLOIT" else None,
            scan_cmd=argos_pb2.ScanCommand(
                targets  = [cmd.get("params", {}).get("target", "")],
                scan_type = "tcp_syn",
                ports     = scan_ports,
            ) if ctype == "SCAN" else None,
        )


class ArgosOperatorConsoleServicer(argos_pb2_grpc.OperatorConsoleServicer):
    """Servicio OperatorConsole: dashboard streaming + control."""

    def __init__(self, director: Director) -> None:
        self.director = director

    async def WatchMission(self, request: argos_pb2.MissionRequest, context):
        """Stream de eventos al dashboard/CLI."""
        log.info(f"[gRPC] WatchMission <- mision {request.mission_id}")
        bus = self.director.bus
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)

        async def _push(data):
            try:
                queue.put_nowait(data)
            except asyncio.QueueFull:
                pass

        bus.subscribe("*", _push)
        try:
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield argos_pb2.MissionUpdate(
                        event_type = item.get("type", "EVENT") if isinstance(item, dict) else "EVENT",
                        payload    = _json.dumps(item, default=str),
                        timestamp  = int(time.time()),
                    )
                except asyncio.TimeoutError:
                    yield argos_pb2.MissionUpdate(
                        event_type = "KEEPALIVE", payload = "{}",
                        timestamp  = int(time.time()),
                    )
        finally:
            bus.unsubscribe("*", _push)

    async def ResolveDecision(self, request: argos_pb2.DecisionResponse, context) -> argos_pb2.DecisionAck:
        if request.approved:
            await self.director.approve_decision(request.decision_id, request.custom_cmd or None)
        else:
            await self.director.reject_decision(request.decision_id)
        return argos_pb2.DecisionAck(ok=True, message="OK")

    async def SetMode(self, request: argos_pb2.ModeChange, context) -> argos_pb2.ModeAck:
        profile_map = {0: "ghost", 1: "balanced", 2: "blitz"}
        self.director.config.profile = profile_map.get(request.profile, "balanced")
        return argos_pb2.ModeAck(ok=True)

    async def ExecuteCommand(self, request: argos_pb2.ManualCommand, context) -> argos_pb2.CommandResult:
        log.info(f"[gRPC] ExecuteCommand -> {request.agent_id[:8]}: {request.command[:60]}")
        cmd = {"type": "EXPLOIT", "action": request.command, "agent_id": request.agent_id}
        await self.director.queue_command(request.agent_id, cmd)
        return argos_pb2.CommandResult(output="Queued", ok=True)

    async def GetWorldGraph(self, request: argos_pb2.WorldGraphRequest, context) -> argos_pb2.WorldGraphSnapshot:
        return argos_pb2.WorldGraphSnapshot(
            graph_json = self.director.kt.to_json(),
            timestamp  = int(time.time()),
        )


class GrpcServer:
    """Servidor gRPC asíncrono de Argos."""

    def __init__(self, director: Director, host: str = "0.0.0.0", port: int = 50051) -> None:
        self.director = director
        self.host = host
        self.port = port
        self._server: grpc_aio.Server | None = None

    async def start(self) -> None:
        self._server = grpc_aio.server()
        argos_pb2_grpc.add_AgentC2Servicer_to_server(ArgosAgentC2Servicer(self.director), self._server)
        argos_pb2_grpc.add_OperatorConsoleServicer_to_server(ArgosOperatorConsoleServicer(self.director), self._server)
        addr = f"{self.host}:{self.port}"
        self._server.add_insecure_port(addr)
        await self._server.start()
        log.info(f"[gRPC] Servidor escuchando en {addr}")
        await self._server.wait_for_termination()

    async def stop(self) -> None:
        if self._server:
            await self._server.stop(grace=5)
            log.info("[gRPC] Servidor detenido")
