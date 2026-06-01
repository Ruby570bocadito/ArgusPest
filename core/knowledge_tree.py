"""
core/knowledge_tree.py
──────────────────────
Argos Live World Graph — Grafo Vivo del conocimiento táctico.
Implementado sobre NetworkX y persistido en SQLite.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import networkx as nx

log = logging.getLogger("argos.knowledge_tree")


# ─────────────────────────── ENUMS ───────────────────────────────

class NodeType(str, Enum):
    HOST           = "host"
    SERVICE        = "service"
    CREDENTIAL     = "credential"
    VULNERABILITY  = "vulnerability"
    FLAG           = "flag"
    DEFENSE        = "defense"
    GDS            = "global_defense_state"


class EdgeType(str, Enum):
    HAS_SERVICE   = "HAS_SERVICE"
    HAS_CREDS     = "HAS_CREDS"
    PROTECTED_BY  = "PROTECTED_BY"
    CONTAINS      = "CONTAINS"
    EXPLOITS      = "EXPLOITS"
    TRUSTS        = "TRUSTS"
    LATERAL_MOVE  = "LATERAL_MOVE"


class HostRole(str, Enum):
    UNKNOWN     = "unknown"
    WORKSTATION = "workstation"
    SERVER      = "server"
    DC          = "dc"
    DB          = "db"
    WEB         = "web"
    CONTAINER   = "container"
    ROUTER      = "router"


# ─────────────────────────── NODE DATACLASSES ────────────────────

@dataclass
class HostNode:
    id:           str  = field(default_factory=lambda: str(uuid.uuid4()))
    ip:           str  = ""
    hostname:     Optional[str]  = None
    os:           Optional[str]  = None
    arch:         Optional[str]  = None
    role:         str  = HostRole.UNKNOWN
    asset_value:  int  = 10           # 1–100
    owned:        bool = False
    sessions:     List[str] = field(default_factory=list)
    agent_id:     Optional[str] = None
    discovered_at: Optional[str] = None


@dataclass
class ServiceNode:
    id:           str  = field(default_factory=lambda: str(uuid.uuid4()))
    host_id:      str  = ""
    port:         int  = 0
    protocol:     str  = "tcp"
    service_name: str  = "unknown"
    banner:       Optional[str] = None
    version:      Optional[str] = None
    cpe:          Optional[str] = None


@dataclass
class CredentialNode:
    id:           str  = field(default_factory=lambda: str(uuid.uuid4()))
    username:     str  = ""
    type:         str  = "password"    # password | ntlm_hash | kerberos_ticket | ssh_key
    value:        str  = ""
    scope:        str  = "local"       # local | domain
    source_host_id: Optional[str] = None
    target_hosts: List[str] = field(default_factory=list)
    cracked:      bool = False


@dataclass
class VulnerabilityNode:
    id:             str   = field(default_factory=lambda: str(uuid.uuid4()))
    cve:            Optional[str] = None
    description:    str   = ""
    cvss_score:     float = 0.0
    exploit_module: str   = ""
    service_id:     str   = ""
    verified:       bool  = False


@dataclass
class DefenseNode:
    id:              str   = field(default_factory=lambda: str(uuid.uuid4()))
    host_id:         str   = ""
    type:            str   = "edr"     # edr | waf | ids | honeypot
    name:            str   = "unknown"
    aggressiveness:  float = 0.5       # 0.0–1.0


@dataclass
class FlagNode:
    id:           str  = field(default_factory=lambda: str(uuid.uuid4()))
    value:        str  = ""
    host_id:      str  = ""
    path:         Optional[str] = None
    captured_at:  Optional[str] = None
    submitted:    bool = False


@dataclass
class ExploitEdge:
    source_host_id:      str   = ""
    target_host_id:      str   = ""
    technique:           str   = ""
    probability:         float = 0.5   # 0.0–1.0
    stealth_cost:        float = 0.5   # 0.0 (silencioso) – 1.0 (ruidoso)
    mitre_technique_id:  Optional[str] = None
    last_tried:          Optional[str] = None
    success_count:       int   = 0
    failure_count:       int   = 0


# ─────────────────────────── GLOBAL DEFENSE STATE ────────────────

class GlobalDefenseState:
    """
    Nodo único que representa el nivel de alerta global de la red objetivo.
    score 0.0 = operación normal | score 1.0 = defensa activa / cazadores activos.
    """

    EVENTS = {
        "edr_alert":          +0.30,
        "honeypot_detected":  +0.60,
        "agent_killed":       +0.40,
        "scan_detected":      +0.20,
        "ids_triggered":      +0.25,
        "analyst_active":     +0.15,
        "timeout_no_activity":-0.05,
        "agent_cleaned":      -0.02,
    }
    KILL_THRESHOLD = 0.90   # Si supera esto, todos los agentes hibernan

    def __init__(self) -> None:
        self.score: float = 0.0
        self._lock = threading.Lock()
        self._listeners: List[Any] = []

    def update(self, event_type: str, severity: float = 1.0) -> float:
        delta = self.EVENTS.get(event_type, 0.0) * severity
        should_trigger = False
        with self._lock:
            self.score = max(0.0, min(1.0, self.score + delta))
            log.info(f"[GDS] {event_type} → score={self.score:.2f}")
            if self.score >= self.KILL_THRESHOLD:
                should_trigger = True
        if should_trigger:
            self._trigger_kill_switch()
        return self.score

    def decay(self) -> None:
        """Llamar periódicamente para simular que el tiempo enfría la alerta."""
        with self._lock:
            self.score = max(0.0, self.score - 0.02)

    def _trigger_kill_switch(self) -> None:
        log.critical("[GDS] ⚠️  KILL SWITCH ACTIVADO — Alertando a todos los agentes")
        for listener in self._listeners:
            listener("KILL_SWITCH")

    def register_listener(self, fn) -> None:
        self._listeners.append(fn)

    @property
    def level(self) -> str:
        if self.score < 0.3:
            return "green"
        elif self.score < 0.6:
            return "yellow"
        elif self.score < 0.9:
            return "red"
        return "critical"

    def to_dict(self) -> dict:
        return {"score": round(self.score, 3), "level": self.level}


# ─────────────────────────── KNOWLEDGE TREE ──────────────────────

class KnowledgeTree:
    """
    Grafo Vivo de Argos.
    Thread-safe. Todas las escrituras pasan por métodos públicos con lock.
    """

    def __init__(self) -> None:
        self._graph = nx.MultiDiGraph()
        self._lock  = threading.RLock()
        self.gds    = GlobalDefenseState()

        # Añadir nodo GDS al grafo
        self._graph.add_node(
            "GDS",
            type=NodeType.GDS,
            data=self.gds,
        )
        log.info("[KnowledgeTree] Inicializado — Grafo Vivo listo")

    # ─── HOSTS ────────────────────────────────────────────────────

    def add_host(self, host: HostNode) -> str:
        with self._lock:
            existing = self._find_host_by_ip(host.ip)
            if existing:
                log.debug(f"[KT] Host ya existe: {host.ip} → {existing}")
                return existing
            self._graph.add_node(host.id, type=NodeType.HOST, data=host)
            log.info(f"[KT] Host añadido: {host.ip} [{host.id[:8]}]")
            return host.id

    def get_host_by_ip(self, ip: str) -> Optional[HostNode]:
        with self._lock:
            nid = self._find_host_by_ip(ip)
            return self._graph.nodes[nid]["data"] if nid else None

    def mark_owned(self, host_id: str, session_id: str, agent_id: str) -> None:
        with self._lock:
            if host_id in self._graph:
                node: HostNode = self._graph.nodes[host_id]["data"]
                node.owned = True
                node.agent_id = agent_id
                if session_id not in node.sessions:
                    node.sessions.append(session_id)
                log.info(f"[KT] 🏴 Host OWNED: {node.ip} (session={session_id})")

    # ─── SERVICES ─────────────────────────────────────────────────

    def add_service(self, svc: ServiceNode) -> str:
        with self._lock:
            self._graph.add_node(svc.id, type=NodeType.SERVICE, data=svc)
            self._graph.add_edge(svc.host_id, svc.id, type=EdgeType.HAS_SERVICE)
            log.info(f"[KT] Servicio: {svc.service_name}:{svc.port} → host {svc.host_id[:8]}")
            return svc.id

    # ─── CREDENTIALS ──────────────────────────────────────────────

    def add_credential(self, cred: CredentialNode) -> str:
        with self._lock:
            self._graph.add_node(cred.id, type=NodeType.CREDENTIAL, data=cred)
            if cred.source_host_id:
                self._graph.add_edge(cred.source_host_id, cred.id, type=EdgeType.HAS_CREDS)
            log.info(f"[KT] 🔑 Credencial: {cred.username} [{cred.type}]")
            return cred.id

    # ─── VULNERABILITIES ──────────────────────────────────────────

    def add_vulnerability(self, vuln: VulnerabilityNode) -> str:
        with self._lock:
            self._graph.add_node(vuln.id, type=NodeType.VULNERABILITY, data=vuln)
            log.info(f"[KT] Vuln: {vuln.cve or vuln.description[:40]} (CVSS={vuln.cvss_score})")
            return vuln.id

    # ─── FLAGS ────────────────────────────────────────────────────

    def add_flag(self, flag: FlagNode) -> str:
        with self._lock:
            self._graph.add_node(flag.id, type=NodeType.FLAG, data=flag)
            self._graph.add_edge(flag.host_id, flag.id, type=EdgeType.CONTAINS)
            log.info(f"[KT] 🚩 FLAG: {flag.value[:32]}...")
            return flag.id

    # ─── DEFENSES ─────────────────────────────────────────────────

    def add_defense(self, defense: DefenseNode) -> str:
        with self._lock:
            self._graph.add_node(defense.id, type=NodeType.DEFENSE, data=defense)
            self._graph.add_edge(defense.host_id, defense.id, type=EdgeType.PROTECTED_BY)
            self.gds.update("edr_alert", defense.aggressiveness)
            log.warning(f"[KT] 🛡️  Defensa detectada: {defense.name} en {defense.host_id[:8]}")
            return defense.id

    # ─── EXPLOIT EDGES ────────────────────────────────────────────

    def add_exploit_edge(self, edge: ExploitEdge) -> None:
        with self._lock:
            self._graph.add_edge(
                edge.source_host_id,
                edge.target_host_id,
                type=EdgeType.EXPLOITS,
                data=edge,
                cost=self._edge_cost(edge),
            )
            log.debug(f"[KT] Arista EXPLOIT: {edge.source_host_id[:8]} → {edge.target_host_id[:8]} [{edge.technique}]")

    # ─── QUERIES ──────────────────────────────────────────────────

    def get_all_hosts(self) -> List[HostNode]:
        with self._lock:
            return self._get_all_hosts_unlocked()

    def get_owned_hosts(self) -> List[HostNode]:
        with self._lock:
            return [h for h in self._get_all_hosts_unlocked() if h.owned]

    def _get_all_hosts_unlocked(self) -> List[HostNode]:
        """Versión interna sin lock — llamar solo con lock adquirido."""
        return [
            d["data"] for _, d in self._graph.nodes(data=True)
            if d.get("type") == NodeType.HOST
        ]

    def get_services_for_host(self, host_id: str) -> List[ServiceNode]:
        with self._lock:
            result = []
            for _, neighbor, edata in self._graph.out_edges(host_id, data=True):
                if edata.get("type") == EdgeType.HAS_SERVICE:
                    n = self._graph.nodes[neighbor]
                    if n.get("type") == NodeType.SERVICE:
                        result.append(n["data"])
            return result

    def get_attack_graph(self) -> nx.MultiDiGraph:
        """Subgrafo solo con hosts y aristas EXPLOITS."""
        with self._lock:
            host_nodes = [
                n for n, d in self._graph.nodes(data=True)
                if d.get("type") == NodeType.HOST
            ]
            exploit_edges = [
                (u, v, d) for u, v, d in self._graph.edges(data=True)
                if d.get("type") == EdgeType.EXPLOITS
            ]
            ag = nx.MultiDiGraph()
            ag.add_nodes_from(host_nodes)
            for u, v, d in exploit_edges:
                ag.add_edge(u, v, **d)
            return ag

    def stats(self) -> Dict[str, int]:
        with self._lock:
            counts: Dict[str, int] = {}
            for _, d in self._graph.nodes(data=True):
                t = d.get("type", "unknown")
                counts[t] = counts.get(t, 0) + 1
            return counts

    # ─── SERIALIZATION ────────────────────────────────────────────

    def to_json(self) -> str:
        """Serializa el grafo para el dashboard (Cytoscape.js compatible)."""
        with self._lock:
            nodes = []
            for nid, d in self._graph.nodes(data=True):
                ntype = d.get("type", "unknown")
                data  = d.get("data")
                nodes.append({
                    "data": {
                        "id":    nid,
                        "type":  ntype,
                        "label": self._node_label(ntype, data),
                        "owned": getattr(data, "owned", False),
                        **({} if data is None else self._safe_dict(data)),
                    }
                })
            edges = []
            for u, v, d in self._graph.edges(data=True):
                edges.append({
                    "data": {
                        "source": u,
                        "target": v,
                        "type":   d.get("type", ""),
                    }
                })
            return json.dumps({"nodes": nodes, "edges": edges, "gds": self.gds.to_dict()})

    # ─── INTERNAL HELPERS ─────────────────────────────────────────

    def _find_host_by_ip(self, ip: str) -> Optional[str]:
        for nid, d in self._graph.nodes(data=True):
            if d.get("type") == NodeType.HOST:
                host: HostNode = d["data"]
                if host.ip == ip:
                    return nid
        return None

    @staticmethod
    def _edge_cost(edge: ExploitEdge) -> float:
        """Coste para A*: combina probabilidad (invertida) y sigilo."""
        prob_cost    = 1.0 - edge.probability
        stealth_cost = edge.stealth_cost
        return round(0.6 * prob_cost + 0.4 * stealth_cost, 4)

    @staticmethod
    def _node_label(ntype: str, data: Any) -> str:
        if ntype == NodeType.HOST:
            return getattr(data, "ip", "?")
        if ntype == NodeType.SERVICE:
            return f"{getattr(data, 'service_name', '?')}:{getattr(data, 'port', '?')}"
        if ntype == NodeType.CREDENTIAL:
            return getattr(data, "username", "?")
        if ntype == NodeType.FLAG:
            v = getattr(data, "value", "")
            return v[:20] + "..." if len(v) > 20 else v
        if ntype == NodeType.DEFENSE:
            return getattr(data, "name", "?")
        if ntype == NodeType.GDS:
            return "GlobalDefenseState"
        return ntype

    @staticmethod
    def _safe_dict(obj: Any) -> dict:
        try:
            return {k: v for k, v in asdict(obj).items() if not isinstance(v, bytes)}
        except Exception:
            return {}
