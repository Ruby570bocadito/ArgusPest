"""
core/planner.py
───────────────
Planificador A* — Calcula rutas de ataque óptimas sobre el Grafo Vivo.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

import networkx as nx

from core.knowledge_tree import HostNode, KnowledgeTree

log = logging.getLogger("argos.planner")


# ─────────────────────────── DATA CLASSES ────────────────────────

@dataclass
class PlanStep:
    source:     str
    target:     str
    technique:  str
    probability: float
    stealth_cost: float
    mitre_id:   Optional[str] = None
    command:    Optional[str] = None


@dataclass
class Route:
    steps:             List[PlanStep]
    total_probability: float = 1.0
    avg_stealth:       float = 0.5
    score:             float = 0.0
    goal_host:         str   = ""

    def __post_init__(self):
        self.score = self._compute_score()

    def _compute_score(self) -> float:
        if not self.steps:
            return 0.0
        # Score combinado: probabilidad × sigilo promedio
        # stealth_cost: 0.0 (silencioso) – 1.0 (ruidoso)
        # Queremos favorecer rutas silenciosas, así que usamos (1.0 - avg_stealth_cost)
        return round(self.total_probability * (1.0 - self.avg_stealth), 4)

    def summary(self) -> str:
        chain = " → ".join(s.source[:8] for s in self.steps)
        if self.steps:
            chain += f" → {self.steps[-1].target[:8]}"
        return (
            f"Route({len(self.steps)} steps | "
            f"P={self.total_probability:.2f} | "
            f"stealth={self.avg_stealth:.2f} | "
            f"score={self.score:.4f})\n  {chain}"
        )


# ─────────────────────────── PLANNER ─────────────────────────────

class AStarPlanner:
    """
    Calcula rutas óptimas hacia objetivos usando A* sobre el grafo de ataques.

    Perfiles:
      ghost    → penaliza mucho el sigilo (elige rutas lentas pero silenciosas)
      balanced → equilibrio entre velocidad y sigilo
      blitz    → maximiza probabilidad de éxito sin importar el ruido
    """

    PROFILE_STEALTH_WEIGHT = {
        "ghost":    0.8,
        "balanced": 0.5,
        "blitz":    0.1,
    }

    def __init__(self, kt: KnowledgeTree) -> None:
        self.kt = kt

    def find_routes(
        self,
        start_host_id: str,
        goal: str,          # "domain_admin" | "flag:CTF{*}" | "host:<ip>" | "owned"
        profile: str = "balanced",
        max_routes: int = 5,
    ) -> List[Route]:
        """
        Devuelve hasta max_routes rutas ordenadas por score descendente.
        """
        attack_graph = self.kt.get_attack_graph()

        if start_host_id not in attack_graph:
            log.warning(f"[Planner] Host origen {start_host_id[:8]} no está en el grafo de ataque")
            return []

        target_ids = self._resolve_goal(goal)
        if not target_ids:
            log.warning(f"[Planner] No se encontraron objetivos para goal='{goal}'")
            return []

        routes: List[Route] = []
        sw = self.PROFILE_STEALTH_WEIGHT.get(profile, 0.5)

        for target_id in target_ids:
            if target_id == start_host_id:
                continue
            if target_id not in attack_graph:
                # Añadir el nodo objetivo aunque no tenga aristas aún
                attack_graph.add_node(target_id)

            try:
                path = nx.astar_path(
                    attack_graph,
                    start_host_id,
                    target_id,
                    heuristic=self._heuristic(profile),
                    weight="cost",
                )
                route = self._build_route(attack_graph, path, sw, goal_host=target_id)
                routes.append(route)
                log.info(f"[Planner] Ruta encontrada → {route.summary()}")
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                log.debug(f"[Planner] Sin ruta hacia {target_id[:8]}")

        routes.sort(key=lambda r: r.score, reverse=True)
        return routes[:max_routes]

    # ─── GOAL RESOLVER ────────────────────────────────────────────

    def _resolve_goal(self, goal: str) -> List[str]:
        hosts = self.kt.get_all_hosts()

        if goal == "domain_admin":
            return [h.id for h in hosts if h.role == "dc"]

        if goal == "owned":
            return [h.id for h in hosts if not h.owned]

        if goal.startswith("host:"):
            ip = goal.split(":", 1)[1]
            return [h.id for h in hosts if h.ip == ip]

        if goal.startswith("flag:"):
            # Cualquier host que pueda tener flags
            return [h.id for h in hosts if h.asset_value >= 50]

        # Fallback: todos los hosts de alto valor
        log.debug(f"[Planner] goal desconocido '{goal}' → targets de alto valor")
        return [h.id for h in hosts if h.asset_value >= 60]

    # ─── HEURISTIC ────────────────────────────────────────────────

    def _heuristic(self, profile: str):
        """
        Heurística A* basada en último octeto de IP.
        En ghost, penaliza más las aristas ruidosas.
        """
        sw = self.PROFILE_STEALTH_WEIGHT.get(profile, 0.5)
        # Snapshot seguro del grafo para evitar race conditions
        all_hosts = self.kt.get_all_hosts()
        host_data = {h.id: h for h in all_hosts}

        def h(n1: str, n2: str) -> float:
            try:
                h1: HostNode = host_data[n1]
                h2: HostNode = host_data[n2]
                distance = abs(
                    int(h1.ip.split(".")[-1]) - int(h2.ip.split(".")[-1])
                ) / 255.0
            except Exception:
                distance = 0.5
            return distance * sw

        return h

    # ─── ROUTE BUILDER ────────────────────────────────────────────

    def _build_route(
        self,
        graph: nx.MultiDiGraph,
        path: List[str],
        stealth_weight: float,
        goal_host: str,
    ) -> Route:
        steps: List[PlanStep] = []
        total_probability = 1.0
        total_stealth     = 0.0

        for i in range(len(path) - 1):
            src, dst = path[i], path[i + 1]
            # Obtener la mejor arista entre src y dst
            best_edge = self._best_edge(graph, src, dst)

            step = PlanStep(
                source      = src,
                target      = dst,
                technique   = best_edge.get("technique",   "unknown"),
                probability = best_edge.get("probability", 0.5),
                stealth_cost= best_edge.get("stealth_cost",0.5),
                mitre_id    = best_edge.get("mitre_technique_id"),
            )
            steps.append(step)
            total_probability *= step.probability
            total_stealth     += step.stealth_cost

        avg_stealth = total_stealth / len(steps) if steps else 0.5
        return Route(
            steps             = steps,
            total_probability = round(total_probability, 4),
            avg_stealth       = round(avg_stealth, 4),
            goal_host         = goal_host,
        )

    @staticmethod
    def _best_edge(graph: nx.MultiDiGraph, src: str, dst: str) -> dict:
        """Elige la arista de menor coste entre src y dst."""
        edges = graph.get_edge_data(src, dst) or {}
        if not edges:
            return {"technique": "unknown", "probability": 0.5, "stealth_cost": 0.5}
        best = min(edges.values(), key=lambda e: e.get("cost", 1.0))
        edata = best.get("data")
        if edata:
            return {
                "technique":          edata.technique,
                "probability":        edata.probability,
                "stealth_cost":       edata.stealth_cost,
                "mitre_technique_id": edata.mitre_technique_id,
            }
        return best
