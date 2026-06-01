"""
core/decision_fusion.py
───────────────────────
Fusionador de Decisiones — Combina A*, CBR y Reglas en una acción final.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.cbr import CaseBasedReasoner
from core.planner import AStarPlanner, Route
from core.rules_engine import RulesEngine, TacticalAction

log = logging.getLogger("argos.decision_fusion")


# ─────────────────────────── DATA CLASSES ────────────────────────

@dataclass
class Decision:
    action:        str
    confidence:    float
    needs_approval: bool
    source:        str          # "planner" | "cbr" | "rules" | "fusion"
    params:        Dict[str, Any] = field(default_factory=dict)
    mitre_id:      Optional[str] = None
    risk:          float = 0.5
    stealth:       float = 0.5
    alternatives:  List[str] = field(default_factory=list)
    explanation:   str = ""

    def to_dict(self) -> dict:
        return {
            "action":        self.action,
            "confidence":    round(self.confidence, 4),
            "needs_approval": self.needs_approval,
            "source":        self.source,
            "params":        self.params,
            "mitre_id":      self.mitre_id,
            "risk":          self.risk,
            "stealth":       self.stealth,
            "alternatives":  self.alternatives,
            "explanation":   self.explanation,
        }


# ─────────────────────────── DECISION FUSION ─────────────────────

class DecisionFusion:
    """
    Fusiona las recomendaciones de los tres motores (A*, CBR, Reglas)
    y produce una acción final con su nivel de confianza.

    Umbrales de confianza por perfil:
      ghost    → 0.85  (solo ejecuta si está muy seguro)
      balanced → 0.65  (equilibrio)
      blitz    → 0.35  (actúa con poca evidencia)

    Pesos de contribución:
      A* Planner  → 45%
      CBR Memory  → 30%
      Rules       → 25%
    """

    THRESHOLDS = {
        "ghost":    0.85,
        "balanced": 0.65,
        "blitz":    0.35,
    }

    WEIGHTS = {
        "planner": 0.45,
        "cbr":     0.30,
        "rules":   0.25,
    }

    def __init__(
        self,
        planner: AStarPlanner,
        cbr:     CaseBasedReasoner,
        rules:   RulesEngine,
    ) -> None:
        self.planner = planner
        self.cbr     = cbr
        self.rules   = rules

    def fuse(
        self,
        service:       Dict[str, Any],
        source_host_id: str,
        goal:          str   = "domain_admin",
        profile:       str   = "balanced",
        defense_level: str   = "none",
        os_type:       str   = "unknown",
        owned:         bool  = False,
    ) -> Decision:
        """
        Produce una Decision fusionando los tres motores.
        """
        candidates: Dict[str, float] = {}
        action_meta: Dict[str, dict] = {}

        # ── 1. A* Planner ──────────────────────────────────────
        plan_routes = self.planner.find_routes(source_host_id, goal, profile)
        if plan_routes:
            best_route: Route = plan_routes[0]
            if best_route.steps:
                step = best_route.steps[0]
                tech = step.technique
                score = self.WEIGHTS["planner"] * best_route.total_probability
                candidates[tech] = candidates.get(tech, 0.0) + score
                action_meta[tech] = {
                    "mitre_id": step.mitre_id,
                    "risk":     step.stealth_cost,
                    "stealth":  1.0 - step.stealth_cost,
                    "source":   "planner",
                }
                log.debug(f"[Fusion] Planner sugiere: {tech} (score={score:.3f})")

        # ── 2. CBR Memory ──────────────────────────────────────
        svc_desc = self._service_description(service, os_type, defense_level)
        cbr_cases = self.cbr.query_similar(svc_desc, top_k=5)
        for case in cbr_cases[:3]:
            action = case["action"]
            score  = self.WEIGHTS["cbr"] * case["weighted_score"]
            candidates[action] = candidates.get(action, 0.0) + score
            if action not in action_meta:
                action_meta[action] = {"source": "cbr", "risk": 0.5, "stealth": 0.5}
            log.debug(f"[Fusion] CBR sugiere: {action} (score={score:.3f})")

        # ── 3. Rules Engine ────────────────────────────────────
        rule_actions: List[TacticalAction] = self.rules.evaluate(
            service, defense_level, profile, os_type, owned
        )
        for rule in rule_actions[:4]:
            score = self.WEIGHTS["rules"] * rule.priority
            candidates[rule.action] = candidates.get(rule.action, 0.0) + score
            if rule.action not in action_meta:
                action_meta[rule.action] = {
                    "mitre_id": rule.mitre_id,
                    "risk":     rule.risk,
                    "stealth":  rule.stealth,
                    "source":   "rules",
                    "params":   rule.params,
                }
            log.debug(f"[Fusion] Rules sugiere: {rule.action} (score={score:.3f})")

        # ── 4. Fusión final ────────────────────────────────────
        if not candidates:
            log.warning("[Fusion] Sin candidatos — decisión vacía")
            return Decision(
                action="manual_intervention_required",
                confidence=0.0,
                needs_approval=True,
                source="fusion",
                explanation="Ningún motor produjo candidatos. Intervención manual requerida.",
            )

        # Ordenar candidatos por score
        sorted_candidates = sorted(candidates.items(), key=lambda x: x[1], reverse=True)
        best_action, best_score = sorted_candidates[0]
        confidence = min(1.0, best_score)

        # Alternativas (top 3 excluyendo la mejor)
        alternatives = [a for a, _ in sorted_candidates[1:4]]

        # Metadatos de la acción ganadora
        meta = action_meta.get(best_action, {})
        threshold = self.THRESHOLDS.get(profile, 0.65)
        needs_approval = confidence < threshold or meta.get("risk", 0.5) > 0.8

        explanation = self._build_explanation(
            best_action, confidence, threshold, plan_routes, cbr_cases, rule_actions
        )

        decision = Decision(
            action        = best_action,
            confidence    = confidence,
            needs_approval= needs_approval,
            source        = meta.get("source", "fusion"),
            params        = meta.get("params", {}),
            mitre_id      = meta.get("mitre_id"),
            risk          = meta.get("risk", 0.5),
            stealth       = meta.get("stealth", 0.5),
            alternatives  = alternatives,
            explanation   = explanation,
        )

        log.info(
            f"[Fusion] ✅ Decisión: '{best_action}' | "
            f"conf={confidence:.3f} | approval={'SI' if needs_approval else 'NO'}"
        )
        return decision

    # ─── HELPERS ──────────────────────────────────────────────────

    @staticmethod
    def _service_description(service: dict, os_type: str, defense: str) -> str:
        name    = service.get("name", "unknown")
        version = service.get("version", "")
        banner  = service.get("banner", "")
        port    = service.get("port", "?")
        parts = [f"{name} en {os_type}", f"puerto {port}"]
        if version:
            parts.append(f"versión {version}")
        if banner:
            parts.append(banner[:80])
        if defense not in ("none",):
            parts.append(f"defensa: {defense}")
        return ", ".join(parts)

    @staticmethod
    def _build_explanation(
        action:      str,
        confidence:  float,
        threshold:   float,
        routes:      list,
        cbr_cases:   list,
        rules:       list,
    ) -> str:
        lines = [f"Acción elegida: '{action}' (confianza={confidence:.2%})"]
        if routes:
            r = routes[0]
            lines.append(f"• Planner: ruta de {len(r.steps)} pasos, P={r.total_probability:.2f}")
        if cbr_cases:
            top = cbr_cases[0]
            lines.append(
                f"• CBR: caso similar '{top.get('description','')[:50]}' "
                f"(éxito={'Sí' if top.get('success') else 'No'}, sim={top.get('similarity',0):.2f})"
            )
        if rules:
            top_rule = rules[0]
            lines.append(f"• Regla: '{top_rule.action}' prio={top_rule.priority:.2f}")
        lines.append(
            f"→ {'Aprobación requerida' if confidence < threshold else 'Ejecución automática'} "
            f"(umbral={threshold:.0%})"
        )
        return " | ".join(lines)
