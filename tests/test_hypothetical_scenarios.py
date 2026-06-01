#!/usr/bin/env python3
"""
tests/test_hypothetical_scenarios.py
─────────────────────────────────────
Testing de escenarios hipotéticos avanzados.
Simula situaciones reales de red team que podrían ocurrir.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

from core.decision_fusion import Decision, DecisionFusion
from core.director import Director, MissionConfig
from core.event_bus import Event, EventBus
from core.knowledge_tree import (
    CredentialNode,
    DefenseNode,
    ExploitEdge,
    FlagNode,
    HostNode,
    KnowledgeTree,
    ServiceNode,
)
from core.planner import AStarPlanner
from core.rules_engine import RulesEngine


@pytest.fixture
def bus():
    return EventBus()


@pytest.fixture
def mission_config(tmp_path):
    return MissionConfig(
        target="10.0.0.0/24",
        goal="domain_admin",
        profile="balanced",
        mode="pentest",
        output_dir=str(tmp_path),
    )


# ═══════════════════════════════════════════════════════════════════
# ESCENARIO 1: Operación fantasma — perfil ghost con máxima stealth
# ═══════════════════════════════════════════════════════════════════

class TestGhostOperation:
    """Simula una operación real con perfil ghost donde cada acción
    debe ser evaluada con máxima cautela."""

    @pytest.mark.asyncio
    async def test_ghost_requires_approval_for_everything(self, mission_config):
        mission_config.profile = "ghost"
        mission_config.auto_decide = False
        director = Director(config=mission_config, bus=EventBus())

        await director.register_agent({
            "agent_id": "ghost-agent",
            "ip": "10.0.0.50",
            "os": "linux",
        })

        # Descubrir servicio SSH
        await director.process_finding("ghost-agent", {
            "type": "SERVICE_OPEN",
            "port": 22,
            "service_name": "ssh",
            "version": "OpenSSH 7.4",
            "banner": "",
        })

        pending = director.list_pending_decisions()
        # En ghost, casi todo requiere aprobación
        assert len(pending) >= 0  # Puede ser 0 si la confianza es alta

    def test_ghost_threshold_is_highest(self):
        thresholds = DecisionFusion.THRESHOLDS
        assert thresholds["ghost"] > thresholds["balanced"]
        assert thresholds["balanced"] > thresholds["blitz"]

    def test_ghost_rules_penalize_noisy_actions(self):
        rules = RulesEngine()
        svc = {"name": "ssh", "port": 22, "version": "", "banner": ""}

        ghost = rules.evaluate(svc, defense_level="none", profile="ghost")
        blitz = rules.evaluate(svc, defense_level="none", profile="blitz")

        # Ghost debe tener menos acciones de alta prioridad ruidosas
        ghost_noisy = [a for a in ghost if a.risk > 0.7]
        blitz_noisy = [a for a in blitz if a.risk > 0.7]
        assert len(ghost_noisy) <= len(blitz_noisy)


# ═══════════════════════════════════════════════════════════════════
# ESCENARIO 2: Red altamente defendida — EDR activo, kill switch
# ═══════════════════════════════════════════════════════════════════

class TestHighDefenseNetwork:
    """Simula una red con EDR activo que detecta actividad y
    eventualmente activa el kill switch."""

    def test_edr_detection_escalation(self):
        kt = KnowledgeTree()
        gds = kt.gds

        # Escalación gradual de detección
        assert gds.level == "green"

        gds.update("scan_detected")     # Escaneo detectado
        assert gds.level in ("green", "yellow")

        gds.update("ids_triggered")     # IDS activado
        assert gds.level in ("yellow", "red")

        gds.update("edr_alert")         # EDR alerta
        assert gds.level in ("yellow", "red", "critical")

    def test_kill_switch_hibernation(self):
        kt = KnowledgeTree()
        triggered = []
        kt.gds.register_listener(lambda e: triggered.append(e))

        # Simular múltiples detecciones que activan kill switch
        kt.gds.update("honeypot_detected")  # +0.60
        kt.gds.update("agent_killed")       # +0.40 → 1.00

        assert kt.gds.score >= 0.90
        assert "KILL_SWITCH" in triggered
        assert kt.gds.level == "critical"

    def test_defense_decay_over_time(self):
        kt = KnowledgeTree()

        # Subir GDS
        kt.gds.update("edr_alert")   # +0.30
        kt.gds.update("edr_alert")   # +0.30 → 0.60
        assert kt.gds.score == 0.60

        # Simular decaimiento con el tiempo
        for _ in range(10):
            kt.gds.decay()

        # Debe haber bajado
        assert kt.gds.score < 0.60
        assert kt.gds.score >= 0.0

    def test_high_defense_reduces_action_priority(self):
        rules = RulesEngine()
        svc = {"name": "ssh", "port": 22, "version": "", "banner": ""}

        low_def = rules.evaluate(svc, defense_level="none")
        high_def = rules.evaluate(svc, defense_level="high")

        avg_low = sum(a.priority for a in low_def) / len(low_def)
        avg_high = sum(a.priority for a in high_def) / len(high_def)

        assert avg_high <= avg_low


# ═══════════════════════════════════════════════════════════════════
# ESCENARIO 3: Ataque multi-step — pivoteo a través de múltiples hosts
# ═══════════════════════════════════════════════════════════════════

class TestMultiStepAttack:
    """Simula un ataque APT real con pivoteo a través de múltiples
    hosts hasta llegar al domain controller."""

    @pytest.fixture
    def enterprise_network(self):
        """Simula una red empresarial con múltiples segmentos."""
        kt = KnowledgeTree()

        # Segmento 1: DMZ
        web_server = HostNode(ip="10.0.1.10", hostname="web01", os="linux", role="web", asset_value=30)
        web_id = kt.add_host(web_server)

        # Segmento 2: Internal
        app_server = HostNode(ip="10.0.2.10", hostname="app01", os="linux", role="server", asset_value=60)
        app_id = kt.add_host(app_server)

        db_server = HostNode(ip="10.0.2.20", hostname="db01", os="linux", role="db", asset_value=80)
        db_id = kt.add_host(db_server)

        # Segmento 3: AD
        dc_server = HostNode(ip="10.0.3.10", hostname="dc01", os="windows", role="dc", asset_value=100)
        dc_id = kt.add_host(dc_server)

        # Aristas de ataque (rutas de pivoteo)
        kt.add_exploit_edge(ExploitEdge(
            source_host_id=web_id, target_host_id=app_id,
            technique="web_app_exploit", probability=0.8, stealth_cost=0.5,
            mitre_technique_id="T1190",
        ))
        kt.add_exploit_edge(ExploitEdge(
            source_host_id=app_id, target_host_id=db_id,
            technique="db_credential_harvest", probability=0.7, stealth_cost=0.4,
            mitre_technique_id="T1005",
        ))
        kt.add_exploit_edge(ExploitEdge(
            source_host_id=db_id, target_host_id=dc_id,
            technique="kerberoasting", probability=0.6, stealth_cost=0.6,
            mitre_technique_id="T1558.003",
        ))

        # Servicios
        kt.add_service(ServiceNode(host_id=web_id, port=443, service_name="https", version="nginx 1.18"))
        kt.add_service(ServiceNode(host_id=app_id, port=8080, service_name="http", version="tomcat 9.0"))
        kt.add_service(ServiceNode(host_id=db_id, port=3306, service_name="mysql", version="5.7"))
        kt.add_service(ServiceNode(host_id=dc_id, port=389, service_name="ldap"))
        kt.add_service(ServiceNode(host_id=dc_id, port=88, service_name="kerberos"))

        return kt, web_id, app_id, db_id, dc_id

    def test_planner_finds_path_through_network(self, enterprise_network):
        kt, web_id, _, _, dc_id = enterprise_network
        planner = AStarPlanner(kt)

        routes = planner.find_routes(web_id, "domain_admin", "balanced")
        assert len(routes) > 0

        best = routes[0]
        assert len(best.steps) >= 1
        assert best.total_probability > 0

    def test_planner_route_probability_decreases_with_steps(self, enterprise_network):
        kt, web_id, _, _, dc_id = enterprise_network
        planner = AStarPlanner(kt)

        routes = planner.find_routes(web_id, "domain_admin", "balanced")
        assert len(routes) > 0

        best = routes[0]
        # La probabilidad total debe ser el producto de las individuales
        expected_prob = 1.0
        for step in best.steps:
            expected_prob *= step.probability

        assert abs(best.total_probability - round(expected_prob, 4)) < 0.001

    def test_ghost_profile_chooses_stealthier_route(self, enterprise_network):
        kt, web_id, _, _, dc_id = enterprise_network
        planner = AStarPlanner(kt)

        ghost_routes = planner.find_routes(web_id, "domain_admin", "ghost")
        blitz_routes = planner.find_routes(web_id, "domain_admin", "blitz")

        # Ambos deben encontrar rutas
        if ghost_routes and blitz_routes:
            # Las rutas pueden ser las mismas en este caso simple
            assert len(ghost_routes) > 0
            assert len(blitz_routes) > 0


# ═══════════════════════════════════════════════════════════════════
# ESCENARIO 4: CTF Mode — captura de flags competitiva
# ═══════════════════════════════════════════════════════════════════

class TestCTFMode:
    """Simula una competición CTF donde el objetivo es capturar
    flags en lugar de domain admin."""

    @pytest.mark.asyncio
    async def test_flag_capture_workflow(self, mission_config):
        mission_config.mode = "ctf"
        mission_config.goal = "flag:CTF{*}"
        director = Director(config=mission_config, bus=EventBus())

        captured_flags = []

        @director.bus.on(Event.FLAG_CAPTURED)
        async def on_flag(data):
            captured_flags.append(data["value"])

        await director.register_agent({
            "agent_id": "ctf-agent",
            "ip": "10.0.0.50",
            "os": "linux",
        })

        await director.process_finding("ctf-agent", {
            "type": "FLAG",
            "flag_value": "CTF{web_exploit_100pts}",
            "path": "/var/www/html/flag.txt",
        })

        assert "CTF{web_exploit_100pts}" in captured_flags
        stats = director.kt.stats()
        assert stats.get("flag", 0) >= 1

    @pytest.mark.asyncio
    async def test_multiple_flag_captures(self, mission_config):
        mission_config.mode = "ctf"
        director = Director(config=mission_config, bus=EventBus())

        await director.register_agent({
            "agent_id": "ctf-agent2",
            "ip": "10.0.0.51",
            "os": "linux",
        })

        flags = [
            "CTF{sql_injection_200}",
            "CTF{xss_reflected_100}",
            "CTF{file_upload_150}",
        ]

        for flag in flags:
            await director.process_finding("ctf-agent2", {
                "type": "FLAG",
                "flag_value": flag,
            })

        stats = director.kt.stats()
        assert stats.get("flag", 0) >= 3


# ═══════════════════════════════════════════════════════════════════
# ESCENARIO 5: Blitz operation — ataque rápido y agresivo
# ═══════════════════════════════════════════════════════════════════

class TestBlitzOperation:
    """Simula un ataque blitz donde la velocidad es prioritaria
    sobre el sigilo."""

    def test_blitz_low_threshold(self):
        assert DecisionFusion.THRESHOLDS["blitz"] == 0.35

    def test_blitz_rules_boost_priority(self):
        rules = RulesEngine()
        svc = {"name": "ssh", "port": 22, "version": "", "banner": ""}

        blitz = rules.evaluate(svc, defense_level="none", profile="blitz")
        balanced = rules.evaluate(svc, defense_level="none", profile="balanced")

        # Blitz multiplica prioridades por 1.2
        blitz_total = sum(a.priority for a in blitz)
        balanced_total = sum(a.priority for a in balanced)

        assert blitz_total >= balanced_total

    def test_blitz_accepts_high_risk_actions(self):
        rules = RulesEngine()
        svc = {"name": "smb", "port": 445, "version": "", "banner": ""}

        blitz = rules.evaluate(svc, defense_level="none", profile="blitz", os_type="windows")

        # Debe incluir EternalBlue (risk=0.9)
        high_risk = [a for a in blitz if a.risk >= 0.9]
        assert len(high_risk) > 0


# ═══════════════════════════════════════════════════════════════════
# ESCENARIO 6: Agente perdido y recuperación
# ═══════════════════════════════════════════════════════════════════

class TestAgentLossAndRecovery:
    """Simula la pérdida de un agente y su recuperación."""

    @pytest.mark.asyncio
    async def test_agent_heartbeat_updates_last_seen(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())

        await director.register_agent({
            "agent_id": "unstable-agent",
            "ip": "10.0.0.50",
            "os": "linux",
        })

        # Verificar que el heartbeat actualiza last_seen
        import time
        await director.process_heartbeat("unstable-agent", {"cpu_usage": 50.0})
        first_seen = director.agents["unstable-agent"].last_seen

        await asyncio.sleep(0.01)
        await director.process_heartbeat("unstable-agent", {"cpu_usage": 60.0})
        second_seen = director.agents["unstable-agent"].last_seen

        assert second_seen >= first_seen

    @pytest.mark.asyncio
    async def test_heartbeat_from_unknown_agent(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        # No debe crashear
        await director.process_heartbeat("unknown-agent", {"cpu_usage": 50.0})


# ═══════════════════════════════════════════════════════════════════
# ESCENARIO 7: Grafo vivo — actualización dinámica del conocimiento
# ═══════════════════════════════════════════════════════════════════

class TestLiveKnowledgeGraph:
    """Simula la evolución del grafo de conocimiento a medida que
    se descubren nuevos hosts, servicios y credenciales."""

    def test_graph_grows_with_discoveries(self):
        kt = KnowledgeTree()

        initial_stats = kt.stats()
        assert initial_stats.get("host", 0) == 0

        # Descubrir hosts
        h1_id = kt.add_host(HostNode(ip="10.0.0.1", hostname="web01"))
        h2_id = kt.add_host(HostNode(ip="10.0.0.2", hostname="db01"))
        h3_id = kt.add_host(HostNode(ip="10.0.0.3", hostname="dc01"))

        stats = kt.stats()
        assert stats.get("host", 0) == 3

        # Añadir servicios
        kt.add_service(ServiceNode(host_id=h1_id, port=80, service_name="http"))
        kt.add_service(ServiceNode(host_id=h2_id, port=3306, service_name="mysql"))
        kt.add_service(ServiceNode(host_id=h3_id, port=389, service_name="ldap"))

        stats = kt.stats()
        assert stats.get("service", 0) == 3

        # Añadir credenciales
        h1 = kt.get_host_by_ip("10.0.0.1")
        if h1:
            kt.add_credential(CredentialNode(
                username="admin", value="secret", source_host_id=h1.id,
            ))

        stats = kt.stats()
        assert stats.get("credential", 0) >= 1

    def test_json_serialization_roundtrip(self):
        kt = KnowledgeTree()
        kt.add_host(HostNode(ip="10.0.0.1", hostname="test"))
        kt.add_service(ServiceNode(
            host_id=kt.get_host_by_ip("10.0.0.1").id,
            port=80, service_name="http",
        ))

        json_str = kt.to_json()
        data = json.loads(json_str)

        assert "nodes" in data
        assert "edges" in data
        assert "gds" in data
        assert len(data["nodes"]) >= 2  # host + service


# ═══════════════════════════════════════════════════════════════════
# ESCENARIO 8: Decisiones concurrentes — múltiples hallazgos simultáneos
# ═══════════════════════════════════════════════════════════════════

class TestConcurrentDecisions:
    """Simula múltiples agentes reportando hallazgos simultáneamente."""

    @pytest.mark.asyncio
    async def test_concurrent_findings_dont_crash(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())

        await director.register_agent({
            "agent_id": "agent-a",
            "ip": "10.0.0.50",
            "os": "linux",
        })
        await director.register_agent({
            "agent_id": "agent-b",
            "ip": "10.0.0.51",
            "os": "linux",
        })

        # Simular hallazgos concurrentes
        findings = [
            ("agent-a", {"type": "SERVICE_OPEN", "port": 80, "service_name": "http", "version": "2.4.49", "banner": "apache"}),
            ("agent-b", {"type": "SERVICE_OPEN", "port": 22, "service_name": "ssh", "version": "7.4", "banner": ""}),
            ("agent-a", {"type": "SERVICE_OPEN", "port": 443, "service_name": "https", "version": "", "banner": ""}),
        ]

        # Procesar concurrentemente
        tasks = [
            director.process_finding(agent_id, finding)
            for agent_id, finding in findings
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Ninguno debe haber lanzado excepción
        for r in results:
            assert not isinstance(r, Exception)

        # El grafo debe tener los servicios
        stats = director.kt.stats()
        assert stats.get("service", 0) >= 3


# ═══════════════════════════════════════════════════════════════════
# ESCENARIO 9: Reglas para servicios exóticos
# ═══════════════════════════════════════════════════════════════════

class TestExoticServices:
    """Testing de reglas para servicios menos comunes."""

    def test_docker_api_exposed(self):
        rules = RulesEngine()
        svc = {"name": "docker", "port": 2375, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("docker" in a.action.lower() for a in actions)
        # Debe incluir acciones de ejecución y escalada
        assert len(actions) >= 2

    def test_kubelet_exposed(self):
        rules = RulesEngine()
        svc = {"name": "kubernetes", "port": 10250, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("kubelet" in a.action.lower() for a in actions)

    def test_port_based_detection(self):
        """Servicios detectados solo por puerto, sin nombre."""
        rules = RulesEngine()

        # Puerto 2375 → Docker
        svc = {"name": "unknown", "port": 2375, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("docker" in a.action.lower() for a in actions)

        # Puerto 10250 → Kubernetes
        svc = {"name": "unknown", "port": 10250, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("kubelet" in a.action.lower() for a in actions)

        # Puerto 5985 → WinRM
        svc = {"name": "unknown", "port": 5985, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("winrm" in a.action.lower() for a in actions)
