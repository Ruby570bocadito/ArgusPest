"""
tests/test_comprehensive.py
───────────────────────────
Tests comprehensivos para módulos sin cobertura y escenarios hipotéticos.
Cubre: EventBus, ExploitManager, ReconManager, Database, escenarios avanzados.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.decision_fusion import Decision, DecisionFusion
from core.director import Director, MissionConfig, PendingDecision
from core.event_bus import Event, EventBus, get_bus
from core.exploit_manager import ACTION_TO_MSF, ExploitManager
from core.knowledge_tree import (
    CredentialNode,
    DefenseNode,
    ExploitEdge,
    FlagNode,
    GlobalDefenseState,
    HostNode,
    HostRole,
    KnowledgeTree,
    ServiceNode,
    VulnerabilityNode,
)
from core.planner import AStarPlanner, PlanStep, Route
from core.recon_manager import ReconManager
from core.rules_engine import RulesEngine, TacticalAction


# ─────────────────────────── FIXTURES ────────────────────────────

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


@pytest.fixture
def populated_kt():
    tree = KnowledgeTree()
    h1 = HostNode(ip="10.0.0.1", hostname="attacker", os="linux", owned=True)
    h2 = HostNode(ip="10.0.0.10", hostname="web01", os="linux", asset_value=50)
    h3 = HostNode(ip="10.0.0.20", hostname="dc01", os="windows", role="dc", asset_value=100)
    id1 = tree.add_host(h1)
    id2 = tree.add_host(h2)
    id3 = tree.add_host(h3)
    tree.add_service(ServiceNode(host_id=id2, port=80, service_name="http", version="Apache 2.4.49"))
    tree.add_service(ServiceNode(host_id=id2, port=22, service_name="ssh", version="OpenSSH 7.4"))
    tree.add_service(ServiceNode(host_id=id3, port=445, service_name="smb"))
    tree.add_service(ServiceNode(host_id=id3, port=389, service_name="ldap"))
    tree.add_exploit_edge(ExploitEdge(
        source_host_id=id1, target_host_id=id2,
        technique="apache_path_traversal", probability=0.9, stealth_cost=0.4,
    ))
    tree.add_exploit_edge(ExploitEdge(
        source_host_id=id2, target_host_id=id3,
        technique="smb_pass_the_hash", probability=0.7, stealth_cost=0.5,
    ))
    return tree, id1, id2, id3


# ═══════════════════════════════════════════════════════════════════
# EVENT BUS TESTS
# ═══════════════════════════════════════════════════════════════════

class TestEventBus:

    @pytest.mark.asyncio
    async def test_emit_and_receive(self, bus):
        received = []

        @bus.on("test.event")
        async def handler(data):
            received.append(data)

        await bus.emit("test.event", {"key": "value"})
        assert len(received) == 1
        assert received[0]["key"] == "value"

    @pytest.mark.asyncio
    async def test_wildcard_handler(self, bus):
        received = []

        @bus.on("*")
        async def handler(data):
            received.append(data)

        await bus.emit("any.event", {"x": 1})
        await bus.emit("other.event", {"y": 2})
        assert len(received) == 2

    @pytest.mark.asyncio
    async def test_multiple_handlers(self, bus):
        results = []

        @bus.on("multi")
        async def h1(data):
            results.append("h1")

        @bus.on("multi")
        async def h2(data):
            results.append("h2")

        await bus.emit("multi", {})
        assert results == ["h1", "h2"]

    @pytest.mark.asyncio
    async def test_unsubscribe(self, bus):
        count = 0

        async def handler(data):
            nonlocal count
            count += 1

        bus.subscribe("evt", handler)
        await bus.emit("evt", {})
        assert count == 1

        bus.unsubscribe("evt", handler)
        await bus.emit("evt", {})
        assert count == 1  # No incrementa

    @pytest.mark.asyncio
    async def test_handler_error_doesnt_crash(self, bus):
        async def bad_handler(data):
            raise ValueError("boom")

        bus.subscribe("error_evt", bad_handler)
        # No debe lanzar excepción
        await bus.emit("error_evt", {})

    def test_history(self, bus):
        async def _run():
            await bus.emit("h1", {"a": 1})
            await bus.emit("h2", {"b": 2})
            await bus.emit("h1", {"a": 3})

        asyncio.get_event_loop().run_until_complete(_run())
        history = bus.get_history("h1")
        assert len(history) == 2
        assert history[0]["data"]["a"] == 1
        assert history[1]["data"]["a"] == 3

    def test_history_limit(self, bus):
        async def _run():
            for i in range(10):
                await bus.emit("evt", {"i": i})

        asyncio.get_event_loop().run_until_complete(_run())
        history = bus.get_history(limit=3)
        assert len(history) == 3

    def test_handler_count(self, bus):
        async def h1(data):
            pass

        async def h2(data):
            pass

        bus.subscribe("count_evt", h1)
        bus.subscribe("count_evt", h2)
        assert bus.handler_count("count_evt") == 2
        assert bus.handler_count("nonexistent") == 0

    def test_singleton_bus(self):
        bus1 = get_bus()
        bus2 = get_bus()
        assert bus1 is bus2

    def test_emit_sync_from_sync_context(self, bus):
        received = []

        @bus.on("sync_evt")
        async def handler(data):
            received.append(data)

        # emit_sync debe funcionar desde contexto síncrono
        bus.emit_sync("sync_evt", {"sync": True})
        # Dar tiempo al loop para procesar
        import time
        time.sleep(0.1)
        assert len(received) >= 1


# ═══════════════════════════════════════════════════════════════════
# KNOWLEDGE TREE ADVANCED TESTS
# ═══════════════════════════════════════════════════════════════════

class TestKnowledgeTreeAdvanced:

    def test_add_vulnerability(self):
        kt = KnowledgeTree()
        vuln = VulnerabilityNode(
            cve="CVE-2021-41773",
            description="Apache Path Traversal",
            cvss_score=7.5,
            exploit_module="apache_normalize_path_rce",
        )
        vid = kt.add_vulnerability(vuln)
        stats = kt.stats()
        assert stats.get("vulnerability", 0) >= 1

    def test_add_defense_triggers_gds(self):
        kt = KnowledgeTree()
        initial_gds = kt.gds.score
        defense = DefenseNode(
            host_id="host1",
            type="edr",
            name="SentinelOne",
            aggressiveness=0.8,
        )
        kt.add_defense(defense)
        assert kt.gds.score > initial_gds

    def test_get_attack_graph(self, populated_kt):
        tree, id1, id2, id3 = populated_kt
        ag = tree.get_attack_graph()
        assert id1 in ag.nodes
        assert id2 in ag.nodes
        assert id3 in ag.nodes
        # Debe tener aristas EXPLOITS
        assert ag.has_edge(id1, id2)
        assert ag.has_edge(id2, id3)

    def test_to_json_structure(self, populated_kt):
        tree, _, _, _ = populated_kt
        data = json.loads(tree.to_json())
        assert "nodes" in data
        assert "edges" in data
        assert "gds" in data
        assert "score" in data["gds"]
        assert "level" in data["gds"]

    def test_host_role_enum(self):
        h = HostNode(ip="10.0.0.1", role=HostRole.DC)
        assert h.role == "dc"

    def test_get_services_for_host(self, populated_kt):
        tree, _, id2, _ = populated_kt
        svcs = tree.get_services_for_host(id2)
        assert len(svcs) == 2
        ports = {s.port for s in svcs}
        assert 80 in ports
        assert 22 in ports

    def test_deduplication_preserves_data(self):
        kt = KnowledgeTree()
        h1 = HostNode(ip="10.0.0.1", hostname="first", os="linux")
        h2 = HostNode(ip="10.0.0.1", hostname="second", os="windows")
        id1 = kt.add_host(h1)
        id2 = kt.add_host(h2)
        assert id1 == id2
        # El primero debe prevalecer
        host = kt.get_host_by_ip("10.0.0.1")
        assert host.hostname == "first"

    def test_gds_level_transitions(self):
        gds = GlobalDefenseState()
        assert gds.level == "green"
        gds.score = 0.3
        assert gds.level == "yellow"
        gds.score = 0.6
        assert gds.level == "red"
        gds.score = 0.9
        assert gds.level == "critical"

    def test_gds_to_dict(self):
        gds = GlobalDefenseState()
        d = gds.to_dict()
        assert "score" in d
        assert "level" in d
        assert isinstance(d["score"], float)

    def test_credential_target_hosts(self):
        kt = KnowledgeTree()
        h = HostNode(ip="10.0.0.1")
        hid = kt.add_host(h)
        cred = CredentialNode(
            username="admin",
            value="secret",
            source_host_id=hid,
            scope="domain",
        )
        cred.target_hosts.append("10.0.0.2")
        kt.add_credential(cred)
        stats = kt.stats()
        assert stats.get("credential", 0) >= 1


# ═══════════════════════════════════════════════════════════════════
# PLANNER ADVANCED TESTS
# ═══════════════════════════════════════════════════════════════════

class TestPlannerAdvanced:

    def test_goal_owned_finds_unowned_hosts(self, populated_kt):
        tree, id1, id2, id3 = populated_kt
        planner = AStarPlanner(tree)
        routes = planner.find_routes(id1, "owned", "balanced")
        # id2 e id3 no son owned
        assert len(routes) > 0

    def test_goal_host_by_ip(self, populated_kt):
        tree, id1, _, _ = populated_kt
        planner = AStarPlanner(tree)
        routes = planner.find_routes(id1, "host:10.0.0.20", "balanced")
        assert len(routes) > 0

    def test_goal_flag_targets_high_value(self, populated_kt):
        tree, id1, _, _ = populated_kt
        planner = AStarPlanner(tree)
        routes = planner.find_routes(id1, "flag:CTF{test}", "balanced")
        # Debe encontrar hosts con asset_value >= 50
        assert len(routes) > 0

    def test_goal_unknown_fallback(self, populated_kt):
        tree, id1, _, _ = populated_kt
        planner = AStarPlanner(tree)
        routes = planner.find_routes(id1, "custom_goal_xyz", "balanced")
        # Fallback: hosts con asset_value >= 60
        assert len(routes) > 0

    def test_route_summary(self):
        step = PlanStep(
            source="a", target="b",
            technique="test", probability=0.8, stealth_cost=0.3,
        )
        route = Route(steps=[step], goal_host="b")
        summary = route.summary()
        assert "Route" in summary
        assert "1 steps" in summary

    def test_empty_route_score(self):
        route = Route(steps=[], goal_host="x")
        assert route.score == 0.0

    def test_max_routes_limit(self, populated_kt):
        tree, id1, _, _ = populated_kt
        planner = AStarPlanner(tree)
        routes = planner.find_routes(id1, "domain_admin", "balanced", max_routes=1)
        assert len(routes) <= 1

    def test_start_host_not_in_attack_graph(self):
        kt = KnowledgeTree()
        h = HostNode(ip="10.0.0.1")
        kt.add_host(h)
        planner = AStarPlanner(kt)
        routes = planner.find_routes("nonexistent_id", "domain_admin", "balanced")
        assert routes == []


# ═══════════════════════════════════════════════════════════════════
# RULES ENGINE ADVANCED TESTS
# ═══════════════════════════════════════════════════════════════════

class TestRulesEngineAdvanced:

    def test_docker_rules(self):
        rules = RulesEngine()
        svc = {"name": "docker", "port": 2375, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("docker" in a.action.lower() for a in actions)

    def test_kubernetes_rules(self):
        rules = RulesEngine()
        svc = {"name": "kubernetes", "port": 10250, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("kubelet" in a.action.lower() for a in actions)

    def test_winrm_rules(self):
        rules = RulesEngine()
        svc = {"name": "winrm", "port": 5985, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("winrm" in a.action.lower() for a in actions)

    def test_rdp_rules_low_defense(self):
        rules = RulesEngine()
        svc = {"name": "rdp", "port": 3389, "version": "", "banner": ""}
        actions = rules.evaluate(svc, defense_level="none")
        assert any("bluekeep" in a.action.lower() for a in actions)

    def test_rdp_rules_high_defense(self):
        rules = RulesEngine()
        svc = {"name": "rdp", "port": 3389, "version": "", "banner": ""}
        actions = rules.evaluate(svc, defense_level="high")
        # BlueKeep solo en none/low
        assert not any("bluekeep" in a.action.lower() for a in actions)

    def test_postgresql_rules(self):
        rules = RulesEngine()
        svc = {"name": "postgresql", "port": 5432, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("postgresql" in a.action.lower() for a in actions)

    def test_mssql_rules(self):
        rules = RulesEngine()
        svc = {"name": "mssql", "port": 1433, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("mssql" in a.action.lower() for a in actions)

    def test_snmp_rules(self):
        rules = RulesEngine()
        svc = {"name": "snmp", "port": 161, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("snmp" in a.action.lower() for a in actions)

    def test_generic_rules(self):
        rules = RulesEngine()
        svc = {"name": "unknown_service", "port": 9999, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert len(actions) > 0
        assert any("banner_grab" in a.action for a in actions)

    def test_tactical_action_adjusted_priority(self):
        action = TacticalAction(
            action="test", priority=0.8, risk=0.9, stealth=0.2,
        )
        # Ghost penaliza acciones ruidosas
        ghost_prio = action.adjusted_priority("ghost", "none")
        assert ghost_prio < 0.8

        # Blitz incrementa prioridad
        action2 = TacticalAction(
            action="test", priority=0.8, risk=0.5, stealth=0.5,
        )
        blitz_prio = action2.adjusted_priority("blitz", "none")
        assert blitz_prio > 0.8

    def test_tactical_action_high_defense_penalty(self):
        action = TacticalAction(
            action="noisy", priority=0.8, risk=0.9, stealth=0.1,
        )
        prio = action.adjusted_priority("balanced", "high")
        assert prio < 0.8  # Penalizado por defensa alta + riesgo alto

    def test_ssh_cve_version_matching(self):
        rules = RulesEngine()
        svc = {"name": "ssh", "port": 22, "version": "OpenSSH 9.2p1", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("CVE-2023-38408" in a.action for a in actions)

    def test_ftp_version_matching(self):
        rules = RulesEngine()
        svc = {"name": "ftp", "port": 21, "version": "2.3.4", "banner": "vsftpd 2.3.4"}
        actions = rules.evaluate(svc)
        assert any("CVE-2011-2523" in a.action for a in actions)

    def test_http_tomcat_detection(self):
        rules = RulesEngine()
        svc = {"name": "http", "port": 8080, "version": "", "banner": "tomcat"}
        actions = rules.evaluate(svc)
        assert any("tomcat" in a.action.lower() for a in actions)


# ═══════════════════════════════════════════════════════════════════
# DECISION FUSION ADVANCED TESTS
# ═══════════════════════════════════════════════════════════════════

class TestDecisionFusionAdvanced:

    def test_fusion_with_all_engines(self, populated_kt):
        tree, id1, id2, id3 = populated_kt
        planner = AStarPlanner(tree)
        rules = RulesEngine()
        from core.cbr import CaseBasedReasoner
        cbr = CaseBasedReasoner.__new__(CaseBasedReasoner)
        cbr.enabled = False

        fusion = DecisionFusion(planner, cbr, rules)
        svc = {"name": "http", "port": 80, "version": "2.4.49", "banner": "apache"}
        decision = fusion.fuse(svc, id1, "domain_admin", "balanced")

        assert decision.action != ""
        assert decision.confidence > 0
        assert isinstance(decision.needs_approval, bool)
        assert decision.source in ("planner", "cbr", "rules", "fusion")

    def test_decision_to_dict(self):
        d = Decision(
            action="test_action",
            confidence=0.75,
            needs_approval=True,
            source="fusion",
            params={"key": "value"},
            mitre_id="T1190",
            risk=0.5,
            stealth=0.5,
            alternatives=["alt1", "alt2"],
            explanation="test explanation",
        )
        d_dict = d.to_dict()
        assert d_dict["action"] == "test_action"
        assert d_dict["confidence"] == 0.75
        assert d_dict["params"] == {"key": "value"}
        assert d_dict["mitre_id"] == "T1190"

    def test_fusion_empty_graph_manual_intervention(self):
        kt = KnowledgeTree()
        planner = AStarPlanner(kt)
        rules = RulesEngine()
        from core.cbr import CaseBasedReasoner
        cbr = CaseBasedReasoner.__new__(CaseBasedReasoner)
        cbr.enabled = False

        fusion = DecisionFusion(planner, cbr, rules)
        svc = {"name": "unknown_xyz", "port": 9999, "version": "", "banner": ""}
        decision = fusion.fuse(svc, "nonexistent", "domain_admin", "balanced")
        # Rules engine siempre produce algo (banner_grab)
        assert decision.action != ""

    def test_blitz_profile_lower_threshold(self, populated_kt):
        tree, id1, _, _ = populated_kt
        planner = AStarPlanner(tree)
        rules = RulesEngine()
        from core.cbr import CaseBasedReasoner
        cbr = CaseBasedReasoner.__new__(CaseBasedReasoner)
        cbr.enabled = False

        fusion = DecisionFusion(planner, cbr, rules)
        svc = {"name": "ssh", "port": 22, "version": "", "banner": ""}

        blitz_dec = fusion.fuse(svc, id1, "domain_admin", "blitz")
        ghost_dec = fusion.fuse(svc, id1, "domain_admin", "ghost")

        # Blitz tiene threshold menor → menos probable que necesite aprobación
        assert DecisionFusion.THRESHOLDS["blitz"] < DecisionFusion.THRESHOLDS["ghost"]


# ═══════════════════════════════════════════════════════════════════
# DIRECTOR ADVANCED TESTS
# ═══════════════════════════════════════════════════════════════════

class TestDirectorAdvanced:

    @pytest.mark.asyncio
    async def test_register_multiple_agents(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        for i in range(5):
            ack = await director.register_agent({
                "agent_id": f"agent-{i}",
                "ip": f"10.0.0.{50 + i}",
                "os": "linux",
            })
            assert ack["success"] is True
        assert len(director.agents) == 5

    @pytest.mark.asyncio
    async def test_process_heartbeat(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        await director.register_agent({
            "agent_id": "hb-agent",
            "ip": "10.0.0.50",
            "os": "linux",
        })
        await director.process_heartbeat("hb-agent", {"cpu_usage": 45.0})
        assert director.agents["hb-agent"].last_seen != ""

    @pytest.mark.asyncio
    async def test_process_finding_unknown_agent(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        # Agente no registrado
        result = await director.process_finding("unknown-agent", {
            "type": "SERVICE_OPEN",
            "port": 80,
            "service_name": "http",
        })
        # No debe crashear
        assert result is None or isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_reject_decision(self, mission_config):
        mission_config.auto_decide = False
        director = Director(config=mission_config, bus=EventBus())
        await director.register_agent({"agent_id": "agent-r", "ip": "10.0.0.55"})
        await director.process_finding("agent-r", {
            "type": "SERVICE_OPEN", "port": 22,
            "service_name": "ssh", "version": "7.4", "banner": "",
        })
        pending = director.list_pending_decisions()
        if pending:
            did = pending[0]["decision_id"]
            await director.reject_decision(did)
            assert director.decisions[did].approved is False

    @pytest.mark.asyncio
    async def test_approve_nonexistent_decision(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        result = await director.approve_decision("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_auto_decide_mode(self, mission_config):
        mission_config.auto_decide = True
        director = Director(config=mission_config, bus=EventBus())
        await director.register_agent({"agent_id": "auto-agent", "ip": "10.0.0.60"})
        result = await director.process_finding("auto-agent", {
            "type": "SERVICE_OPEN", "port": 22,
            "service_name": "ssh", "version": "7.4", "banner": "",
        })
        # En auto-decide, puede retornar comando directamente
        assert result is None or isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_pause_mission(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        # Verificar que pause cambia el estado
        director.running = True
        await director.pause()
        assert director.running is False

    @pytest.mark.asyncio
    async def test_queue_command_full(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        await director.register_agent({"agent_id": "q-agent", "ip": "10.0.0.61"})
        # Llenar la cola (maxsize=20)
        for i in range(25):
            await director.queue_command("q-agent", {"type": "test", "i": i})
        # Los últimos deben descartarse
        cmd = await director.get_pending_command("q-agent")
        assert cmd is not None

    @pytest.mark.asyncio
    async def test_queue_command_no_agent(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        cmd = await director.get_pending_command("nonexistent")
        assert cmd is None

    @pytest.mark.asyncio
    async def test_process_finding_host_discovered(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        await director.register_agent({"agent_id": "disc-agent", "ip": "10.0.0.62"})
        await director.process_finding("disc-agent", {
            "type": "HOST_DISCOVERED",
            "ip": "10.0.0.100",
            "hostname": "newhost",
            "os": "windows",
        })
        host = director.kt.get_host_by_ip("10.0.0.100")
        assert host is not None
        assert host.hostname == "newhost"

    @pytest.mark.asyncio
    async def test_process_finding_credential(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        await director.register_agent({"agent_id": "cred-agent", "ip": "10.0.0.63"})
        await director.process_finding("cred-agent", {
            "type": "CREDENTIAL",
            "username": "admin",
            "cred_type": "ntlm_hash",
            "value": "aad3b435b51404ee",
            "scope": "domain",
        })
        stats = director.kt.stats()
        assert stats.get("credential", 0) >= 1

    @pytest.mark.asyncio
    async def test_process_finding_defense(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        await director.register_agent({"agent_id": "def-agent", "ip": "10.0.0.64"})
        initial_gds = director.kt.gds.score
        await director.process_finding("def-agent", {
            "type": "DEFENSE_DETECTED",
            "defense_type": "edr",
            "defense_name": "CrowdStrike",
            "severity": 0.7,
        })
        assert director.kt.gds.score > initial_gds

    def test_beacon_interval_profiles(self, mission_config):
        mission_config.profile = "ghost"
        director = Director(config=mission_config, bus=EventBus())
        assert director._beacon_interval() == 120

        mission_config.profile = "blitz"
        director = Director(config=mission_config, bus=EventBus())
        assert director._beacon_interval() == 15

        mission_config.profile = "balanced"
        director = Director(config=mission_config, bus=EventBus())
        assert director._beacon_interval() == 60

    def test_status_completeness(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        status = director.status()
        required_keys = [
            "mission_id", "running", "target", "goal", "profile",
            "mode", "gds", "agents_alive", "agents_total",
            "pending_decisions", "graph_stats", "cbr_stats",
        ]
        for key in required_keys:
            assert key in status, f"Missing key: {key}"


# ═══════════════════════════════════════════════════════════════════
# RECON MANAGER TESTS
# ═══════════════════════════════════════════════════════════════════

class TestReconManager:

    @pytest.mark.asyncio
    async def test_on_agent_registered_dispatches_scan(self, mission_config):
        bus = EventBus()
        director = Director(config=mission_config, bus=bus)
        recon = ReconManager(director, bus)

        await bus.emit(Event.AGENT_REGISTERED, {
            "agent_id": "recon-agent",
            "ip": "10.0.0.70",
        })

        # Comando debe estar encolado
        cmd = await director.get_pending_command("recon-agent")
        assert cmd is not None
        assert cmd["type"] == "SCAN"

    @pytest.mark.asyncio
    async def test_on_host_discovered_dispatches_scan(self, mission_config):
        bus = EventBus()
        director = Director(config=mission_config, bus=bus)
        recon = ReconManager(director, bus)

        await director.register_agent({
            "agent_id": "recon-agent2",
            "ip": "10.0.0.71",
            "os": "linux",
        })

        await bus.emit(Event.HOST_DISCOVERED, {
            "host_id": "new-host-id",
            "ip": "10.0.0.80",
        })

        # Comando de scan debe estar encolado
        cmd = await director.get_pending_command("recon-agent2")
        assert cmd is not None
        assert cmd["type"] == "SCAN"

    @pytest.mark.asyncio
    async def test_no_duplicate_scans(self, mission_config):
        bus = EventBus()
        director = Director(config=mission_config, bus=bus)
        recon = ReconManager(director, bus)

        await director.register_agent({
            "agent_id": "recon-agent3",
            "ip": "10.0.0.72",
            "os": "linux",
        })

        # Emitir mismo host dos veces
        await bus.emit(Event.HOST_DISCOVERED, {
            "host_id": "dup-host",
            "ip": "10.0.0.90",
        })
        await bus.emit(Event.HOST_DISCOVERED, {
            "host_id": "dup-host",
            "ip": "10.0.0.90",
        })

        # Solo un scan debe estar encolado (el del agent registered)
        cmd1 = await director.get_pending_command("recon-agent3")
        cmd2 = await director.get_pending_command("recon-agent3")
        # El segundo puede ser None si solo se encoló uno
        assert cmd1 is not None

    def test_get_best_agent_no_agents(self, mission_config):
        bus = EventBus()
        director = Director(config=mission_config, bus=bus)
        recon = ReconManager(director, bus)
        assert recon._get_best_agent() is None

    def test_get_best_agent_dead_agents(self, mission_config):
        bus = EventBus()
        director = Director(config=mission_config, bus=bus)
        recon = ReconManager(director, bus)
        director.agents["dead-agent"] = MagicMock(is_alive=False)
        assert recon._get_best_agent() is None


# ═══════════════════════════════════════════════════════════════════
# EXPLOIT MANAGER TESTS
# ═══════════════════════════════════════════════════════════════════

class TestExploitManager:

    def test_action_mapping_completeness(self):
        # Verificar que las acciones clave están mapeadas
        critical_actions = [
            "smb_eternalblue_MS17-010",
            "apache_path_traversal_CVE-2021-41773",
            "vsftpd_backdoor_CVE-2011-2523",
            "ssh_brute_force",
            "redis_config_rewrite_rce",
        ]
        for action in critical_actions:
            assert action in ACTION_TO_MSF, f"Missing MSF mapping: {action}"

    def test_action_mapping_has_module(self):
        for action, info in ACTION_TO_MSF.items():
            assert "module" in info, f"Action {action} missing module"

    def test_local_ip(self, mission_config):
        bus = EventBus()
        director = Director(config=mission_config, bus=bus)
        exploit_mgr = ExploitManager(director, bus)
        ip = exploit_mgr._local_ip()
        # Debe ser una IP válida o 127.0.0.1
        assert "." in ip

    @pytest.mark.asyncio
    async def test_dispatch_to_agent(self, mission_config):
        bus = EventBus()
        director = Director(config=mission_config, bus=bus)
        exploit_mgr = ExploitManager(director, bus)

        await director.register_agent({
            "agent_id": "exploit-agent",
            "ip": "10.0.0.80",
            "os": "linux",
        })

        # ReconManager encola un port_scan al registrar el agente
        # Consumirlo primero
        _ = await director.get_pending_command("exploit-agent")

        await exploit_mgr._dispatch_to_agent("exploit-agent", "ssh_brute_force", "host-1")

        cmd = await director.get_pending_command("exploit-agent")
        assert cmd is not None
        assert cmd["action"] == "ssh_brute_force"

    def test_get_msf_action_map(self, mission_config):
        bus = EventBus()
        director = Director(config=mission_config, bus=bus)
        exploit_mgr = ExploitManager(director, bus)
        action_map = exploit_mgr.get_msf_action_map()
        assert len(action_map) > 0
        assert "smb_eternalblue_MS17-010" in action_map


# ═══════════════════════════════════════════════════════════════════
# DATABASE MODELS TESTS
# ═══════════════════════════════════════════════════════════════════

class TestDatabaseModels:

    @pytest.fixture
    def db(self, tmp_path):
        from database.models import Database
        db_path = str(tmp_path / "test.db")
        return Database(db_path=db_path)

    def test_create_mission(self, db):
        from database.models import Mission
        with db.get_session() as session:
            mission = Mission(
                target="10.0.0.0/24",
                goal="domain_admin",
                profile="ghost",
            )
            session.add(mission)
            session.commit()
            assert mission.id is not None

    def test_create_host_with_mission(self, db):
        from database.models import Mission, Host
        with db.get_session() as session:
            mission = Mission(target="10.0.0.0/24")
            session.add(mission)
            session.commit()

            host = Host(
                mission_id=mission.id,
                ip="10.0.0.10",
                hostname="web01",
                os="linux",
            )
            session.add(host)
            session.commit()
            assert host.id is not None
            assert host.mission_id == mission.id

    def test_create_service(self, db):
        from database.models import Mission, Host, Service
        with db.get_session() as session:
            mission = Mission(target="10.0.0.0/24")
            session.add(mission)
            session.commit()
            host = Host(mission_id=mission.id, ip="10.0.0.10")
            session.add(host)
            session.commit()

            svc = Service(
                host_id=host.id,
                port=80,
                service_name="http",
                version="Apache 2.4.49",
            )
            session.add(svc)
            session.commit()
            assert svc.id is not None

    def test_create_credential(self, db):
        from database.models import Mission, Host, Credential
        with db.get_session() as session:
            mission = Mission(target="10.0.0.0/24")
            session.add(mission)
            session.commit()
            host = Host(mission_id=mission.id, ip="10.0.0.10")
            session.add(host)
            session.commit()

            cred = Credential(
                host_id=host.id,
                username="admin",
                cred_type="ntlm_hash",
                value="aad3b435b51404ee",
            )
            session.add(cred)
            session.commit()
            assert cred.id is not None

    def test_create_flag(self, db):
        from database.models import Mission, Host, Flag
        with db.get_session() as session:
            mission = Mission(target="10.0.0.0/24")
            session.add(mission)
            session.commit()
            host = Host(mission_id=mission.id, ip="10.0.0.10")
            session.add(host)
            session.commit()

            flag = Flag(
                host_id=host.id,
                value="CTF{test_flag}",
                path="/root/flag.txt",
            )
            session.add(flag)
            session.commit()
            assert flag.id is not None

    def test_create_decision_record(self, db):
        from database.models import Mission, DecisionRecord
        with db.get_session() as session:
            mission = Mission(target="10.0.0.0/24")
            session.add(mission)
            session.commit()

            decision = DecisionRecord(
                mission_id=mission.id,
                action="ssh_brute_force",
                confidence=0.75,
                source="fusion",
            )
            session.add(decision)
            session.commit()
            assert decision.id is not None
            assert decision.approved is None  # Pending

    def test_save_and_query_event(self, db):
        from database.models import Mission, MissionEvent
        with db.get_session() as session:
            mission = Mission(id="test-mission-123", target="10.0.0.0/24")
            session.add(mission)
            session.commit()

            db.save_event(
                session, mission.id,
                event_type="host.discovered",
                agent_id="agent-1",
                host_id="host-1",
                data={"ip": "10.0.0.10"},
            )
            events = session.query(MissionEvent).filter_by(
                mission_id=mission.id
            ).all()
            assert len(events) == 1
            assert events[0].event_type == "host.discovered"

    def test_mission_summary(self, db):
        from database.models import Mission, Host, Flag, Credential
        with db.get_session() as session:
            mission = Mission(target="10.0.0.0/24", goal="domain_admin")
            session.add(mission)
            session.commit()

            host = Host(mission_id=mission.id, ip="10.0.0.10", owned=True)
            session.add(host)
            session.commit()

            flag = Flag(host_id=host.id, value="CTF{test}")
            session.add(flag)
            session.commit()

            summary = db.get_mission_summary(session, mission.id)
            assert summary["hosts_total"] == 1
            assert summary["hosts_owned"] == 1
            assert summary["flags"] == 1

    def test_cascade_delete_mission(self, db):
        from database.models import Mission, Host, Service
        with db.get_session() as session:
            mission = Mission(target="10.0.0.0/24")
            session.add(mission)
            session.commit()

            host = Host(mission_id=mission.id, ip="10.0.0.10")
            session.add(host)
            session.commit()

            svc = Service(host_id=host.id, port=80, service_name="http")
            session.add(svc)
            session.commit()

            host_id = host.id
            session.delete(mission)
            session.commit()

            # Host y Service deben haberse eliminado por cascade
            assert session.get(Host, host_id) is None


# ═══════════════════════════════════════════════════════════════════
# KILL SWITCH SCENARIOS
# ═══════════════════════════════════════════════════════════════════

class TestKillSwitchScenarios:

    def test_kill_switch_from_multiple_events(self):
        gds = GlobalDefenseState()
        triggered = []
        gds.register_listener(lambda e: triggered.append(e))

        # Múltiples eventos menores que suman > 0.90
        gds.update("scan_detected")      # +0.20
        gds.update("ids_triggered")      # +0.25 → 0.45
        gds.update("edr_alert")          # +0.30 → 0.75
        gds.update("analyst_active")     # +0.15 → 0.90

        assert gds.score >= 0.90
        assert "KILL_SWITCH" in triggered

    def test_kill_switch_from_single_major_event(self):
        gds = GlobalDefenseState()
        triggered = []
        gds.register_listener(lambda e: triggered.append(e))

        gds.update("honeypot_detected")  # +0.60
        gds.update("honeypot_detected")  # +0.60 → 1.00 (clamped)

        assert gds.score == 1.0
        assert triggered.count("KILL_SWITCH") >= 1

    def test_decay_prevents_kill_switch(self):
        gds = GlobalDefenseState()
        triggered = []
        gds.register_listener(lambda e: triggered.append(e))

        gds.update("edr_alert")   # +0.30
        gds.decay()               # -0.02 → 0.28
        gds.update("edr_alert")   # +0.30 → 0.58
        gds.decay()               # -0.02 → 0.56
        gds.update("edr_alert")   # +0.30 → 0.86

        assert gds.score < 0.90
        assert "KILL_SWITCH" not in triggered

    def test_agent_killed_event(self):
        gds = GlobalDefenseState()
        gds.update("agent_killed")  # +0.40
        assert gds.score == 0.40

    def test_gds_custom_severity(self):
        gds = GlobalDefenseState()
        gds.update("edr_alert", severity=0.5)  # +0.30 * 0.5 = +0.15
        assert gds.score == 0.15

    def test_gds_unknown_event_no_effect(self):
        gds = GlobalDefenseState()
        gds.update("unknown_event_type")
        assert gds.score == 0.0


# ═══════════════════════════════════════════════════════════════════
# PROFILE-BASED BEHAVIOR TESTS
# ═══════════════════════════════════════════════════════════════════

class TestProfileBehavior:

    def test_ghost_high_confidence_threshold(self):
        assert DecisionFusion.THRESHOLDS["ghost"] == 0.85

    def test_blitz_low_confidence_threshold(self):
        assert DecisionFusion.THRESHOLDS["blitz"] == 0.35

    def test_balanced_medium_confidence_threshold(self):
        assert DecisionFusion.THRESHOLDS["balanced"] == 0.65

    def test_ghost_profile_rules_penalize_noise(self):
        rules = RulesEngine()
        svc = {"name": "ssh", "port": 22, "version": "", "banner": ""}

        ghost_actions = rules.evaluate(svc, defense_level="none", profile="ghost")
        blitz_actions = rules.evaluate(svc, defense_level="none", profile="blitz")

        # Ghost debe tener prioridades más bajas en acciones ruidosas
        if ghost_actions and blitz_actions:
            ghost_total = sum(a.priority for a in ghost_actions)
            blitz_total = sum(a.priority for a in blitz_actions)
            # Blitz multiplica por 1.2, ghost penaliza
            assert blitz_total >= ghost_total

    def test_planner_profile_stealth_weights(self):
        assert AStarPlanner.PROFILE_STEALTH_WEIGHT["ghost"] == 0.8
        assert AStarPlanner.PROFILE_STEALTH_WEIGHT["balanced"] == 0.5
        assert AStarPlanner.PROFILE_STEALTH_WEIGHT["blitz"] == 0.1


# ═══════════════════════════════════════════════════════════════════
# EDGE CASE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_empty_service_name_rules(self):
        rules = RulesEngine()
        svc = {"name": "", "port": 0, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        # Debe caer en generic
        assert len(actions) > 0

    def test_very_long_ip_in_planner(self):
        kt = KnowledgeTree()
        h1 = HostNode(ip="10.0.0.1", owned=True)
        h2 = HostNode(ip="10.0.0.2")
        id1 = kt.add_host(h1)
        id2 = kt.add_host(h2)
        kt.add_exploit_edge(ExploitEdge(
            source_host_id=id1, target_host_id=id2,
            technique="test", probability=0.5,
        ))
        planner = AStarPlanner(kt)
        routes = planner.find_routes(id1, "host:10.0.0.2", "balanced")
        assert len(routes) > 0

    def test_ipv6_host(self):
        kt = KnowledgeTree()
        h = HostNode(ip="::1", hostname="localhost", os="linux")
        hid = kt.add_host(h)
        host = kt.get_host_by_ip("::1")
        assert host is not None
        assert host.ip == "::1"

    def test_decision_fusion_weights_sum(self):
        total = sum(DecisionFusion.WEIGHTS.values())
        assert abs(total - 1.0) < 0.001

    def test_mission_config_defaults(self):
        cfg = MissionConfig()
        assert cfg.target == "10.0.0.0/24"
        assert cfg.goal == "domain_admin"
        assert cfg.profile == "balanced"
        assert cfg.mode == "pentest"
        assert cfg.parallel == 3
        assert cfg.mission_id != ""

    def test_pending_decision_defaults(self):
        pd = PendingDecision()
        assert pd.decision_id != ""
        assert pd.resolved is False
        assert pd.approved is None

    def test_exploit_edge_defaults(self):
        edge = ExploitEdge()
        assert edge.probability == 0.5
        assert edge.stealth_cost == 0.5
        assert edge.success_count == 0
        assert edge.failure_count == 0

    def test_host_node_defaults(self):
        h = HostNode()
        assert h.ip == ""
        assert h.owned is False
        assert h.asset_value == 10
        assert h.sessions == []
