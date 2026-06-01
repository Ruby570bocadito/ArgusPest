"""
tests/test_director.py
──────────────────────
Tests unitarios del Director y los componentes del Motor de Decisión.
Ejecutar: pytest tests/ -v
"""

from __future__ import annotations

import pytest

from core.cbr import CaseBasedReasoner
from core.decision_fusion import DecisionFusion
from core.director import Director, MissionConfig
from core.event_bus import Event, EventBus
from core.knowledge_tree import (
    CredentialNode,
    ExploitEdge,
    FlagNode,
    HostNode,
    KnowledgeTree,
    ServiceNode,
)
from core.planner import AStarPlanner
from core.rules_engine import RulesEngine

# ─────────────────────────── FIXTURES ────────────────────────────

@pytest.fixture
def kt():
    return KnowledgeTree()


@pytest.fixture
def populated_kt():
    """KnowledgeTree con varios hosts y servicios para tests."""
    tree = KnowledgeTree()

    h1 = HostNode(ip="10.0.0.1", hostname="attacker", os="linux", owned=True)
    h2 = HostNode(ip="10.0.0.10", hostname="web01", os="linux", asset_value=50)
    h3 = HostNode(ip="10.0.0.20", hostname="dc01", os="windows", role="dc", asset_value=100)

    id1 = tree.add_host(h1)
    id2 = tree.add_host(h2)
    id3 = tree.add_host(h3)

    # Servicios
    tree.add_service(ServiceNode(host_id=id2, port=80,  service_name="http", version="Apache 2.4.49"))
    tree.add_service(ServiceNode(host_id=id2, port=22,  service_name="ssh",  version="OpenSSH 7.4"))
    tree.add_service(ServiceNode(host_id=id3, port=445, service_name="smb"))
    tree.add_service(ServiceNode(host_id=id3, port=389, service_name="ldap"))

    # Aristas de explotación
    tree.add_exploit_edge(ExploitEdge(
        source_host_id=id1, target_host_id=id2,
        technique="apache_path_traversal", probability=0.9, stealth_cost=0.4,
    ))
    tree.add_exploit_edge(ExploitEdge(
        source_host_id=id2, target_host_id=id3,
        technique="smb_pass_the_hash", probability=0.7, stealth_cost=0.5,
    ))

    return tree, id1, id2, id3


@pytest.fixture
def rules():
    return RulesEngine()


@pytest.fixture
def cbr(tmp_path):
    # CBR con Qdrant en directorio temporal
    try:
        c = CaseBasedReasoner(db_path=str(tmp_path / "qdrant"))
        return c
    except Exception:
        return CaseBasedReasoner.__new__(CaseBasedReasoner)


@pytest.fixture
def mission_config(tmp_path):
    return MissionConfig(
        target     = "10.0.0.0/24",
        goal       = "domain_admin",
        profile    = "balanced",
        mode       = "pentest",
        output_dir = str(tmp_path),
    )


# ─────────────────────────── KNOWLEDGE TREE TESTS ────────────────

class TestKnowledgeTree:

    def test_add_host_deduplication(self, kt):
        h1 = HostNode(ip="192.168.1.1")
        h2 = HostNode(ip="192.168.1.1")  # Misma IP
        id1 = kt.add_host(h1)
        id2 = kt.add_host(h2)
        assert id1 == id2, "Hosts con misma IP deben deduplicarse"
        assert len(kt.get_all_hosts()) == 1

    def test_add_multiple_hosts(self, kt):
        for i in range(5):
            kt.add_host(HostNode(ip=f"10.0.0.{i}"))
        assert len(kt.get_all_hosts()) == 5

    def test_mark_owned(self, kt):
        h = HostNode(ip="10.0.0.5")
        hid = kt.add_host(h)
        kt.mark_owned(hid, "session-123", "agent-abc")
        host = kt.get_host_by_ip("10.0.0.5")
        assert host.owned is True
        assert "session-123" in host.sessions

    def test_add_service_linked_to_host(self, kt):
        h = HostNode(ip="10.0.0.1")
        hid = kt.add_host(h)
        svc = ServiceNode(host_id=hid, port=22, service_name="ssh")
        kt.add_service(svc)
        services = kt.get_services_for_host(hid)
        assert len(services) == 1
        assert services[0].port == 22

    def test_add_credential(self, kt):
        h = HostNode(ip="10.0.0.1")
        hid = kt.add_host(h)
        cred = CredentialNode(username="admin", value="password123", source_host_id=hid)
        kt.add_credential(cred)
        stats = kt.stats()
        assert stats.get("credential", 0) >= 1

    def test_add_flag(self, kt):
        h = HostNode(ip="10.0.0.1")
        hid = kt.add_host(h)
        flag = FlagNode(value="CTF{test_flag}", host_id=hid)
        kt.add_flag(flag)
        stats = kt.stats()
        assert stats.get("flag", 0) >= 1

    def test_gds_updates(self, kt):
        initial = kt.gds.score
        kt.gds.update("edr_alert")
        assert kt.gds.score > initial

    def test_gds_decay(self, kt):
        kt.gds.update("edr_alert")
        score_before = kt.gds.score
        kt.gds.decay()
        assert kt.gds.score < score_before

    def test_to_json(self, populated_kt):
        tree, _, _, _ = populated_kt
        import json
        data = json.loads(tree.to_json())
        assert "nodes" in data
        assert "edges" in data
        assert "gds" in data
        assert len(data["nodes"]) > 0

    def test_owned_hosts(self, kt):
        h1 = HostNode(ip="10.0.0.1")
        h2 = HostNode(ip="10.0.0.2")
        id1 = kt.add_host(h1)
        kt.add_host(h2)
        kt.mark_owned(id1, "sess", "agt")
        owned = kt.get_owned_hosts()
        assert len(owned) == 1
        assert owned[0].ip == "10.0.0.1"


# ─────────────────────────── PLANNER TESTS ───────────────────────

class TestAStarPlanner:

    def test_finds_route_to_dc(self, populated_kt):
        tree, id1, id2, id3 = populated_kt
        planner = AStarPlanner(tree)
        routes = planner.find_routes(id1, "domain_admin", "balanced")
        assert len(routes) > 0
        best = routes[0]
        assert best.total_probability > 0
        assert len(best.steps) > 0

    def test_no_route_to_unknown_host(self, populated_kt):
        tree, id1, _, _ = populated_kt
        planner = AStarPlanner(tree)
        routes = planner.find_routes(id1, "host:99.99.99.99", "balanced")
        assert routes == []

    def test_route_score_ordering(self, populated_kt):
        tree, id1, _, _ = populated_kt
        planner = AStarPlanner(tree)
        routes = planner.find_routes(id1, "domain_admin", "balanced", max_routes=5)
        scores = [r.score for r in routes]
        assert scores == sorted(scores, reverse=True), "Rutas deben estar ordenadas por score"

    def test_ghost_profile_penalizes_noise(self, populated_kt):
        tree, id1, _, _ = populated_kt
        planner = AStarPlanner(tree)
        ghost_routes   = planner.find_routes(id1, "domain_admin", "ghost")
        blitz_routes   = planner.find_routes(id1, "domain_admin", "blitz")
        if ghost_routes and blitz_routes:
            # Ghost debe preferir rutas más silenciosas
            assert ghost_routes[0].avg_stealth <= blitz_routes[0].avg_stealth + 0.1


# ─────────────────────────── RULES ENGINE TESTS ──────────────────

class TestRulesEngine:

    def test_ssh_rules_low_defense(self, rules):
        svc = {"name": "ssh", "port": 22, "version": "OpenSSH 7.4", "banner": ""}
        actions = rules.evaluate(svc, defense_level="none", profile="balanced")
        assert len(actions) > 0
        assert any(a.action == "ssh_default_credentials" for a in actions)

    def test_http_rules_apache_vuln(self, rules):
        svc = {"name": "http", "port": 80, "version": "2.4.49", "banner": "apache"}
        actions = rules.evaluate(svc, defense_level="none", profile="blitz")
        assert any("CVE-2021-41773" in a.action for a in actions)

    def test_smb_eternalblue_rule(self, rules):
        svc = {"name": "smb", "port": 445, "version": "", "banner": ""}
        actions = rules.evaluate(svc, defense_level="none", profile="blitz", os_type="windows")
        assert any("MS17-010" in a.action or "eternalblue" in a.action.lower() for a in actions)

    def test_ghost_profile_penalizes_noisy_actions(self, rules):
        svc = {"name": "ssh", "port": 22, "version": "", "banner": ""}
        ghost_actions   = rules.evaluate(svc, defense_level="none", profile="ghost")
        blitz_actions   = rules.evaluate(svc, defense_level="none", profile="blitz")
        # En ghost, la prioridad ajustada de acciones ruidosas debe ser menor
        if ghost_actions and blitz_actions:
            top_ghost = ghost_actions[0]
            top_blitz = blitz_actions[0]
            assert top_ghost.stealth >= top_blitz.stealth - 0.1

    def test_high_defense_reduces_priority(self, rules):
        svc = {"name": "ssh", "port": 22, "version": "", "banner": ""}
        low_def  = rules.evaluate(svc, defense_level="none",   profile="balanced")
        high_def = rules.evaluate(svc, defense_level="high",   profile="balanced")
        # Con defensa alta, la prioridad promedio debe ser menor
        avg_low  = sum(a.priority for a in low_def)  / max(len(low_def),  1)
        avg_high = sum(a.priority for a in high_def) / max(len(high_def), 1)
        assert avg_high <= avg_low

    def test_mysql_rules(self, rules):
        svc = {"name": "mysql", "port": 3306, "version": "5.7", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("mysql" in a.action.lower() for a in actions)

    def test_redis_rules(self, rules):
        svc = {"name": "redis", "port": 6379, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("redis" in a.action.lower() for a in actions)

    def test_ldap_kerberoasting(self, rules):
        svc = {"name": "ldap", "port": 389, "version": "", "banner": ""}
        actions = rules.evaluate(svc)
        assert any("kerberoast" in a.action.lower() for a in actions)


# ─────────────────────────── CBR TESTS ───────────────────────────

class TestCBR:

    def test_add_and_query_case(self, cbr):
        if not cbr.enabled:
            pytest.skip("Qdrant/SentenceTransformers no disponibles")
        cbr.add_case("Apache 2.4.49 en Ubuntu, puerto 80", "path_traversal_CVE", True)
        results = cbr.query_similar("Apache HTTP server puerto 80")
        assert len(results) > 0

    def test_weighted_score_success_boost(self, cbr):
        if not cbr.enabled:
            pytest.skip("Qdrant/SentenceTransformers no disponibles")
        cbr.add_case("SSH OpenSSH 7.4, puerto 22", "brute_force", True,  {"score": 1.0})
        cbr.add_case("SSH OpenSSH 7.4, puerto 22", "other_action", False, {"score": 1.0})
        results = cbr.query_similar("SSH 7.4")
        # El caso exitoso debe tener mayor weighted_score
        success_cases = [r for r in results if r["success"]]
        failed_cases  = [r for r in results if not r["success"]]
        if success_cases and failed_cases:
            assert success_cases[0]["weighted_score"] > failed_cases[0]["weighted_score"]


# ─────────────────────────── DECISION FUSION TESTS ───────────────

class TestDecisionFusion:

    def test_fusion_produces_decision(self, populated_kt, cbr):
        tree, id1, id2, _ = populated_kt
        planner = AStarPlanner(tree)
        rules   = RulesEngine()
        fusion  = DecisionFusion(planner, cbr, rules)

        svc = {"name": "http", "port": 80, "version": "Apache 2.4.49", "banner": "apache"}
        decision = fusion.fuse(svc, id1, "domain_admin", "balanced")

        assert decision.action != ""
        assert 0.0 <= decision.confidence <= 1.0
        assert isinstance(decision.needs_approval, bool)

    def test_ghost_profile_requires_approval_more_often(self, populated_kt, cbr):
        tree, id1, _, _ = populated_kt
        planner = AStarPlanner(tree)
        rules   = RulesEngine()
        fusion  = DecisionFusion(planner, cbr, rules)

        svc = {"name": "ssh", "port": 22, "version": "", "banner": ""}
        ghost_dec   = fusion.fuse(svc, id1, "domain_admin", "ghost")
        blitz_dec   = fusion.fuse(svc, id1, "domain_admin", "blitz")

        # Ghost tiene umbral mayor → más probable que pida aprobación
        if ghost_dec.confidence == blitz_dec.confidence:
            assert ghost_dec.needs_approval or not blitz_dec.needs_approval

    def test_no_candidates_returns_manual_intervention(self, kt, cbr):
        planner = AStarPlanner(kt)   # Grafo vacío
        rules   = RulesEngine()
        fusion  = DecisionFusion(planner, cbr, rules)

        svc = {"name": "unknown_service_xyz", "port": 9999, "version": "", "banner": ""}
        decision = fusion.fuse(svc, "nonexistent_host", "domain_admin", "balanced")
        # Con grafo vacío, el planificador no aporta; depende de reglas
        assert decision.action != ""


# ─────────────────────────── DIRECTOR TESTS ──────────────────────

class TestDirector:

    @pytest.mark.asyncio
    async def test_register_agent(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        ack = await director.register_agent({
            "agent_id": "test-agent-001",
            "hostname": "victim01",
            "ip":       "10.0.0.50",
            "os":       "linux",
            "arch":     "amd64",
        })
        assert ack["success"] is True
        assert ack["mission_id"] == mission_config.mission_id
        assert "test-agent-001" in director.agents

    @pytest.mark.asyncio
    async def test_process_finding_service_creates_node(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        await director.register_agent({
            "agent_id": "agent-002",
            "ip":       "10.0.0.51",
            "os":       "linux",
        })
        await director.process_finding("agent-002", {
            "type":         "SERVICE_OPEN",
            "port":         22,
            "protocol":     "tcp",
            "service_name": "ssh",
            "banner":       "OpenSSH 7.4",
            "version":      "7.4",
        })
        stats = director.kt.stats()
        assert stats.get("service", 0) >= 1

    @pytest.mark.asyncio
    async def test_process_finding_flag(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        await director.register_agent({"agent_id": "agent-003", "ip": "10.0.0.52"})
        captured_flags = []

        @director.bus.on(Event.FLAG_CAPTURED)
        async def on_flag(data):
            captured_flags.append(data["value"])

        await director.process_finding("agent-003", {
            "type":       "FLAG",
            "flag_value": "CTF{test_flag_1234}",
        })
        assert "CTF{test_flag_1234}" in captured_flags

    @pytest.mark.asyncio
    async def test_decision_queue(self, mission_config):
        mission_config.auto_decide = False
        director = Director(config=mission_config, bus=EventBus())
        await director.register_agent({"agent_id": "agent-004", "ip": "10.0.0.53"})
        await director.process_finding("agent-004", {
            "type":         "SERVICE_OPEN",
            "port":         22,
            "service_name": "ssh",
            "version":      "7.4",
            "banner":       "",
        })
        # Puede haber 0 decisiones si la confianza es suficientemente alta
        pending = director.list_pending_decisions()
        assert isinstance(pending, list)

    @pytest.mark.asyncio
    async def test_approve_decision(self, mission_config):
        mission_config.auto_decide = False
        director = Director(config=mission_config, bus=EventBus())
        await director.register_agent({"agent_id": "agent-005", "ip": "10.0.0.54"})
        await director.process_finding("agent-005", {
            "type": "SERVICE_OPEN", "port": 445,
            "service_name": "smb", "version": "", "banner": "",
        })
        pending = director.list_pending_decisions()
        if pending:
            did = pending[0]["decision_id"]
            await director.approve_decision(did)
            assert director.decisions[did].approved is True

    def test_status_output(self, mission_config):
        director = Director(config=mission_config, bus=EventBus())
        status = director.status()
        assert "mission_id" in status
        assert "gds"        in status
        assert "running"    in status
        assert status["mission_id"] == mission_config.mission_id


# ─────────────────────────── GDS TESTS ───────────────────────────

class TestGlobalDefenseState:

    def test_kill_switch_triggered_at_threshold(self):
        from core.knowledge_tree import GlobalDefenseState
        gds = GlobalDefenseState()
        triggered = []
        gds.register_listener(lambda e: triggered.append(e))

        # Forzar score cercano al umbral
        gds.score = 0.89
        gds.update("honeypot_detected")   # +0.60 → >0.90

        assert gds.score >= gds.KILL_THRESHOLD
        assert "KILL_SWITCH" in triggered

    def test_score_clamps_to_one(self):
        from core.knowledge_tree import GlobalDefenseState
        gds = GlobalDefenseState()
        for _ in range(10):
            gds.update("honeypot_detected")
        assert gds.score <= 1.0

    def test_score_cannot_go_below_zero(self):
        from core.knowledge_tree import GlobalDefenseState
        gds = GlobalDefenseState()
        for _ in range(20):
            gds.decay()
        assert gds.score >= 0.0
