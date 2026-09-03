"""
tests/test_remaining_modules.py
Tests for previously uncovered modules: grpc_server, cli, dashboard, main, cbr_seed, argos_console.
"""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


# ═══════════════════════════════════════════════════════════════════
# GRPC SERVER TESTS
# ═══════════════════════════════════════════════════════════════════

class TestGrpcHelpers:

    def test_finding_type_name(self):
        from api.grpc_server import ArgosAgentC2Servicer
        assert ArgosAgentC2Servicer._finding_type_name(0) == "HOST_DISCOVERED"
        assert ArgosAgentC2Servicer._finding_type_name(1) == "SERVICE_OPEN"
        assert ArgosAgentC2Servicer._finding_type_name(2) == "CREDENTIAL"
        assert ArgosAgentC2Servicer._finding_type_name(3) == "VULNERABILITY"
        assert ArgosAgentC2Servicer._finding_type_name(4) == "FLAG"
        assert ArgosAgentC2Servicer._finding_type_name(5) == "DEFENSE_DETECTED"
        assert ArgosAgentC2Servicer._finding_type_name(99) == "UNKNOWN"

    def test_event_to_finding_scan_result(self):
        from api.grpc_server import ArgosAgentC2Servicer
        from shared.proto import argos_pb2

        event = argos_pb2.AgentEvent()
        event.agent_id = "agent1"
        event.type = argos_pb2.SCAN_RESULT
        event.scan.target_ip = "10.0.0.1"
        svc = event.scan.services.add()
        svc.port = 80
        svc.protocol = "tcp"
        svc.name = "http"
        svc.banner = "Apache/2.4"
        svc.version = "2.4.41"

        finding = ArgosAgentC2Servicer._event_to_finding(event)
        assert finding is not None
        assert finding["type"] == "SERVICE_OPEN"
        assert finding["port"] == 80
        assert finding["service_name"] == "http"

    def test_event_to_finding_scan_no_services(self):
        from api.grpc_server import ArgosAgentC2Servicer
        from shared.proto import argos_pb2

        event = argos_pb2.AgentEvent()
        event.agent_id = "agent1"
        event.type = argos_pb2.SCAN_RESULT
        event.scan.target_ip = "10.0.0.1"
        # No services added

        finding = ArgosAgentC2Servicer._event_to_finding(event)
        assert finding is None

    def test_event_to_finding_exploit_result(self):
        from api.grpc_server import ArgosAgentC2Servicer
        from shared.proto import argos_pb2

        event = argos_pb2.AgentEvent()
        event.agent_id = "agent1"
        event.type = argos_pb2.EXPLOIT_RESULT
        event.exploit.success = True
        event.exploit.cve_or_technique = "CVE-2021-44228"
        event.exploit.session_id = "sess1"
        event.exploit.output = "got shell"

        finding = ArgosAgentC2Servicer._event_to_finding(event)
        assert finding["type"] == "EXPLOIT_SUCCESS"
        assert finding["technique"] == "CVE-2021-44228"

    def test_event_to_finding_exploit_failed(self):
        from api.grpc_server import ArgosAgentC2Servicer
        from shared.proto import argos_pb2

        event = argos_pb2.AgentEvent()
        event.agent_id = "agent1"
        event.type = argos_pb2.EXPLOIT_RESULT
        event.exploit.success = False
        event.exploit.cve_or_technique = "CVE-2021-44228"

        finding = ArgosAgentC2Servicer._event_to_finding(event)
        assert finding["type"] == "EXPLOIT_FAILED"

    def test_event_to_finding_credential(self):
        from api.grpc_server import ArgosAgentC2Servicer
        from shared.proto import argos_pb2

        event = argos_pb2.AgentEvent()
        event.agent_id = "agent1"
        event.type = argos_pb2.CREDENTIAL_FOUND
        event.cred.username = "admin"
        event.cred.type = "password"
        event.cred.value = "secret123"
        event.cred.scope = "10.0.0.1"

        finding = ArgosAgentC2Servicer._event_to_finding(event)
        assert finding["type"] == "CREDENTIAL"
        assert finding["username"] == "admin"

    def test_event_to_finding_flag(self):
        from api.grpc_server import ArgosAgentC2Servicer
        from shared.proto import argos_pb2

        event = argos_pb2.AgentEvent()
        event.agent_id = "agent1"
        event.type = argos_pb2.FLAG_CAPTURED
        event.flag.value = "CTF{test_flag}"
        event.flag.path = "/root/flag.txt"

        finding = ArgosAgentC2Servicer._event_to_finding(event)
        assert finding["type"] == "FLAG"
        assert finding["flag_value"] == "CTF{test_flag}"

    def test_event_to_finding_defense(self):
        from api.grpc_server import ArgosAgentC2Servicer
        from shared.proto import argos_pb2

        event = argos_pb2.AgentEvent()
        event.agent_id = "agent1"
        event.type = argos_pb2.DEFENSE_ALERT
        event.defense.type = "IDS"
        event.defense.name = "Snort"
        event.defense.severity = 3

        finding = ArgosAgentC2Servicer._event_to_finding(event)
        assert finding["type"] == "DEFENSE_DETECTED"
        assert finding["defense_name"] == "Snort"

    def test_event_to_finding_unknown_type(self):
        from api.grpc_server import ArgosAgentC2Servicer
        from shared.proto import argos_pb2

        event = argos_pb2.AgentEvent()
        event.agent_id = "agent1"
        event.type = 999  # Unknown type

        finding = ArgosAgentC2Servicer._event_to_finding(event)
        assert finding is None

    def test_dict_to_director_command_exploit(self):
        from api.grpc_server import ArgosAgentC2Servicer

        cmd = {
            "command_id": "cmd1",
            "type": "EXPLOIT",
            "action": "ms17_010",
            "target_host": "10.0.0.1",
            "cve": "CVE-2017-0144",
            "params": {"payload": "reverse_tcp"},
            "timeout": 60,
        }
        result = ArgosAgentC2Servicer._dict_to_director_command(cmd)
        assert result.command_id == "cmd1"
        assert result.type == 1  # EXPLOIT
        assert result.timeout_s == 60
        assert result.exploit_cmd.target_host == "10.0.0.1"
        assert result.exploit_cmd.technique == "ms17_010"

    def test_dict_to_director_command_scan(self):
        from api.grpc_server import ArgosAgentC2Servicer

        cmd = {
            "type": "SCAN",
            "params": {"target": "10.0.0.0/24", "ports": [22, 80]},
        }
        result = ArgosAgentC2Servicer._dict_to_director_command(cmd)
        assert result.type == 0  # SCAN
        assert result.scan_cmd.targets == ["10.0.0.0/24"]

    def test_dict_to_director_command_unknown_type(self):
        from api.grpc_server import ArgosAgentC2Servicer

        cmd = {"type": "UNKNOWN_TYPE", "command_id": "cmd2"}
        result = ArgosAgentC2Servicer._dict_to_director_command(cmd)
        assert result.command_id == "cmd2"
        assert result.type == 1  # Default to EXPLOIT

    def test_stringify_params_non_string_values(self):
        from api.grpc_server import ArgosAgentC2Servicer

        params = {
            "wordlist": "rockyou_top1000",                 # string → igual
            "port": 445,                                   # int → str
            "creds": [("root", "root"), ("admin", "admin")],  # list → JSON
        }
        out = ArgosAgentC2Servicer._stringify_params(params)
        assert out["wordlist"] == "rockyou_top1000"
        assert out["port"] == "445"
        assert isinstance(out["creds"], str)
        assert "root" in out["creds"]

    def test_dict_to_director_command_exploit_stringifies_params(self):
        from api.grpc_server import ArgosAgentC2Servicer

        cmd = {
            "type": "EXPLOIT",
            "action": "ssh_default_credentials",
            "target_host": "10.0.0.1",
            "params": {"creds": [("root", "root"), ("admin", "admin")]},
        }
        # No debe lanzar TypeError: los params del proto son map<string,string>
        result = ArgosAgentC2Servicer._dict_to_director_command(cmd)
        assert result.type == 1
        assert isinstance(result.exploit_cmd.params["creds"], str)

    def test_grpc_server_init(self):
        from api.grpc_server import GrpcServer

        director = MagicMock()
        server = GrpcServer(director, host="127.0.0.1", port=50052)
        assert server.host == "127.0.0.1"
        assert server.port == 50052
        assert server.director is director

    @pytest.mark.asyncio
    async def test_grpc_server_stop_without_start(self):
        from api.grpc_server import GrpcServer

        director = MagicMock()
        server = GrpcServer(director)
        server._server = None
        # Should not crash
        await server.stop()


# ═══════════════════════════════════════════════════════════════════
# CLI TESTS
# ═══════════════════════════════════════════════════════════════════

class TestCli:

    def test_cli_version(self):
        from ui.cli import cli
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "2.0.0" in result.output

    def test_cli_help(self):
        from ui.cli import cli
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "ARGOS" in result.output

    def test_status_no_mission(self, tmp_path):
        from ui.cli import cli
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--mission-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "No hay misión activa" in result.output

    def test_status_json_output(self, tmp_path):
        from ui.cli import cli
        from click.testing import CliRunner
        runner = CliRunner()
        state = {"gds": {"score": 0.5}, "agents": [], "phase": "recon"}
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(state))

        result = runner.invoke(cli, ["status", "--json", "--mission-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "gds" in result.output

    def test_status_text_output(self, tmp_path):
        from ui.cli import cli
        from click.testing import CliRunner
        runner = CliRunner()
        state = {"gds": {"score": 0.5}, "agents": [], "phase": "recon"}
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(state))

        result = runner.invoke(cli, ["status", "--mission-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "Misión" in result.output or "gds" in result.output.lower()

    def test_status_with_agents(self, tmp_path):
        from ui.cli import cli
        from click.testing import CliRunner
        runner = CliRunner()
        state = {
            "gds": {"score": 0.2},
            "agents": [{"id": "a1", "status": "active", "ip": "10.0.0.1"}],
            "phase": "exploitation",
        }
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(state))

        result = runner.invoke(cli, ["status", "--mission-dir", str(tmp_path)])
        assert result.exit_code == 0

    def test_print_banner(self):
        from ui.cli import print_banner
        # Should not crash
        print_banner()

    def test_dashboard_import_error(self):
        from ui.cli import cli
        from click.testing import CliRunner
        runner = CliRunner()
        with patch.dict(sys.modules, {"ui.dashboard": None}):
            result = runner.invoke(cli, ["dashboard"])
            assert result.exit_code == 0
            assert "Error" in result.output or "textual" in result.output.lower()


# ═══════════════════════════════════════════════════════════════════
# DASHBOARD TESTS
# ═══════════════════════════════════════════════════════════════════

class TestDashboard:

    def test_dashboard_class_exists(self):
        from ui.dashboard import ArgosDashboard
        assert ArgosDashboard is not None

    def test_dashboard_bindings(self):
        from ui.dashboard import ArgosDashboard
        # BINDINGS is a list of tuples: (key, action, description)
        binding_keys = [b[0] for b in ArgosDashboard.BINDINGS]
        assert "q" in binding_keys
        assert "r" in binding_keys
        assert "a" in binding_keys

    def test_agent_table_class(self):
        from ui.dashboard import AgentTable
        assert AgentTable is not None

    def test_host_table_class(self):
        from ui.dashboard import HostTable
        assert HostTable is not None

    def test_decision_queue_class(self):
        from ui.dashboard import DecisionQueue
        assert DecisionQueue is not None

    def test_gds_log_class(self):
        from ui.dashboard import GDSLog
        from textual.widgets import Log
        assert issubclass(GDSLog, Log)

    def test_dashboard_has_css(self):
        from ui.dashboard import ArgosDashboard
        assert ArgosDashboard.CSS is not None
        assert "Screen" in ArgosDashboard.CSS


# ═══════════════════════════════════════════════════════════════════
# CBR SEED TESTS
# ═══════════════════════════════════════════════════════════════════

class TestCBRSeedModule:

    def test_tactics_db_structure(self):
        from core.cbr_seed import TACTICS_DB
        assert len(TACTICS_DB) >= 4
        for tactic in TACTICS_DB:
            assert "description" in tactic
            assert "metadata" in tactic
            assert "technique" in tactic["metadata"]
            assert "port" in tactic["metadata"]
            assert "success_rate" in tactic["metadata"]

    def test_tactics_db_techniques(self):
        from core.cbr_seed import TACTICS_DB
        techniques = [t["metadata"]["technique"] for t in TACTICS_DB]
        assert "ms17_010_eternalblue" in techniques
        assert "ssh_bruteforce" in techniques
        assert "sql_injection" in techniques
        assert "kerberoasting" in techniques

    def test_seed_intelligence_cbr_disabled(self):
        from core import cbr_seed
        with patch.object(cbr_seed.CaseBasedReasoner, "__init__", return_value=None):
            # Mock the enabled property
            with patch.object(cbr_seed.CaseBasedReasoner, "enabled", False, create=True):
                # Should not crash, just log error
                cbr_seed.seed_intelligence()

    def test_tactics_db_ports(self):
        from core.cbr_seed import TACTICS_DB
        ports = [t["metadata"]["port"] for t in TACTICS_DB]
        assert 445 in ports  # SMB
        assert 22 in ports   # SSH
        assert 80 in ports   # HTTP
        assert 88 in ports   # Kerberos


# ═══════════════════════════════════════════════════════════════════
# ARGOS CONSOLE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestArgosConsole:

    def test_console_import(self):
        # Should import without crashing
        import argos_console
        assert hasattr(argos_console, "ArgosConsole")

    def test_console_class_exists(self):
        from argos_console import ArgosConsole
        # Basic check that the app can be instantiated
        assert ArgosConsole is not None

    def test_console_is_cmd_subclass(self):
        from argos_console import ArgosConsole
        import cmd
        assert issubclass(ArgosConsole, cmd.Cmd)

    def test_console_has_do_commands(self):
        from argos_console import ArgosConsole
        # Should have do_ methods for commands
        methods = [m for m in dir(ArgosConsole) if m.startswith("do_")]
        assert len(methods) > 0


# ═══════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT TESTS
# ═══════════════════════════════════════════════════════════════════

class TestMain:

    def test_main_import(self):
        # Should import without crashing
        import main
        assert hasattr(main, "__file__")

    def test_main_has_entry_points(self):
        import main
        # main.py should have main() and amain() functions
        assert hasattr(main, "main")
        assert hasattr(main, "amain")
        assert callable(main.main)
        assert hasattr(main.amain, "__call__") or hasattr(main.amain, "__wrapped__")
