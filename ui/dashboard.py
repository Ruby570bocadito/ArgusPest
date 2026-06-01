"""
ui/dashboard.py
───────────────
Terminal User Interface (TUI) para ARGOS usando Textual.
Proporciona una vista "hacker" en tiempo real del orquestador.
"""

import sqlite3
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Log, Static

# ─────────────────────────────────────────────────────────────────
# WIDGETS
# ─────────────────────────────────────────────────────────────────

class AgentTable(DataTable):
    """Tabla de Agentes Activos"""
    def on_mount(self) -> None:
        self.add_columns("ID", "IP", "OS", "Last Beacon", "Status")
        self.cursor_type = "row"
        self.zebra_stripes = True

class HostTable(DataTable):
    """Tabla de Hosts Descubiertos (Knowledge Tree)"""
    def on_mount(self) -> None:
        self.add_columns("Host ID", "IP", "OS", "Ports", "Owned")
        self.cursor_type = "row"
        self.zebra_stripes = True

class DecisionQueue(DataTable):
    """Cola de Decisiones Pendientes (HITL)"""
    def on_mount(self) -> None:
        self.add_columns("ID", "Target", "Action", "Confidence")
        self.cursor_type = "row"
        self.zebra_stripes = True

class GDSLog(Log):
    """Registro de eventos y Global Defense State"""
    pass

# ─────────────────────────────────────────────────────────────────
# APP MAIN
# ─────────────────────────────────────────────────────────────────

class ArgosDashboard(App):
    """App principal de la TUI de Argos."""

    CSS = """
    Screen {
        background: $surface;
    }
    #left-pane {
        width: 30%;
        border-right: vkey $primary;
    }
    #right-pane {
        width: 70%;
    }
    .panel-title {
        background: $primary;
        color: $text;
        text-align: center;
        text-style: bold;
        padding: 0 1;
    }
    DataTable {
        height: 100%;
        border: round $secondary;
    }
    GDSLog {
        height: 100%;
        border: round $error;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("a", "approve_decision", "Approve Decision"),
    ]

    def compose(self) -> ComposeResult:
        """Diseño visual del dashboard."""
        yield Header(show_clock=True)

        with Horizontal():
            # Panel Izquierdo: Agentes y Decisiones
            with Vertical(id="left-pane"):
                yield Static("🤖 AGENTS IN FIELD", classes="panel-title")
                self.agent_table = AgentTable(id="agents")
                yield self.agent_table

                yield Static("⚠️ DECISION QUEUE", classes="panel-title")
                self.decision_table = DecisionQueue(id="decisions")
                yield self.decision_table

            # Panel Derecho: Grafo de Hosts y Logs
            with Vertical(id="right-pane"):
                yield Static("🕸️ KNOWLEDGE TREE (HOSTS)", classes="panel-title")
                self.host_table = HostTable(id="hosts")
                yield self.host_table

                yield Static("🚨 GLOBAL DEFENSE STATE & LOGS", classes="panel-title")
                self.gds_log = GDSLog(id="logs")
                yield self.gds_log

        yield Footer()

    def on_mount(self) -> None:
        """Al iniciar, arrancar el actualizador en segundo plano."""
        self.title = "ARGOS - Semi-Autonomous Offensive Platform"
        self.db_path = Path("data/argos.db")
        self.gds_log.write_line("[SYSTEM] Inicializando Argos TUI Dashboard...")
        self.update_timer = self.set_interval(2.0, self.refresh_data)
        self.refresh_data()

    def refresh_data(self) -> None:
        """Lee la DB SQLite y actualiza las tablas (en prod usaríamos gRPC stream)."""
        if not self.db_path.exists():
            return

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # --- Agents ---
            self.agent_table.clear()
            cursor.execute("SELECT id, ip, os, last_seen, is_alive FROM agents")
            for row in cursor.fetchall():
                status = "🟢 Alive" if row[4] else "🔴 Dead"
                self.agent_table.add_row(row[0][:8], row[1], row[2], str(row[3])[:19], status)

            # --- Hosts ---
            self.host_table.clear()
            cursor.execute("SELECT id, ip, os, owned FROM hosts")
            for row in cursor.fetchall():
                owned = "🔥 YES" if row[3] else "❌ NO"
                self.host_table.add_row(row[0][:8], row[1], row[2], "...", owned)

            # --- Decisions ---
            self.decision_table.clear()
            cursor.execute("SELECT id, host_id, action, confidence FROM decisions WHERE approved IS NULL")
            for row in cursor.fetchall():
                conf = f"{row[3]*100:.1f}%" if row[3] else "N/A"
                self.decision_table.add_row(row[0][:8], row[1][:8], row[2], conf)

            conn.close()
        except Exception as e:
            self.gds_log.write_line(f"[ERROR] Error leyendo DB: {e}")

    def action_refresh(self) -> None:
        """Refrescar manualmente."""
        self.gds_log.write_line("[SYSTEM] Refresco manual solicitado...")
        self.refresh_data()

    def action_approve_decision(self) -> None:
        """Aprobar decisión seleccionada."""
        row_key = self.decision_table.cursor_coordinate
        if row_key is None:
            self.gds_log.write_line("[ACTION] No hay decisión seleccionada.")
            return

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            rows = cursor.execute(
                "SELECT id FROM decisions WHERE approved IS NULL ORDER BY created_at"
            ).fetchall()
            conn.close()

            idx = row_key.row
            if idx < len(rows):
                decision_id = rows[idx][0]
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE decisions SET approved = TRUE WHERE id = ?", (decision_id,)
                )
                conn.commit()
                conn.close()
                self.gds_log.write_line(f"[ACTION] Decisión {decision_id[:8]} APROBADA ✅")
                self.refresh_data()
            else:
                self.gds_log.write_line("[ACTION] Índice fuera de rango.")
        except Exception as e:
            self.gds_log.write_line(f"[ERROR] Fallo al aprobar: {e}")

if __name__ == "__main__":
    app = ArgosDashboard()
    app.run()
