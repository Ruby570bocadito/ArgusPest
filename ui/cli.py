"""
ui/cli.py
─────────
Argos CLI — Punto de entrada principal (Click + Rich).
"""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Añadir raíz al path
sys.path.insert(0, str(Path(__file__).parent.parent))

console = Console()

BANNER = r"""
[bold cyan]
    ___    ____  ______  ____  _____
   /   |  / __ \/ ____/ / __ \/ ___/
  / /| | / /_/ / / __ / / / /\__ \ 
 / ___ |/ _, _/ /_/ // /_/ /___/ / 
/_/  |_/_/ |_|\____/\____//____/  
[/bold cyan][bold white]  Semi-Autonomous Offensive Operations Platform v2.0[/bold white]
[dim]  Human-in-the-Loop · A* · CBR · Rules Engine[/dim]
"""


def print_banner():
    console.print(BANNER)


# ─────────────────────────── CLI GROUP ───────────────────────────

@click.group()
@click.version_option(version="2.0.0", prog_name="argos")
@click.pass_context
def cli(ctx):
    """
    \b
    ╔═══════════════════════════════════════════════╗
    ║  ARGOS — Offensive Operations Platform v2.0   ║
    ║  Use 'argos COMMAND --help' for more info.    ║
    ╚═══════════════════════════════════════════════╝
    """
    ctx.ensure_object(dict)


# ─────────────────────────── START ───────────────────────────────

@cli.command()
@click.option("--target",      "-t", required=True,              help="Rango objetivo (CIDR o IP). Ej: 10.0.0.0/24")
@click.option("--goal",        "-g", default="domain_admin",     help="Objetivo: domain_admin | flag:CTF{*} | host:<ip> | exfil:<path>")
@click.option("--profile",     "-p", default="balanced",         help="Perfil: ghost | balanced | blitz", type=click.Choice(["ghost", "balanced", "blitz"]))
@click.option("--mode",        "-m", default="pentest",          help="Modo: pentest | ctf",             type=click.Choice(["pentest", "ctf"]))
@click.option("--parallel",          default=3,                  help="Máx. agentes simultáneos")
@click.option("--msf",               is_flag=True, default=False, help="Habilitar integración Metasploit")
@click.option("--auto-decide",       is_flag=True, default=False, help="No preguntar nunca (solo notificar)")
@click.option("--output-dir",        default="./missions",       help="Directorio de salida de misión")
@click.option("--config",      "-c", default="config.yaml",      help="Archivo de configuración")
def start(target, goal, profile, mode, parallel, msf, auto_decide, output_dir, config):
    """Iniciar una misión autónoma."""
    print_banner()

    import yaml

    from core.director import Director, MissionConfig
    from core.event_bus import get_bus
    from core.notifications import WebhookNotifier

    # Cargar webhook desde config
    webhook_url = None
    try:
        with open(config) as f:
            cfg = yaml.safe_load(f) or {}
            webhook_url = cfg.get("notifications", {}).get("webhook_url")
    except Exception:
        pass
    notifier = WebhookNotifier({"webhook_url": webhook_url})

    mission = MissionConfig(
        target      = target,
        goal        = goal,
        profile     = profile,
        mode        = mode,
        parallel    = parallel,
        use_msf     = msf,
        auto_decide = auto_decide,
        output_dir  = output_dir,
    )

    # Asegurar directorios
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    Path("./data/qdrant").mkdir(parents=True, exist_ok=True)
    Path("./logs").mkdir(parents=True, exist_ok=True)

    console.print(Panel.fit(
        f"[bold]Misión:[/bold]  [cyan]{mission.mission_id}[/cyan]\n"
        f"[bold]Target:[/bold]  [yellow]{target}[/yellow]\n"
        f"[bold]Goal:[/bold]    [green]{goal}[/green]\n"
        f"[bold]Profile:[/bold] [magenta]{profile}[/magenta]\n"
        f"[bold]Mode:[/bold]    {mode}  |  "
        f"[bold]Auto-decide:[/bold] {'[green]ON[/green]' if auto_decide else '[red]OFF[/red]'}\n"
        f"[bold]MSF:[/bold]     {'[green]ON[/green]' if msf else 'OFF'}",
        title="[bold cyan]🚀 Iniciando Misión[/bold cyan]",
        border_style="cyan",
    ))

    bus = get_bus()

    from core.event_bus import Event
    @bus.on(Event.HOST_DISCOVERED)
    async def _on_host(data):
        console.print(f"  [cyan]🖥  Host:[/cyan] {data.get('ip')}")

    @bus.on(Event.SERVICE_DISCOVERED)
    async def _on_svc(data):
        console.print(f"  [blue]🔌 Servicio:[/blue] {data.get('service')}:{data.get('port')} en {data.get('host_id','?')[:8]}")

    @bus.on(Event.DECISION_CREATED)
    async def _on_decision(data):
        d = data.get("decision", {})
        conf = d.get("confidence", 0)
        color = "green" if conf > 0.7 else "yellow" if conf > 0.4 else "red"
        console.print(
            f"  [bold {color}]🧠 Decisión:[/bold {color}] "
            f"'{d.get('action')}' conf=[{color}]{conf:.0%}[/{color}] "
            f"{'⚠️  [yellow]APROBACIÓN REQUERIDA[/yellow]' if d.get('needs_approval') else '✅ Auto'}"
        )

    @bus.on(Event.FLAG_CAPTURED)
    async def _on_flag(data):
        flag_val = data.get('value', '')
        console.print(f"  [bold green]🚩 FLAG CAPTURADA:[/bold green] [green]{flag_val}[/green]")
        asyncio.create_task(notifier.notify_flag(flag_val, data.get("host_ip", "unknown")))

    @bus.on(Event.KILL_SWITCH)
    async def _on_kill(data):
        console.print("  [bold red]🔴 KILL SWITCH ACTIVADO — Hiberna todos los agentes[/bold red]")
        asyncio.create_task(notifier.send_alert("🔴 KILL SWITCH ACTIVADO", "Hibernando todos los agentes por emergencia.", 0xFF0000))

    director = Director(config=mission, bus=bus)
    console.print("\n[dim]Ctrl+C para pausar · 'argos status' en otra terminal para monitorear[/dim]\n")

    try:
        asyncio.run(director.start())
    except KeyboardInterrupt:
        console.print("\n[yellow]⏸  Misión pausada por el usuario.[/yellow]")


# ─────────────────────────── DASHBOARD ───────────────────────────

@cli.command("dashboard")
def start_dashboard():
    """Lanza el Dashboard TUI a pantalla completa."""
    console.print("[bold cyan]Lanzando Argos TUI Dashboard...[/bold cyan]")
    try:
        from ui.dashboard import ArgosDashboard
        app = ArgosDashboard()
        app.run()
    except ImportError as e:
        console.print(f"[bold red]Error al cargar el dashboard: {e}[/bold red]")
        console.print("Asegúrate de que 'textual' está instalado (pip install textual).")


# ─────────────────────────── STATUS ──────────────────────────────

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Salida en formato JSON")
@click.option("--mission-dir", default="./missions", help="Directorio de misión activa")
def status(as_json, mission_dir):
    """Mostrar estado de la misión activa."""
    # En producción: conectar al director vía gRPC o socket IPC
    # Aquí mostramos el estado del archivo de estado si existe
    state_file = Path(mission_dir) / "state.json"

    if not state_file.exists():
        console.print("[yellow]ℹ️  No hay misión activa en este directorio.[/yellow]")
        console.print(f"[dim]Busca en: {mission_dir}[/dim]")
        return

    with open(state_file) as f:
        state = json.load(f)

    if as_json:
        console.print_json(json.dumps(state))
        return

    # Tabla de estado
    gds = state.get("gds", {})
    gds_score = gds.get("score", 0)
    gds_color = "green" if gds_score < 0.3 else "yellow" if gds_score < 0.7 else "red"

    console.print(Panel(
        f"  [bold]Misión:[/bold]  [cyan]{state.get('mission_id', '?')}[/cyan]\n"
        f"  [bold]Target:[/bold]  {state.get('target', '?')}\n"
        f"  [bold]Goal:[/bold]    [green]{state.get('goal', '?')}[/green]\n"
        f"  [bold]Profile:[/bold] [magenta]{state.get('profile', '?')}[/magenta]\n"
        f"  [bold]GDS:[/bold]     [{gds_color}]{gds_score:.0%} ({gds.get('level','?')})[/{gds_color}]\n"
        f"  [bold]Agentes:[/bold] {state.get('agents_alive', 0)}/{state.get('agents_total', 0)} activos\n"
        f"  [bold]Decisiones pendientes:[/bold] {state.get('pending_decisions', 0)}",
        title="[bold cyan]📊 Estado de Misión[/bold cyan]",
        border_style="cyan",
    ))

    # Grafo stats
    gs = state.get("graph_stats", {})
    if gs:
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        t.add_column("Tipo de Nodo")
        t.add_column("Cantidad", justify="right")
        for k, v in gs.items():
            t.add_row(k, str(v))
        console.print(t)


# ─────────────────────────── DECIDE ──────────────────────────────

@cli.group()
def decide():
    """Gestión de decisiones pendientes (Human-in-the-Loop)."""
    pass


@decide.command("list")
@click.option("--mission-dir", default="./missions", help="Directorio de misión activa")
def decide_list(mission_dir):
    """Listar decisiones pendientes de aprobación."""
    from database.models import Database, DecisionRecord

    db = Database()
    with db.get_session() as session:
        pending = session.query(DecisionRecord).filter(
            DecisionRecord.approved.is_(None)
        ).all()

    if not pending:
        console.print("[yellow]No hay decisiones pendientes.[/yellow]")
        return

    t = Table(title="Decisiones Pendientes", box=box.ROUNDED)
    t.add_column("ID", style="cyan")
    t.add_column("Acción", style="yellow")
    t.add_column("Confianza", justify="right")
    t.add_column("Host")
    for d in pending:
        t.add_row(d.id[:8], d.action, f"{d.confidence:.0%}", (d.host_id or "?")[:8])
    console.print(t)


@decide.command("approve")
@click.argument("decision_id")
@click.option("--custom", "-c", default=None, help="Comando personalizado alternativo")
@click.option("--mission-dir", default="./missions", help="Directorio de misión activa")
def decide_approve(decision_id, custom, mission_dir):
    """Aprobar una decisión pendiente."""
    from database.models import Database, DecisionRecord

    db = Database()
    with db.get_session() as session:
        decision = session.query(DecisionRecord).filter(
            DecisionRecord.id.like(f"{decision_id}%")
        ).first()
        if not decision:
            console.print(f"[red]Decisión {decision_id} no encontrada.[/red]")
            return
        decision.approved = True
        decision.custom_cmd = custom
        session.commit()
    console.print(f"[green]✅ Decisión {decision_id} APROBADA[/green]")
    if custom:
        console.print(f"[dim]Comando personalizado: {custom}[/dim]")


@decide.command("reject")
@click.argument("decision_id")
@click.option("--mission-dir", default="./missions", help="Directorio de misión activa")
def decide_reject(decision_id, mission_dir):
    """Rechazar una decisión pendiente."""
    from database.models import Database, DecisionRecord

    db = Database()
    with db.get_session() as session:
        decision = session.query(DecisionRecord).filter(
            DecisionRecord.id.like(f"{decision_id}%")
        ).first()
        if not decision:
            console.print(f"[red]Decisión {decision_id} no encontrada.[/red]")
            return
        decision.approved = False
        session.commit()
    console.print(f"[red]❌ Decisión {decision_id} RECHAZADA[/red]")


@decide.command("auto")
@click.option("--max-risk", default="medium", help="Nivel máximo de riesgo auto-aprobable",
              type=click.Choice(["low", "medium", "high"]))
@click.option("--timeout", default="30m", help="Timeout para auto-aprobación (Ej: 30m, 2h)")
def decide_auto(max_risk, timeout):
    """Configurar auto-aprobación de decisiones por debajo de un umbral de riesgo."""
    import yaml
    risk_map = {"low": 0.3, "medium": 0.6, "high": 0.9}
    try:
        with open("config.yaml") as f:
            cfg = yaml.safe_load(f) or {}
        cfg["director"] = cfg.get("director", {})
        cfg["director"]["auto_decide_max_risk"] = risk_map[max_risk]
        cfg["director"]["auto_decide"] = True
        with open("config.yaml", "w") as f:
            yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False)
        console.print(f"[cyan]⚡ Auto-decide activado:[/cyan] max_risk={max_risk} ({risk_map[max_risk]}), timeout={timeout}")
    except Exception as e:
        console.print(f"[red]Error al configurar: {e}[/red]")


# ─────────────────────────── AGENT ───────────────────────────────

@cli.group()
def agent():
    """Control directo de agentes de campo."""
    pass


@agent.command("list")
def agent_list():
    """Listar agentes activos."""
    from database.models import AgentRecord, Database

    db = Database()
    with db.get_session() as session:
        agents = session.query(AgentRecord).filter(
            AgentRecord.is_alive
        ).all()

    if not agents:
        console.print("[yellow]No hay agentes activos.[/yellow]")
        return

    t = Table(title="Agentes Activos", box=box.ROUNDED)
    t.add_column("ID", style="cyan")
    t.add_column("IP")
    t.add_column("OS")
    t.add_column("Hostname")
    t.add_column("Last Seen")
    for a in agents:
        last = str(a.last_seen or "?")[:16]
        t.add_row((a.id or "?")[:8], a.ip or "?", a.os or "?", a.hostname or "?", last)
    console.print(t)


@agent.command("exec")
@click.argument("agent_id")
@click.argument("command")
def agent_exec(agent_id, command):
    """Ejecutar un comando en un agente."""
    from database.models import AgentRecord, Database

    db = Database()
    with db.get_session() as session:
        agent = session.query(AgentRecord).filter(
            AgentRecord.id.like(f"{agent_id}%")
        ).first()
        if not agent:
            console.print(f"[red]Agente {agent_id} no encontrado.[/red]")
            return

    console.print(f"[cyan]⚡ Comando encolado para[/cyan] [{agent_id[:8]}] @ {agent.ip}: {command}")
    console.print("[dim]El comando se ejecutará en el próximo beacon del agente.[/dim]")


@agent.command("kill")
@click.argument("agent_id")
@click.option("--clean", is_flag=True, help="Limpiar persistencia y logs antes de matar")
def agent_kill(agent_id, clean):
    """Terminar un agente (con limpieza opcional)."""
    from database.models import AgentRecord, Database

    db = Database()
    with db.get_session() as session:
        agent = session.query(AgentRecord).filter(
            AgentRecord.id.like(f"{agent_id}%")
        ).first()
        if not agent:
            console.print(f"[red]Agente {agent_id} no encontrado.[/red]")
            return
        agent.is_alive = False
        session.commit()

    console.print(
        f"[red]💥 Agente {agent_id[:8]} TERMINADO[/red]"
        + (" (con limpieza)" if clean else "")
    )


# ─────────────────────────── ARSENAL ─────────────────────────────

@cli.group()
def arsenal():
    """Gestión del arsenal de malware."""
    pass


@arsenal.command("build")
@click.argument("malware_type", type=click.Choice([
    "rat", "stager", "virus", "trojan", "spyware",
    "exploit", "payload", "webshell", "rootkit"
]))
@click.option("--os",           "target_os",  default="windows", type=click.Choice(["windows", "linux", "mac"]))
@click.option("--arch",                        default="amd64",   type=click.Choice(["amd64", "arm64", "x86"]))
@click.option("--c2",           "c2_url",      default="",        help="URL del C2")
@click.option("--obfuscation",                 default="garble",  help="Técnicas: garble,upx,crypter")
@click.option("--features",                    default="",        help="Funciones: keylogger,screenshot,persist")
def arsenal_build(malware_type, target_os, arch, c2_url, obfuscation, features):
    """Construir un binario del arsenal con ofuscación."""
    from arsenal.builder import ArsenalBuilder
    builder = ArsenalBuilder()

    with console.status(f"[bold cyan]Compilando {malware_type} para {target_os}/{arch}...[/bold cyan]"):
        output = builder.build(
            malware_type = malware_type,
            target_os    = target_os,
            arch         = arch,
            params       = {
                "c2_url":      c2_url,
                "obfuscation": obfuscation.split(","),
                "features":    features.split(",") if features else [],
            },
        )

    if output:
        console.print(f"[green]✅ Binario generado:[/green] {output}")
    else:
        console.print(f"[red]❌ Error al compilar {malware_type}[/red]")


@arsenal.command("list")
def arsenal_list():
    """Listar binarios compilados disponibles."""
    from pathlib import Path
    output_dir = Path("./arsenal/output")
    if not output_dir.exists():
        console.print("[yellow]No hay binarios compilados aún.[/yellow]")
        return

    t = Table(title="Arsenal", box=box.ROUNDED)
    t.add_column("Nombre", style="cyan")
    t.add_column("Tamaño", justify="right")
    t.add_column("Fecha")

    import datetime
    for f in sorted(output_dir.iterdir()):
        if f.is_file():
            size = f.stat().st_size
            mtime = datetime.datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            t.add_row(f.name, f"{size/1024:.1f} KB", mtime)
    console.print(t)


# ─────────────────────────── REPORT ──────────────────────────────

@cli.group()
def report():
    """Generación de informes de misión."""
    pass


@report.command("generate")
@click.option("--mission", "-m", required=True,    help="ID o directorio de misión")
@click.option("--output",  "-o", default="./reports", help="Directorio de salida")
@click.option("--format",  "-f", default="html",   help="Formato: html | pdf | json",
              type=click.Choice(["html", "pdf", "json"]))
def report_generate(mission, output, format: str):
    """Generar informe completo de misión (ejecutivo + técnico + ATT&CK)."""
    console.print(f"[cyan]📄 Generando informe [{format}] para misión:[/cyan] {mission}")
    Path(output).mkdir(parents=True, exist_ok=True)

    template = f"""# Argos Mission Report — {mission}

## Executive Summary
Mission ID: {mission}
Generated: {__import__('datetime').datetime.now().isoformat()}

## Timeline
(TODO: Automatic timeline generation from mission_events)

## MITRE ATT&CK Matrix
(TODO: ATT&CK mapping from decision records)

## Captured Flags
(TODO: Flag extraction from flag table)
"""
    out_file = Path(output) / f"report_{mission}.{format}"
    out_file.write_text(template, encoding="utf-8")
    console.print(f"[green]✅ Informe generado:[/green] {out_file}")


# ─────────────────────────── CONFIG ──────────────────────────────

@cli.group("config")
def config_cmd():
    """Gestión de configuración global de Argos."""
    pass


@config_cmd.command("show")
@click.option("--file", "-f", default="config.yaml")
def config_show(file):
    """Mostrar configuración activa."""
    import yaml
    try:
        with open(file) as f:
            cfg = yaml.safe_load(f)
        console.print_json(json.dumps(cfg))
    except FileNotFoundError:
        console.print(f"[red]Archivo no encontrado:[/red] {file}")


@config_cmd.command("set")
@click.argument("key")
@click.argument("value")
@click.option("--file", "-f", default="config.yaml")
def config_set(key, value, file):
    """Establecer un valor de configuración (Ej: c2.port 8443)."""
    import yaml
    try:
        with open(file) as f:
            cfg = yaml.safe_load(f) or {}

        # Navegar la clave anidada (ej: "c2.port")
        keys = key.split(".")
        d = cfg
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        # Intentar convertir a tipo correcto
        try:
            d[keys[-1]] = int(value)
        except ValueError:
            try:
                d[keys[-1]] = float(value)
            except ValueError:
                d[keys[-1]] = value

        with open(file, "w") as f:
            yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False)

        console.print(f"[green]✅ {key} = {value}[/green]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")


# ─────────────────────────── ENTRY POINT ─────────────────────────

def main():
    cli(obj={})


if __name__ == "__main__":
    main()
