"""
argos_console.py
────────────────
Consola interactiva de ARGOS v2.0.
Todo desde un solo lugar — sin emojis, con hilo narrativo.
Uso: python argos_console.py
"""
import asyncio
import cmd
import logging
import os
import shutil
import socket
import subprocess
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
logging.basicConfig(level=logging.WARNING)

from core.director import Director, MissionConfig
from core.event_bus import Event, get_bus

# ── ANSI helpers ───────────────────────────────────────────
C = "\033[36m"      # cyan
G = "\033[32m"      # green
Y = "\033[33m"      # yellow
R = "\033[31m"      # red
M = "\033[35m"      # magenta
B = "\033[1m"       # bold
D = "\033[2m"       # dim
N = "\033[0m"       # reset


def box(title: str, body: str, color: str = C) -> str:
    """Render a simple box with a title and body."""
    w = shutil.get_terminal_size().columns - 4
    lines = [f"{color}{B}  {'=' * (w - 2)}{N}"]
    lines.append(f"{color}{B}   {title}{N}")
    for line in body.strip().split("\n"):
        lines.append(f"  {line}")
    lines.append(f"{color}{B}  {'=' * (w - 2)}{N}")
    return "\n".join(lines)


class ArgosConsole(cmd.Cmd):
    prompt = f"{C}{B}argos>{N} "

    def __init__(self):
        super().__init__()
        self.bus = get_bus()
        self.director: Director | None = None
        self._event_log: list[str] = []
        self._setup_handlers()
        self._print_intro()

    def _print_intro(self):
        print(f"""
{C}{B}  ARGOS v2.0 — Semi-Autonomous Offensive Operations Platform{N}
  {D}A* Planner | CBR Memory | Rules Engine | Live World Graph | GDS Kill Switch{N}
  {D}Escribe {B}help{D} para ver comandos, {B}quit{D} para salir{N}
""")

    def _setup_handlers(self):
        """Event bus handlers. Solo acumulan, no imprimen (evita romper el prompt)."""
        @self.bus.on(Event.HOST_DISCOVERED)
        async def _on_host(data): self._event_log.append(f"HOST {data.get('ip')}")

        @self.bus.on(Event.AGENT_REGISTERED)
        async def _on_agent(data): self._event_log.append(f"AGENT {data.get('agent_id','?')[:8]}")

        @self.bus.on(Event.DECISION_CREATED)
        async def _on_decision(data):
            d = data.get("decision", {})
            self._event_log.append(f"DECISION {d.get('action')} conf={d.get('confidence',0):.1%}")

        @self.bus.on(Event.FLAG_CAPTURED)
        async def _on_flag(data): self._event_log.append(f"FLAG {data.get('value')}")

        @self.bus.on(Event.CRED_CAPTURED)
        async def _on_cred(data): self._event_log.append(f"CRED {data.get('username')}")

        @self.bus.on(Event.KILL_SWITCH)
        async def _on_kill(data): self._event_log.append("KILL_SWITCH")

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def _status_line(self) -> str:
        """One-line status bar shown after each command."""
        if not self.director:
            return f"{D}  Sin mision activa. Usa 'start'.{N}"
        s = self.director.status()
        g = s["gds"]
        gc = G if g["score"] < 0.3 else Y if g["score"] < 0.7 else R
        return (
            f"  {B}Mision:{N} {s['mission_id']}  "
            f"{B}Target:{N} {s['target']}  "
            f"{B}Goal:{N} {s['goal']}  "
            f"{B}GDS:{N} {gc}{g['score']:.0%}{N}  "
            f"{B}Hosts:{N} {s['graph_stats'].get('host',0)}  "
            f"{B}Flags:{N} {s['graph_stats'].get('flag',0)}  "
            f"{B}Pendientes:{N} {s['pending_decisions']}"
        )

    def postcmd(self, stop, line):
        if self.director:
            print(f"\n{self._status_line()}\n")
        return stop

    # ═══════════════════════════════════════════════════════════
    # COMMANDS
    # ═══════════════════════════════════════════════════════════

    def do_start(self, arg):
        """start [target] [goal] [profile] [--auto] — Iniciar una mision.
        Ej: start 10.100.0.0/24 domain_admin balanced
            start --auto"""
        parts = arg.replace("--auto", "").split()
        auto = "--auto" in arg

        target  = parts[0] if len(parts) > 0 else "10.100.0.0/24"
        goal    = parts[1] if len(parts) > 1 else "domain_admin"
        profile = parts[2] if len(parts) > 2 else "balanced"

        self.director = Director(config=MissionConfig(
            target=target, goal=goal, profile=profile, auto_decide=auto,
        ), bus=self.bus)

        cbr_ok  = self.director.cbr.enabled
        msf_ok  = self.director.exploit_manager.msf.connected if hasattr(self.director, 'exploit_manager') else False

        engine_status = (
            f"  {G}[OK]{N} A* Planner       {D}(NetworkX, heuristic IP-distance){N}\n"
            f"  {G if cbr_ok else Y}{'[OK]' if cbr_ok else '[--]'}{N} CBR Memory       "
            f"{D if cbr_ok else '(Qdrant + embeddings no instalados)'}{N}\n"
            f"  {G}[OK]{N} Rules Engine     {D}(10+ servicios, 500 reglas){N}\n"
            f"  {G}[OK]{N} Decision Fusion  {D}(weights: A* 45% | CBR 30% | Rules 25%){N}\n"
            f"  {G}[OK]{N} Knowledge Tree   {D}(NetworkX MultiDiGraph, thread-safe){N}\n"
            f"  {G}[OK]{N} Global Defense State {D}(kill switch @ 90%){N}\n"
            f"  {G}[OK]{N} Recon Manager    {D}(auto-dispatch a agentes){N}\n"
            f"  {G}[OK]{N} Exploit Manager  {D}(agente local + MSF RPC){N}\n"
            f"  {G if msf_ok else Y}{'[OK]' if msf_ok else '[--]'}{N} Metasploit RPC    "
            f"{D if msf_ok else '(pymetasploit3 no instalado)'}{N}"
        )

        body = (
            f"  {B}ID:{N}      {self.director.config.mission_id}\n"
            f"  {B}Target:{N}  {target}\n"
            f"  {B}Goal:{N}    {goal}\n"
            f"  {B}Profile:{N} {profile}  {D}(threshold: {self.director.fusion.THRESHOLDS[profile]:.0%}){N}\n"
            f"  {B}Auto:{N}    {'ON' if auto else 'OFF (HITL)'}\n"
            f"\n"
            f"  {B}Motores de decision:{N}\n"
            f"{engine_status}\n"
            f"\n"
            f"  {B}Flujo de operacion:{N}\n"
            f"  {D}1. Registrar agentes (agent register){N}\n"
            f"  {D}2. Descubrir hosts y servicios (agent find){N}\n"
            f"  {D}3. El motor de decision propone acciones{N}\n"
            f"  {D}4. Tu apruebas/rechazas (decide approve/reject){N}\n"
            f"  {D}5. El agente ejecuta el exploit{N}\n"
            f"  {D}6. Capturar flags y credenciales{N}\n"
            f"\n"
            f"  {Y}Prueba 'demo' para ver una mision completa.{N}"
        )
        print(box("MISION INICIADA", body, C))

    def do_guide(self, arg):
        """guide — Explicar la arquitectura y flujo de ARGOS."""
        text = """
  ARGOS es un orquestador ofensivo semi-autonomo que emula APTs.

  ARQUITECTURA
  ============
  Un Agente en campo descubre hosts y servicios. Cada hallazgo se
  envia al Director, que actualiza el Knowledge Tree (grafo vivo).

  El Director invoca el Decision Fusion Engine, que combina 3 motores:

    A* Planner (45%)
      Busca rutas optimas a traves del grafo de ataque.
      Elige el camino mas silencioso o mas rapido segun el perfil.

    CBR Memory (30%)
      Memoria vectorial (Qdrant + embeddings).
      Recuerda que tacticas funcionaron en situaciones similares.

    Rules Engine (25%)
      Arboles de decision tacticos por servicio/SO/defensa.
      Ej: SMB 445 + Windows XP -> EternalBlue.

  PERFILES DE OPERACION
  =====================
    ghost    — Maximo sigilo. Solo actua con confianza > 85%.
    balanced — Equilibrio velocidad/sigilo. Umbral 65%. (default)
    blitz    — Agresivo. Actua con poca evidencia. Umbral 35%.

  GLOBAL DEFENSE STATE (GDS)
  ==========================
  Monitoriza la "paranoia" de la red enemiga (0% - 100%).
  Cada alerta defensiva sube el GDS. Al llegar a 90%:
    -> KILL SWITCH: todos los agentes hibernan.

  HUMAN-IN-THE-LOOP (HITL)
  ========================
  Por defecto (auto_decide=OFF), las decisiones se encolan.
  El operador las revisa con 'decide list' y aprueba/rechaza.
  Con --auto, las decisiones con confianza suficiente se
  ejecutan sin intervencion.

  FLUJO COMPLETO
  ==============
    1. Agente se registra         -> agent register
    2. Agente escanea red          -> HOST_DISCOVERED
    3. Agente reporta servicios    -> SERVICE_OPEN
    4. Director evalua             -> Decision Fusion
    5. Operador aprueba/rechaza    -> decide approve/reject
    6. Agente ejecuta exploit      -> EXPLOIT_SUCCESS
    7. Agente extrae credenciales  -> CREDENTIAL
    8. Agente busca flags          -> FLAG_CAPTURED
"""
        print(textwrap.dedent(text))

    def do_demo(self, arg):
        """demo — Ejecutar una mision de demostracion narrada paso a paso."""
        fast = "--fast" in arg
        delay = 0.3 if fast else 0.0

        if not self.director:
            self.do_start("10.100.0.0/24 domain_admin balanced")

        async def run():
            d = self.director

            # FASE 1 — Registro
            print(box("FASE 1/6 — REGISTRO DE AGENTE", (
                "  Un agente compromete un endpoint y se registra en el C2.\n"
                "  El Director lo anade al Knowledge Tree como nodo HOST.\n"
                "  El Recon Manager ordena automaticamente un escaneo inicial."
            ), M))
            await d.register_agent({
                "agent_id": "cell-01", "ip": "10.100.0.50",
                "os": "linux", "hostname": "pivot"
            })
            print(f"  {G}[+]{N} Agente registrado: cell-01 @ 10.100.0.50")
            print(f"  {D}  -> Recon Manager encola port_scan sobre 10.100.0.50{N}")
            await asyncio.sleep(delay)

            # FASE 2 — Reconocimiento
            print(box("FASE 2/6 — RECONOCIMIENTO", (
                "  El agente escanea la red y descubre un nuevo host.\n"
                "  Encuentra el puerto 445 (SMB) abierto en Windows 7.\n"
                "  Este hallazgo activa el Decision Engine."
            ), M))
            await d.process_finding("cell-01", {
                "type": "HOST_DISCOVERED", "ip": "10.100.0.20", "os": "windows"
            })
            print(f"  {G}[+]{N} Host descubierto: 10.100.0.20 (Windows)")
            print(f"  {D}  -> Knowledge Tree: nuevo nodo HOST anadido{N}")

            await d.process_finding("cell-01", {
                "type": "SERVICE_OPEN", "port": 445,
                "service_name": "smb", "version": "", "banner": "Windows 7 SP1"
            })
            print(f"  {G}[+]{N} Servicio detectado: SMB:445 @ 10.100.0.20")
            await asyncio.sleep(delay)

            # FASE 3 — Decision Engine
            print(box("FASE 3/6 — MOTOR DE DECISION", (
                f"  El Decision Fusion Engine evalua el contexto:\n"
                f"\n"
                f"    {B}Rules Engine (25%):{N} SMB en Windows -> smb_eternalblue_MS17-010 (prio=0.90)\n"
                f"    {B}A* Planner (45%):{N}   Busca ruta al DC... {D}(sin DC en el grafo aun){N}\n"
                f"    {B}CBR Memory (30%):{N}   {D}(modo degradado — sin Qdrant){N}\n"
                f"\n"
                f"  {Y}Fusion:{N} smb_enum_shares (conf: 21%) — necesita aprobacion (HITL)\n"
                f"  {D}(El Planner no encuentra DC porque no hay aristas de ataque aun.{N}\n"
                f"  {D} Con un grafo mas poblado, la confianza seria mayor){N}"
            ), M))
            print(f"  {Y}[!]{N} Decision encolada: smb_enum_shares (conf: 21%)")
            print(f"  {D}  -> Esperando aprobacion del operador (HITL){N}")

            pending = d.list_pending_decisions()
            if pending:
                did = pending[0]["decision_id"]
                print(f"\n  {B}Simulando aprobacion automatica...{N}")
                await d.approve_decision(did)
                print(f"  {G}[+]{N} Decision {did} APROBADA")
            await asyncio.sleep(delay)

            # FASE 4 — Explotacion
            print(box("FASE 4/6 — EXPLOTACION", (
                "  La decision aprobada se despacha al Exploit Manager.\n"
                "  El agente ejecuta EternalBlue contra 10.100.0.20:445.\n"
                "  El host es comprometido exitosamente (OWNED)."
            ), M))
            await d.process_finding("cell-01", {
                "type": "EXPLOIT_SUCCESS",
                "technique": "smb_eternalblue_MS17-010",
                "session_id": "sess-001",
                "context_description": "SMB Windows 7 SP1, puerto 445, EternalBlue",
            })
            print(f"  {G}[+]{N} Exploit exitoso: EternalBlue MS17-010")
            print(f"  {G}[+]{N} Host OWNED: 10.100.0.20 (session: sess-001)")
            print(f"  {D}  -> CBR registra caso exitoso para futuras misiones{N}")
            await asyncio.sleep(delay)

            # FASE 5 — Post-explotacion
            print(box("FASE 5/6 — POST-EXPLOTACION", (
                "  Con acceso al sistema, el agente extrae credenciales\n"
                "  (hash NTLM del Administrador) y busca flags."
            ), M))
            await d.process_finding("cell-01", {
                "type": "CREDENTIAL",
                "username": "Administrator",
                "cred_type": "ntlm_hash",
                "value": "aad3b435b51404ee...8846f7eaee8fb117",
                "scope": "local",
            })
            print(f"  {G}[+]{N} Credencial extraida: Administrator (NTLM hash)")

            await d.process_finding("cell-01", {
                "type": "FLAG",
                "flag_value": "CTF{Argus_Demo_2024}",
                "path": "C:\\Users\\Administrator\\Desktop\\flag.txt",
            })
            print(f"  {G}[+]{N} FLAG capturada: CTF{{Argus_Demo_2024}}")
            await asyncio.sleep(delay)

            # FASE 6 — Defensa
            print(box("FASE 6/6 — RESPUESTA DEFENSIVA", (
                "  El EDR enemigo (SentinelOne) detecta actividad.\n"
                "  El Global Defense State (GDS) sube.\n"
                "  Si el GDS llega a 90%, Kill Switch hiberna todos los agentes."
            ), M))
            await d.process_finding("cell-01", {
                "type": "DEFENSE_DETECTED",
                "defense_type": "edr",
                "defense_name": "SentinelOne",
                "severity": 0.6,
            })
            gds = d.kt.gds.to_dict()
            gc = G if gds["score"] < 0.3 else Y if gds["score"] < 0.7 else R
            print(f"  {Y}[!]{N} EDR detectado: SentinelOne")
            print(f"  {Y}[!]{N} GDS: {gc}{gds['score']:.0%}{N} ({gds['level']})")
            await asyncio.sleep(delay)

            # RESUMEN
            stats = d.kt.stats()
            print(box("MISION COMPLETADA", (
                f"  {B}Hosts descubiertos:{N}     {stats.get('host', 0)}\n"
                f"  {B}Servicios detectados:{N}   {stats.get('service', 0)}\n"
                f"  {B}Credenciales extraidas:{N} {stats.get('credential', 0)}\n"
                f"  {B}Flags capturadas:{N}       {stats.get('flag', 0)}\n"
                f"  {B}GDS final:{N}              {gds['score']:.0%} ({gds['level']})\n"
                f"  {B}Decisiones pendientes:{N}  {len(d.list_pending_decisions())}\n"
                f"\n"
                f"  {G}La mision es un exito.{N} El motor de decision funciono\n"
                f"  correctamente y el operador tuvo control total (HITL)."
            ), G))

        self._run(run())

    def do_agent(self, arg):
        """agent <cmd> — Gestionar agentes de campo.
        agent register <id> <ip> [os]   — Registrar un nuevo agente
        agent list                       — Listar agentes activos
        agent find <port> <service>      — Simular hallazgo de servicio"""
        parts = arg.split()
        if not parts:
            print(f"  {D}Subcomandos: register, list, find{N}")
            return
        if not self.director:
            print(f"  {Y}Inicia una mision primero: start{N}")
            return

        if parts[0] == "register" and len(parts) >= 3:
            async def reg():
                ack = await self.director.register_agent({
                    "agent_id": parts[1], "ip": parts[2],
                    "os": parts[3] if len(parts) > 3 else "linux",
                    "hostname": parts[1],
                })
                print(f"  {G}[+]{N} Agente {parts[1][:8]} registrado @ {parts[2]}")
                print(f"  {D}  -> Beacon interval: {ack['beacon_interval_sec']}s{N}")
            self._run(reg())

        elif parts[0] == "list":
            if not self.director.agents:
                print(f"  {D}No hay agentes registrados.{N}")
                return
            print(f"\n  {B}{'ID':<12} {'IP':<16} {'OS':<12} {'Estado':<8}{N}")
            print(f"  {'-'*48}")
            for aid, a in self.director.agents.items():
                s = f"{G}ACTIVO{N}" if a.is_alive else f"{R}MUERTO{N}"
                print(f"  {aid[:11]:<12} {a.ip:<16} {a.os:<12} {s}")
            print()

        elif parts[0] == "find" and len(parts) >= 3:
            async def find():
                agents = [aid for aid, a in self.director.agents.items() if a.is_alive]
                if not agents:
                    print(f"  {R}No hay agentes vivos para reportar hallazgos.{N}")
                    return
                result = await self.director.process_finding(agents[0], {
                    "type": "SERVICE_OPEN",
                    "port": int(parts[1]),
                    "service_name": parts[2],
                    "version": parts[3] if len(parts) > 3 else "",
                    "banner": parts[4] if len(parts) > 4 else "",
                })
                print(f"  {G}[+]{N} Hallazgo reportado: {parts[2]}:{parts[1]}")
                if result:
                    print(f"  {Y}[!]{N} Director ordena: {result.get('action')}")
                else:
                    print(f"  {D}  -> Motor de decision evaluando...{N}")
            self._run(find())

    def do_decide(self, arg):
        """decide [list|approve <id>|reject <id>] — Human-in-the-Loop.
        decide list              — Ver decisiones pendientes
        decide approve <id>      — Aprobar una decision
        decide reject <id>       — Rechazar una decision"""
        parts = arg.split()
        if not self.director:
            print(f"  {Y}Inicia una mision primero: start{N}")
            return

        if not parts or parts[0] == "list":
            pending = self.director.list_pending_decisions()
            if not pending:
                print(f"  {D}No hay decisiones pendientes.{N}")
                return
            print(f"\n  {B}{'ID':<12} {'Accion':<32} {'Confianza':<12} {'Explicacion'}{N}")
            print(f"  {'-'*80}")
            for p in pending:
                expl = (p.get("explanation", "") or "")[:40]
                print(f"  {p['decision_id']:<12} {p['action']:<32} {p['confidence']:.0%}{'':<7} {expl}")
            print()

        elif parts[0] == "approve" and len(parts) > 1:
            async def app():
                cmd = await self.director.approve_decision(parts[1])
                if cmd:
                    print(f"  {G}[+]{N} Decision {parts[1]} APROBADA")
                    print(f"  {D}  -> Comando: {cmd.get('action', cmd.get('type', '?'))}{N}")
                else:
                    print(f"  {Y}Decision {parts[1]} no encontrada o ya resuelta.{N}")
            self._run(app())

        elif parts[0] == "reject" and len(parts) > 1:
            async def rej():
                await self.director.reject_decision(parts[1])
                print(f"  {R}[-]{N} Decision {parts[1]} RECHAZADA")
            self._run(rej())

    def do_status(self, arg):
        """status — Mostrar estado detallado de la mision activa."""
        if not self.director:
            print(f"  {Y}No hay mision activa. Usa 'start'.{N}")
            return
        s = self.director.status()
        g = s["gds"]
        gc = G if g["score"] < 0.3 else Y if g["score"] < 0.7 else R

        body = (
            f"  {B}ID:{N}         {s['mission_id']}\n"
            f"  {B}Target:{N}     {s['target']}\n"
            f"  {B}Goal:{N}       {s['goal']}\n"
            f"  {B}Profile:{N}    {s['profile']}\n"
            f"  {B}Running:{N}    {G if s['running'] else R}{'YES' if s['running'] else 'NO'}{N}\n"
            f"\n"
            f"  {B}GDS Score:{N}  {gc}{g['score']:.0%}{N} ({g['level']})\n"
            f"  {B}Agentes:{N}    {s['agents_alive']}/{s['agents_total']} vivos\n"
            f"  {B}Pendientes:{N} {s['pending_decisions']} decisiones sin resolver\n"
            f"\n"
            f"  {B}Knowledge Tree:{N}\n"
        )
        for k, v in s.get("graph_stats", {}).items():
            body += f"    {k:<20} {v}\n"
        print(box("ESTADO DE MISION", body, C))

    def do_lab(self, arg):
        """lab — Verificar laboratorio vulnerable (6 targets)."""
        targets = {
            "Apache 2.4.49 (CVE-2021-41773)": ("127.0.0.1", 8080),
            "SSH debil (admin:admin123)": ("127.0.0.1", 2222),
            "MySQL 5.7 (no auth)": ("127.0.0.1", 3306),
            "FTP anonimo": ("127.0.0.1", 2121),
            "Redis 6.2 (no auth)": ("127.0.0.1", 6379),
            "DVWA (SQLi, XSS, RFI)": ("127.0.0.1", 8888),
        }
        ok = 0
        total = len(targets)
        lines = []
        for name, (host, port) in targets.items():
            try:
                s = socket.create_connection((host, port), timeout=2)
                s.close()
                lines.append(f"  {G}[UP]{N}   {name}  {D}({host}:{port}){N}")
                ok += 1
            except Exception:
                lines.append(f"  {R}[DOWN]{N} {name}  {D}({host}:{port}){N}")

        body = "\n".join(lines)
        body += f"\n\n  {G if ok == total else Y}{ok}/{total} targets alcanzables{N}"
        print(box("LABORATORIO VULNERABLE", body, C))

    def do_test(self, arg):
        """test [unit|integration|lab] — Ejecutar bateria de tests."""
        tests = {
            "unit":        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short", "-q"],
            "integration": [sys.executable, "tests/demo_integration.py"],
            "lab":         [sys.executable, "tests/test_lab.py"],
        }
        if arg not in tests:
            print(f"  Opciones: {', '.join(tests.keys())}")
            return
        print(f"\n  {B}Ejecutando tests: {arg}{N}\n")
        subprocess.run(tests[arg], cwd=str(Path(__file__).parent))
        print()

    def do_listen(self, arg):
        """listen [port] — Arrancar servidor gRPC y esperar agentes."""
        port = int(arg) if arg.isdigit() else 50051
        print(f"\n  {B}Arrancando servidor gRPC en 0.0.0.0:{port}...{N}")
        print(f"  {D}Esperando agentes (Ctrl+C para detener)...{N}\n")
        try:
            self._run(self._listen(port))
        except KeyboardInterrupt:
            print(f"\n  {Y}Servidor detenido.{N}")

    async def _listen(self, port: int):
        from api.grpc_server import GrpcServer
        srv = GrpcServer(self.director, port=port)
        try:
            await srv.start()
        except asyncio.CancelledError:
            await srv.stop()

    def do_connect(self, arg):
        """connect cell|stager — Compilar y lanzar agente Go contra el Director."""
        parts = arg.split()
        agent = parts[0] if parts else "cell"
        if agent not in ("cell", "stager"):
            print(f"  {Y}Opciones: cell, stager{N}")
            return
        if not self.director:
            print(f"  {Y}Inicia una mision primero: start{N}")
            return

        src = Path(f"agents/{agent}")
        if not (src / "main.go").exists():
            print(f"  {R}No encontrado: {src}/main.go{N}")
            return

        bin_path = Path(f"/tmp/argos_{agent}")
        print(f"\n  {B}Compilando agente {agent}...{N}")
        result = subprocess.run(
            ["go", "build", "-o", str(bin_path), "."],
            cwd=str(src), capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"  {R}Error compilando:{N}\n{result.stderr[:500]}")
            return
        print(f"  {G}[+]{N} Binario: {bin_path}")
        print(f"  {B}Ejecutando agente...{N}")
        subprocess.Popen(
            [str(bin_path)],
            env={**os.environ, "ARGOS_C2_HOST": "127.0.0.1", "ARGOS_C2_PORT": "50051"},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print(f"  {G}[+]{N} Agente {agent} lanzado en background")
        print(f"  {D}  -> Conectandose a 127.0.0.1:50051 via gRPC{N}")

    def do_exploit(self, arg):
        """exploit <ip> <port> [action] — Lanzar exploit contra un target.
        Ej: exploit 10.100.0.20 445
            exploit 10.100.0.20 80 apache_path_traversal_CVE-2021-41773"""
        parts = arg.split()
        if len(parts) < 2:
            print(f"  {D}Uso: exploit <ip> <port> [action]{N}")
            print(f"  {D}Si no especificas action, el Decision Engine elige.{N}")
            return
        if not self.director:
            print(f"  {Y}Inicia una mision primero: start{N}")
            return

        target_ip = parts[0]
        port = int(parts[1])
        specified_action = parts[2] if len(parts) > 2 else None

        async def run():
            # Registrar host si no existe
            host = self.director.kt.get_host_by_ip(target_ip)
            if not host:
                info = {"agent_id": "console-op", "ip": target_ip, "os": "unknown"}
                await self.director.register_agent(info)
                host = self.director.kt.get_host_by_ip(target_ip)

            host_id = host.id if host else "manual"

            if specified_action:
                action = specified_action
            else:
                # Usar Decision Engine
                svc_name = {80: "http", 443: "https", 22: "ssh", 445: "smb", 3306: "mysql",
                            1433: "mssql", 5432: "postgresql", 21: "ftp", 3389: "rdp",
                            6379: "redis", 161: "snmp"}.get(port, "unknown")
                await self.director.process_finding("console-op", {
                    "type": "SERVICE_OPEN", "port": port,
                    "service_name": svc_name, "version": "", "banner": "",
                })
                pending = self.director.list_pending_decisions()
                if pending:
                    did = pending[0]["decision_id"]
                    action = pending[0]["action"]
                    print(f"  {Y}[Decision Engine]{N} {action} (conf={pending[0]['confidence']:.0%})")
                    await self.director.approve_decision(did)
                else:
                    print(f"  {R}El Decision Engine no pudo decidir.{N}")
                    return

            # Ver si action tiene modulo MSF
            from core.exploit_manager import ACTION_TO_MSF
            msf_info = ACTION_TO_MSF.get(action)
            if msf_info and msf_info.get("module"):
                print(f"  {M}[MSF]{N} {msf_info['module']} -> {target_ip}:{port}")
                if self.director.exploit_manager.msf.connected:
                    await self.director.exploit_manager.exploit_target(action, host_id, "console-op")
                    print(f"  {G}[+]{N} Despachado via MSF RPC")
                else:
                    print(f"  {Y}[!]{N} MSF no esta conectado. Delegando al agente.")
                    await self.director.exploit_manager._dispatch_to_agent("console-op", action, host_id)
            else:
                print(f"  {Y}[Agente]{N} {action} -> {target_ip}:{port}")
                await self.director.exploit_manager._dispatch_to_agent("console-op", action, host_id)

        self._run(run())

    def do_chain(self, arg):
        """chain <ip1> <ip2> ... — Cadena de exploits multi-step.
        Ej: chain 10.100.0.1 10.100.0.20 10.100.0.30"""
        ips = arg.split()
        if len(ips) < 2:
            print(f"  {D}Uso: chain <ip1> <ip2> ...{N}")
            return
        if not self.director:
            print(f"  {Y}Inicia una mision primero: start{N}")
            return

        async def run():
            # Asegurar que los hosts existen
            for ip in ips:
                host = self.director.kt.get_host_by_ip(ip)
                if not host:
                    await self.director.register_agent({"agent_id": f"chain-{ip[-3:]}", "ip": ip, "os": "unknown"})

            print(f"  {B}Chain: {' -> '.join(ips)}{N}")
            for i in range(len(ips) - 1):
                src = ips[i]
                dst = ips[i + 1]
                host = self.director.kt.get_host_by_ip(dst)
                if not host:
                    continue
                # Planner busca ruta
                routes = self.director.planner.find_routes(
                    self.director.kt.get_host_by_ip(src).id, f"host:{dst}", self.director.config.profile,
                )
                if routes:
                    step = routes[0].steps[0] if routes[0].steps else None
                    if step:
                        print(f"  [{i+1}] {src[:8]} -> {dst[:8]}: {step.technique}")
                        await self.director.exploit_manager.exploit_target(
                            step.technique, host.id, f"chain-{src[-3:]}",
                        )
                    else:
                        print(f"  [{i+1}] {R}Sin tecnica disponible para este salto{N}")
                else:
                    print(f"  [{i+1}] {R}Sin ruta del planner{N}")

        self._run(run())

    def do_loot(self, arg):
        """loot — Mostrar tabla de loot (creds, flags, hosts owned)."""
        if not self.director:
            print(f"  {Y}Inicia una mision primero: start{N}")
            return
        stats = self.director.kt.stats()
        owned = self.director.kt.get_owned_hosts()
        print(f"\n  {B}LOOT DE MISION {self.director.config.mission_id}{N}\n")
        print(f"  {G}Hosts owned:{N} {len(owned)}")
        for h in owned:
            print(f"    {h.ip} ({h.os or '?'}) sessions={len(h.sessions)}")
        print(f"  {Y}Credenciales:{N} {stats.get('credential', 0)}")
        print(f"  {R}Flags:{N} {stats.get('flag', 0)}")
        print(f"  {M}Defensas:{N} {stats.get('defense', 0)}")
        print(f"  {B}Pendientes:{N} {len(self.director.list_pending_decisions())}")
        print()

    def do_help(self, arg):
        """help — Mostrar todos los comandos disponibles."""
        cmds = [
            ("guide", "Explicar arquitectura y flujo de ARGOS"),
            ("start [t] [g] [p] [--auto]", "Iniciar una mision"),
            ("demo [--fast]", "Demo narrada de 6 fases"),
            ("status", "Estado detallado de la mision"),
            ("agent register <id> <ip> [os]", "Registrar un agente"),
            ("agent list", "Listar agentes activos"),
            ("agent find <port> <service>", "Simular hallazgo (ej: 445 smb)"),
            ("decide list/approve/reject", "Gestionar decisiones (HITL)"),
            ("connect cell|stager", "Compilar y lanzar agente Go via gRPC"),
            ("listen [port]", "Arrancar servidor gRPC y esperar agentes"),
            ("exploit <ip> <port> [action]", "Lanzar exploit (via MSF o agente)"),
            ("chain <ip1> <ip2> ...", "Cadena de exploits multi-step"),
            ("loot", "Mostrar tabla de loot (creds, flags, hosts)"),
            ("lab", "Verificar laboratorio (6 targets)"),
            ("test unit|integration|lab", "Ejecutar tests"),
            ("quit", "Salir"),
        ]
        print()
        for c, desc in cmds:
            print(f"  {C}{B}{c:<36}{N} {desc}")
        print()

    def do_quit(self, arg):
        """quit — Salir de la consola."""
        print(f"\n  {D}ARGOS console cerrada.{N}\n")
        return True

    do_exit = do_quit
    do_q = do_quit

    def emptyline(self):
        pass


if __name__ == "__main__":
    ArgosConsole().cmdloop()
