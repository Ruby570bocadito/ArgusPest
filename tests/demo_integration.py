"""
tests/demo_integration.py
─────────────────────────
Demo de integración — Simula una misión completa del orquestador sin gRPC ni Docker.
"""
import asyncio
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("argos.demo")

from core.director import Director, MissionConfig
from core.event_bus import Event, get_bus


async def demo(mission_cfg: Optional[MissionConfig] = None) -> dict:
    """Ejecuta una misión de demostración completa y devuelve el estado final."""
    bus = get_bus()
    cfg = mission_cfg or MissionConfig(
        target="10.100.0.0/24",
        goal="domain_admin",
        auto_decide=False,
    )
    director = Director(config=cfg, bus=bus)

    events = {"hosts": [], "decisions": [], "flags": []}

    @bus.on(Event.HOST_DISCOVERED)
    async def on_host(data):
        ip = data.get("ip", "?")
        log.info(f"  🖥  Host descubierto: {ip}")
        events["hosts"].append(ip)

    @bus.on(Event.AGENT_REGISTERED)
    async def on_agent(data):
        log.info(f"  🤖 Agente registrado: {data.get('agent_id','?')[:8]} @ {data.get('ip')}")

    @bus.on(Event.DECISION_CREATED)
    async def on_decision(data):
        d = data.get("decision", {})
        action = d.get("action", "?")
        conf = d.get("confidence", 0)
        log.info(f"  🧠 Decisión: '{action}' conf={conf:.1%}")
        events["decisions"].append(action)

    @bus.on(Event.FLAG_CAPTURED)
    async def on_flag(data):
        val = data.get("value", "")
        log.info(f"  🚩 FLAG: {val}")
        events["flags"].append(val)

    @bus.on(Event.CRED_CAPTURED)
    async def on_cred(data):
        log.info(f"  🔑 Credencial: {data.get('username')} [{data.get('type')}]")

    @bus.on(Event.KILL_SWITCH)
    async def on_kill(data):
        log.info(f"  🔴 KILL SWITCH ACTIVADO — {data}")

    # ─── Fase 1: Registro ────────────────────────────────────
    log.info("\n1️⃣  Registrando agente...")
    await director.register_agent({
        "agent_id": "agent-01",
        "ip": "10.100.0.50",
        "os": "linux",
        "hostname": "pivot",
    })

    # ─── Fase 2: Reconocimiento ──────────────────────────────
    log.info("\n2️⃣  Descubriendo hosts en la red...")
    await director.process_finding("agent-01", {
        "type": "HOST_DISCOVERED",
        "ip": "10.100.0.20",
        "os": "windows",
    })

    log.info("\n3️⃣  Reportando SMB:445 abierto...")
    cmd = await director.process_finding("agent-01", {
        "type": "SERVICE_OPEN",
        "port": 445,
        "service_name": "smb",
        "version": "",
        "banner": "Windows 7 SP1",
    })
    if cmd:
        log.info(f"  ⚡ Director ordena: {cmd.get('action')}")

    # ─── Fase 3: Explotación ─────────────────────────────────
    log.info("\n4️⃣  Simulando EternalBlue exitoso...")
    await director.process_finding("agent-01", {
        "type": "EXPLOIT_SUCCESS",
        "technique": "smb_eternalblue_MS17-010",
        "session_id": "sess-001",
        "context_description": "SMB Windows 7 SP1, puerto 445, EternalBlue",
    })

    # ─── Fase 4: Post-explotación ────────────────────────────
    log.info("\n5️⃣  Extrayendo credenciales...")
    await director.process_finding("agent-01", {
        "type": "CREDENTIAL",
        "username": "Administrator",
        "cred_type": "ntlm_hash",
        "value": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
        "scope": "local",
    })

    # ─── Fase 5: Flag hunting ────────────────────────────────
    log.info("\n6️⃣  Capturando flag...")
    await director.process_finding("agent-01", {
        "type": "FLAG",
        "flag_value": "CTF{Argus_Demo_2024}",
        "path": "C:\\Users\\Administrator\\Desktop\\flag.txt",
    })

    # ─── Fase 6: Simular defensa ─────────────────────────────
    log.info("\n7️⃣  Simulando detección por EDR...")
    await director.process_finding("agent-01", {
        "type": "DEFENSE_DETECTED",
        "defense_type": "edr",
        "defense_name": "SentinelOne",
        "severity": 0.95,
    })
    director.kt.gds.update("honeypot_detected", severity=0.8)

    # ─── Estado final ────────────────────────────────────────
    stats = director.kt.stats()
    gds = director.kt.gds.to_dict()
    status = {
        "mission_id": cfg.mission_id,
        "gds": gds,
        "hosts": stats.get("host", 0),
        "services": stats.get("service", 0),
        "credentials": stats.get("credential", 0),
        "flags": stats.get("flag", 0),
        "pending_decisions": len(director.list_pending_decisions()),
        "events": events,
        "test_passed": events.get("flags", []) != [],
    }

    log.info("\n" + "=" * 50)
    log.info("📊 ESTADO FINAL DE LA MISIÓN")
    log.info("=" * 50)
    log.info(f"  Misión:       {status['mission_id']}")
    log.info(f"  GDS:          {gds['score']:.0%} ({gds['level']})")
    log.info(f"  Hosts:        {status['hosts']}")
    log.info(f"  Servicios:    {status['services']}")
    log.info(f"  Credenciales: {status['credentials']}")
    log.info(f"  Flags:        {status['flags']}")
    log.info(f"  Decisiones:   {status['pending_decisions']} pendientes")
    log.info(f"  Eventos:      {len(status['events']['hosts'])} hosts, {len(status['events']['decisions'])} decisiones, {len(status['events']['flags'])} flags")
    log.info(f"  PASÓ TEST:    {'✅ SI' if status['test_passed'] else '❌ NO'}")

    return status


if __name__ == "__main__":
    status = asyncio.run(demo())
    if not status["test_passed"]:
        exit(1)
