"""
tests/mock_agent.py
───────────────────
Simula un agente en campo enviando eventos al Orquestador a través del Event Bus.
Útil para ver el Dashboard y la CLI reaccionar en tiempo real.
"""

import asyncio
import logging

from core.event_bus import Event, get_bus

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("MockAgent")

async def run_simulation():
    bus = get_bus()
    agent_id = "agent-mock-01"

    log.info("🤖 [MockAgent] Iniciando simulación de infección...")
    await asyncio.sleep(2)

    # 1. El agente se registra
    log.info("🤖 [MockAgent] Registrándose en el Director...")
    await bus.emit(Event.AGENT_REGISTERED, {
        "agent_id": agent_id,
        "ip": "10.100.0.50",
        "os": "linux"
    })
    await asyncio.sleep(3)

    # 2. El agente descubre un objetivo
    log.info("🤖 [MockAgent] Descubriendo host vecino (10.100.0.20)...")
    await bus.emit(Event.HOST_DISCOVERED, {
        "host_id": "host-vuln-01",
        "ip": "10.100.0.20",
        "os": "linux"
    })
    await asyncio.sleep(4)

    # 3. El agente reporta un servicio abierto (SMB)
    log.info("🤖 [MockAgent] Reportando puerto 445 (SMB) abierto en el objetivo...")
    await bus.emit(Event.SERVICE_DISCOVERED, {
        "host_id": "host-vuln-01",
        "port": 445,
        "service": "smb",
        "banner": "Samba 4.10"
    })

    # Aquí el motor de reglas debería saltar, evaluar el riesgo y crear una "Decision"
    await asyncio.sleep(6)

    # 4. Simulamos que algo salió mal y el EDR enemigo detecta actividad
    log.info("🤖 [MockAgent] ⚠️ Simulando alerta defensiva (EDR nos ha detectado)...")
    await bus.emit(Event.DEFENSE_DETECTED, {
        "defense_type": "edr",
        "defense_name": "SentinelOne",
        "severity": 0.95
    })

    # Esto disparará el Kill Switch en el GDS
    await asyncio.sleep(3)
    log.info("🤖 [MockAgent] Simulación terminada.")

if __name__ == "__main__":
    asyncio.run(run_simulation())
