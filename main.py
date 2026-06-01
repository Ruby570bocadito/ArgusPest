"""
main.py
───────
Punto de entrada del Orquestador Argos.
"""

import asyncio
import logging
import sys
from pathlib import Path

import yaml

# Añadir raíz del proyecto al path
sys.path.insert(0, str(Path(__file__).parent))

from core.director import Director, MissionConfig
from core.event_bus import Event, get_bus


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def setup_logging(cfg: dict) -> None:
    log_cfg = cfg.get("logging", {})
    level   = getattr(logging, log_cfg.get("level", "INFO"), logging.INFO)
    fmt     = log_cfg.get("format", "%(asctime)s | %(name)s | %(levelname)s | %(message)s")
    log_file = log_cfg.get("file", "./logs/argos.log")

    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    except Exception:
        pass

    logging.basicConfig(level=level, format=fmt, handlers=handlers)


async def amain() -> None:
    cfg = load_config()
    setup_logging(cfg)

    log = logging.getLogger("argos.main")
    log.info("=" * 60)
    log.info("  ARGOS — Semi-Autonomous Offensive Operations Platform")
    log.info(f"  Version: {cfg['argos']['version']}")
    log.info("=" * 60)

    # Asegurar directorios necesarios
    for d in ["./missions", "./data", "./data/qdrant", "./logs", "./certs"]:
        Path(d).mkdir(parents=True, exist_ok=True)

    bus = get_bus()

    # Suscribir logger de eventos al bus
    @bus.on("*")
    async def log_all_events(data):
        pass  # Silencioso — los componentes tienen su propio logging

    @bus.on(Event.MISSION_STARTED)
    async def on_mission_started(data):
        log.info(f"[Main] ✅ Misión {data.get('mission_id')} arrancada correctamente")

    @bus.on(Event.FLAG_CAPTURED)
    async def on_flag(data):
        log.info(f"[Main] 🚩 FLAG: {data.get('value')}")

    @bus.on(Event.KILL_SWITCH)
    async def on_kill(data):
        log.critical(f"[Main] 🔴 KILL SWITCH activado: {data}")

    # Configuración de misión por defecto (el CLI la sobrescribe)
    d_cfg = cfg.get("director", {})
    mission = MissionConfig(
        profile    = d_cfg.get("default_profile", "balanced"),
        mode       = d_cfg.get("default_mode", "pentest"),
        parallel   = d_cfg.get("max_parallel_agents", 3),
        output_dir = d_cfg.get("output_dir", "./missions"),
    )

    director = Director(config=mission, bus=bus)

    log.info("[Main] Director listo. Esperando agentes...")
    log.info("[Main] Ejecuta 'argos start --help' para iniciar una misión.")

    # En modo servidor puro, el director espera agentes vía gRPC
    # El CLI (ui/cli.py) inyecta la configuración de misión antes de llamar a start()
    await director.start()


def main() -> None:
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        print("\n[Argos] Detenido por el usuario.")


if __name__ == "__main__":
    main()
