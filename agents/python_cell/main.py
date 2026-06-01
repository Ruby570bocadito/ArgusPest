"""
agents/python_cell/main.py
──────────────────────────
Agente de campo completo escrito en Python.
Permite testear la comunicación gRPC real sin necesidad de compilar Go.
"""

import asyncio
import logging
import platform
import random
import sys
from pathlib import Path

# Añadir la raíz al path para poder importar los protobufs
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import grpc

from shared.proto import argos_pb2, argos_pb2_grpc

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("PythonCell")

class PythonAgent:
    def __init__(self, host="localhost", port=50051):
        self.target = f"{host}:{port}"
        self.agent_id = f"py-cell-{random.randint(1000,9999)}"
        self.channel = None
        self.stub = None

    async def start(self):
        log.info(f"🐍 [PyCell] Iniciando agente Python. ID: {self.agent_id}")

        # Conexión gRPC
        self.channel = grpc.aio.insecure_channel(self.target)
        self.stub = argos_pb2_grpc.AgentC2Stub(self.channel)

        await self.register()

        # Bucle de Beacon (stream bidireccional)
        try:
            while True:
                await self.send_beacon()
                await asyncio.sleep(5)
        except asyncio.CancelledError:
            log.info("🐍 [PyCell] Apagando agente...")
        finally:
            await self.channel.close()

    async def register(self):
        log.info("🐍 [PyCell] Registrando en el Director...")
        req = argos_pb2.AgentInfo(
            agent_id=self.agent_id,
            hostname=platform.node(),
            ip="127.0.0.1",
            os=platform.system().lower(),
            arch=platform.machine().lower(),
            version="2.0.0",
        )
        try:
            resp = await self.stub.Register(req)
            log.info(f"🐍 [PyCell] ¡Registro Exitoso! Beacon interval: {resp.beacon_interval_sec}s")
        except grpc.RpcError as e:
            log.error(f"🐍 [PyCell] Error de registro: {e}")

    async def send_beacon(self):
        log.debug("🐍 [PyCell] Enviando beacon...")
        req = argos_pb2.AgentEvent(
            agent_id=self.agent_id,
            type=argos_pb2.HEARTBEAT,
        )
        try:
            async for resp in self.stub.Beacon(iter([req])):
                if resp.type == argos_pb2.SLEEP:
                    log.info("🐍 [PyCell] Recibido comando: SLEEP (GDS Kill Switch activo)")
                elif resp.type != argos_pb2.SCAN:
                    log.info(f"🐍 [PyCell] Recibido comando: tipo={resp.type}")
        except grpc.RpcError as e:
            log.error(f"🐍 [PyCell] Error de conexión con el Director: {e}")

if __name__ == "__main__":
    agent = PythonAgent()
    try:
        asyncio.run(agent.start())
    except KeyboardInterrupt:
        pass
