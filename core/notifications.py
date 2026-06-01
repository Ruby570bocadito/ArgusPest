"""
core/notifications.py
─────────────────────
Módulo para enviar notificaciones a canales de Discord/Slack mediante Webhooks.
"""

import logging
from typing import Any, Dict, Optional

try:
    import httpx
except ImportError:
    httpx = None

log = logging.getLogger("argos.notifications")

class WebhookNotifier:
    def __init__(self, config: Dict[str, Any]):
        self.webhook_url: Optional[str] = config.get("webhook_url")
        self.enabled: bool = bool(self.webhook_url and httpx is not None)
        if self.webhook_url and httpx is None:
            log.warning("Webhook URL configurada, pero 'httpx' no está instalado. Ejecuta: pip install httpx")

    async def send_alert(self, title: str, description: str, color: int = 0x00FF00) -> None:
        """Envia una alerta al webhook (formato Discord)."""
        if not self.enabled:
            return

        payload = {
            "embeds": [{
                "title": title,
                "description": description,
                "color": color,
                "footer": {"text": "ARGOS C2 — Notification System"}
            }]
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(self.webhook_url, json=payload, timeout=5.0)
                resp.raise_for_status()
        except Exception as e:
            log.error(f"[Notifier] Error enviando webhook: {e}")

    async def notify_flag(self, flag_value: str, host_ip: str) -> None:
        await self.send_alert(
            title="🚩 FLAG CAPTURADA",
            description=f"**Valor:** `{flag_value}`\n**Host:** `{host_ip}`",
            color=0x00FF00  # Verde
        )

    async def notify_agent_dead(self, agent_id: str) -> None:
        await self.send_alert(
            title="🔴 AGENTE PERDIDO",
            description=f"El agente **{agent_id}** ha dejado de reportar.",
            color=0xFF0000  # Rojo
        )

    async def notify_host_owned(self, host_ip: str) -> None:
        await self.send_alert(
            title="🔥 HOST COMPROMETIDO",
            description=f"Se obtuvo sesión de alto privilegio en **{host_ip}**.",
            color=0xFFA500  # Naranja
        )
