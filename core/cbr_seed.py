"""
core/cbr_seed.py
────────────────
Inyector de Inteligencia para el CBR (Case-Based Reasoner).
Carga un dataset de tácticas de MITRE ATT&CK para dotar al Orquestador de memoria histórica.
"""

import logging

from core.cbr import CaseBasedReasoner

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("CBR-Seeder")

# Dataset simulado de tácticas ofensivas exitosas
TACTICS_DB = [
    {
        "description": "Explotación de puerto 445 SMB en Windows Server antiguo con vulnerabilidad MS17-010 (EternalBlue). Proporciona acceso de sistema.",
        "metadata": {
            "technique": "ms17_010_eternalblue",
            "port": 445,
            "service": "smb",
            "os": "windows",
            "success_rate": 0.95
        }
    },
    {
        "description": "Fuerza bruta sobre puerto 22 SSH usando lista de credenciales comunes. Efectivo si no hay fail2ban configurado.",
        "metadata": {
            "technique": "ssh_bruteforce",
            "port": 22,
            "service": "ssh",
            "os": "linux",
            "success_rate": 0.40
        }
    },
    {
        "description": "Inyección de SQL en puerto 80/443 (HTTP/S) contra parámetros vulnerables GET/POST. Permite volcado de DB.",
        "metadata": {
            "technique": "sql_injection",
            "port": 80,
            "service": "http",
            "os": "any",
            "success_rate": 0.65
        }
    },
    {
        "description": "Ataque Kerberoasting en el puerto 88 de Controladores de Dominio. Extrae hashes de tickets de servicio.",
        "metadata": {
            "technique": "kerberoasting",
            "port": 88,
            "service": "kerberos",
            "os": "windows",
            "success_rate": 0.85
        }
    }
]

def seed_intelligence():
    log.info("🧠 Inicializando el Case-Based Reasoner (CBR)...")
    cbr = CaseBasedReasoner(db_path="./data/qdrant")

    if not cbr.enabled:
        log.error("❌ CBR está desactivado. Asegúrate de instalar qdrant-client y sentence-transformers.")
        return

    log.info(f"💉 Inyectando {len(TACTICS_DB)} casos de MITRE ATT&CK en la memoria vectorial...")

    for case in TACTICS_DB:
        cbr.add_case(
            description=case["description"],
            action=case["metadata"]["technique"],
            success=case["metadata"]["success_rate"] > 0.5,
            context=case["metadata"],
        )
        log.info(f"   [+] Añadido caso: {case['metadata']['technique']}")

    log.info("\n✅ Memoria inyectada. ARGOS ahora recuerda estas tácticas.")

if __name__ == "__main__":
    seed_intelligence()
