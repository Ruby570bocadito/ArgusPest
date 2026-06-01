"""
core/cbr.py
───────────
Case-Based Reasoning — Memoria semántica de misiones pasadas.
Usa Qdrant (embebido) + Sentence-Transformers (all-MiniLM-L6-v2, 80MB, CPU).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

log = logging.getLogger("argos.cbr")

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, PointStruct, VectorParams
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False
    log.warning("[CBR] qdrant_client no instalado — CBR desactivado")

try:
    from sentence_transformers import SentenceTransformer
    ST_AVAILABLE = True
except ImportError:
    ST_AVAILABLE = False
    log.warning("[CBR] sentence_transformers no instalado — CBR desactivado")

VECTOR_SIZE    = 384        # all-MiniLM-L6-v2
COLLECTION     = "argos_cases"


class CaseBasedReasoner:
    """
    Aprende de cada operación.

    Cada caso almacena:
      - Descripción semántica del servicio/contexto (vector 384-dim)
      - Acción tomada (exploit, técnica, módulo)
      - Resultado (éxito/fallo)
      - Contexto adicional (OS, defensa detectada, perfil)

    En inferencia, busca los k casos más similares y propone
    las acciones con mayor tasa de éxito.
    """

    def __init__(self, db_path: str = "./data/qdrant") -> None:
        self.enabled = QDRANT_AVAILABLE and ST_AVAILABLE
        if not self.enabled:
            log.warning("[CBR] Modo degradado: sin memoria de casos")
            return

        self.client = QdrantClient(path=db_path)
        self.model  = SentenceTransformer("all-MiniLM-L6-v2")
        self._ensure_collection()
        log.info("[CBR] Inicializado — Qdrant listo en %s", db_path)

    # ─── WRITE ────────────────────────────────────────────────────

    def add_case(
        self,
        description: str,
        action:      str,
        success:     bool,
        context:     Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Almacena un caso nuevo.

        description: Texto libre que describe el servicio/situación.
                     Ej: "Apache 2.4.49 en Ubuntu 20.04, puerto 80, sin WAF"
        action:      Técnica usada. Ej: "path_traversal_CVE-2021-41773"
        success:     Si la acción funcionó.
        context:     Metadatos extras (os, edr, profile, etc.)
        """
        if not self.enabled:
            return None

        case_id = str(uuid.uuid4())
        vector  = self._encode(description)
        payload = {
            "description": description,
            "action":      action,
            "success":     success,
            "context":     context or {},
        }

        self.client.upsert(
            collection_name=COLLECTION,
            points=[PointStruct(id=case_id, vector=vector, payload=payload)],
        )
        log.debug(f"[CBR] Caso añadido: {action} → success={success}")
        return case_id

    def update_result(self, case_id: str, success: bool) -> None:
        """Actualiza el resultado de un caso existente."""
        if not self.enabled:
            return
        self.client.set_payload(
            collection_name=COLLECTION,
            payload={"success": success},
            points=[case_id],
        )

    # ─── READ ─────────────────────────────────────────────────────

    def query_similar(
        self,
        description: str,
        top_k:       int  = 5,
        only_success: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Busca los k casos más similares y devuelve acciones ordenadas por
        similitud × tasa de éxito.
        """
        if not self.enabled:
            return []

        vector  = self._encode(description)
        results = self.client.search(
            collection_name=COLLECTION,
            query_vector=vector,
            limit=top_k * 2 if only_success else top_k,
            with_payload=True,
        )

        cases = []
        for r in results:
            if only_success and not r.payload.get("success", False):
                continue
            cases.append({
                "action":      r.payload.get("action", ""),
                "success":     r.payload.get("success", False),
                "description": r.payload.get("description", ""),
                "context":     r.payload.get("context", {}),
                "similarity":  round(r.score, 4),
                # score combinado: similitud × boost de éxito
                "weighted_score": round(r.score * (1.3 if r.payload.get("success") else 0.6), 4),
            })

        cases.sort(key=lambda c: c["weighted_score"], reverse=True)
        return cases[:top_k]

    def best_actions(self, description: str, top_k: int = 3) -> List[str]:
        """Shortcut: devuelve solo los nombres de las mejores acciones."""
        cases = self.query_similar(description, top_k=top_k, only_success=True)
        # Deduplicar manteniendo orden
        seen, result = set(), []
        for c in cases:
            if c["action"] not in seen:
                seen.add(c["action"])
                result.append(c["action"])
        return result

    def stats(self) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}
        info = self.client.get_collection(COLLECTION)
        return {
            "enabled":    True,
            "total_cases": info.points_count,
            "collection": COLLECTION,
        }

    # ─── INTERNAL ─────────────────────────────────────────────────

    def _encode(self, text: str) -> List[float]:
        return self.model.encode(text, normalize_embeddings=True).tolist()

    def _ensure_collection(self) -> None:
        try:
            self.client.get_collection(COLLECTION)
        except Exception:
            self.client.create_collection(
                collection_name=COLLECTION,
                vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
            )
            log.info("[CBR] Colección '%s' creada", COLLECTION)


# ─────────────────────────── SEED DATA ───────────────────────────

DEFAULT_CASES = [
    # SSH
    ("OpenSSH 7.4 en CentOS 7, puerto 22, sin WAF", "ssh_brute_rockyou", True,
     {"os": "linux", "edr": "none"}),
    ("OpenSSH 8.9 en Ubuntu 22.04, puerto 22",      "ssh_default_creds", False,
     {"os": "linux", "edr": "none"}),
    ("Dropbear SSH 2022.83, puerto 2222",            "ssh_brute_common",  True,
     {"os": "linux", "edr": "none"}),

    # HTTP / Web
    ("Apache 2.4.49 en Ubuntu 20.04, puerto 80",    "path_traversal_CVE-2021-41773", True,
     {"os": "linux", "edr": "none"}),
    ("IIS 10.0 en Windows Server 2019, puerto 8172","iis_webdeploy_default_creds",   True,
     {"os": "windows", "edr": "defender"}),
    ("Nginx 1.18 reverse proxy, puerto 443",        "nginx_header_injection",        False,
     {"os": "linux", "edr": "none"}),
    ("Tomcat 9.0.56, puerto 8080, /manager expuesto","tomcat_manager_deploy_war",    True,
     {"os": "linux", "edr": "none"}),

    # SMB / Windows
    ("SMB Windows 7 SP1, puerto 445",               "ms17_010_eternalblue",          True,
     {"os": "windows", "edr": "none"}),
    ("SMB Windows 10 con Defender, puerto 445",     "smb_psexec_hash",               False,
     {"os": "windows", "edr": "defender"}),
    ("SMB Server 2012 R2, NTLM habilitado",         "smb_pass_the_hash",             True,
     {"os": "windows", "edr": "none"}),

    # FTP
    ("vsftpd 2.3.4, puerto 21",                     "vsftpd_backdoor_CVE-2011-2523", True,
     {"os": "linux", "edr": "none"}),
    ("ProFTPD 1.3.5, puerto 21",                    "proftpd_modcopy_CVE-2015-3306", True,
     {"os": "linux", "edr": "none"}),

    # RDP
    ("RDP Windows Server 2016, puerto 3389",        "rdp_bluekeep_CVE-2019-0708",    True,
     {"os": "windows", "edr": "none"}),

    # Databases
    ("MySQL 5.7, puerto 3306, root sin contraseña", "mysql_udf_privesc",             True,
     {"os": "linux", "edr": "none"}),
    ("MSSQL 2019, puerto 1433, sa habilitado",      "mssql_xp_cmdshell",             True,
     {"os": "windows", "edr": "none"}),
    ("PostgreSQL 14, puerto 5432, acceso remoto",   "postgresql_copy_to_rce",        True,
     {"os": "linux", "edr": "none"}),

    # SNMP / Other
    ("SNMP v2c con community 'public', UDP 161",    "snmp_community_enum",           True,
     {"os": "linux", "edr": "none"}),
    ("Redis 6.x sin autenticación, puerto 6379",    "redis_config_rewrite_rce",      True,
     {"os": "linux", "edr": "none"}),
]


def seed_default_cases(cbr: CaseBasedReasoner) -> int:
    """Siembra la base de casos con conocimiento inicial."""
    if not cbr.enabled:
        return 0
    seeded = 0
    for desc, action, success, ctx in DEFAULT_CASES:
        cbr.add_case(desc, action, success, ctx)
        seeded += 1
    log.info(f"[CBR] {seeded} casos semilla cargados")
    return seeded
