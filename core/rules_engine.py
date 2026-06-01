"""
core/rules_engine.py
────────────────────
Motor de Reglas Heurísticas — Árboles de decisión tácticos por servicio/OS/defensa.
Sin dependencias de LLM: lógica experta definida en código + YAML de playbooks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("argos.rules_engine")

# ─────────────────────────── DATA CLASSES ────────────────────────

@dataclass
class TacticalAction:
    """Una acción táctica con su prioridad y metadatos."""
    action:        str
    params:        Dict[str, Any] = field(default_factory=dict)
    priority:      float = 0.5        # 0.0–1.0
    risk:          float = 0.5        # 0.0 (bajo) – 1.0 (alto)
    stealth:       float = 0.5        # 0.0 (ruidoso) – 1.0 (silencioso)
    needs_root:    bool  = False
    mitre_id:      Optional[str] = None
    description:   str   = ""

    def adjusted_priority(self, profile: str, defense_level: str) -> float:
        """Reajusta prioridad según perfil y nivel de defensa."""
        score = self.priority
        if profile == "ghost":
            # En ghost: favorece acciones silenciosas, penaliza las ruidosas
            score *= (0.5 + 0.5 * self.stealth)
            if defense_level in ("high", "critical"):
                score *= 0.6
        elif profile == "blitz":
            # En blitz: ignora sigilo, maximiza probabilidad de éxito
            score *= 1.2
            score = min(score, 1.0)
        # Penaliza si la defensa es alta y la acción es ruidosa
        if defense_level == "high" and self.risk > 0.7:
            score *= 0.5
        return round(score, 4)


# ─────────────────────────── RULES ENGINE ────────────────────────

class RulesEngine:
    """
    Evalúa el contexto táctico y devuelve acciones priorizadas.

    El motor tiene reglas built-in para los servicios más comunes.
    Adicionalmente, puede cargar playbooks YAML personalizados.
    """

    def evaluate(
        self,
        service:        Dict[str, Any],
        defense_level:  str = "none",   # none | low | medium | high | critical
        profile:        str = "balanced",
        os_type:        str = "unknown",
        owned:          bool = False,
    ) -> List[TacticalAction]:
        """
        Evalúa el contexto y devuelve acciones ordenadas por prioridad ajustada.

        service: {"name": str, "port": int, "version": str, "banner": str}
        """
        actions: List[TacticalAction] = []
        svc_name = service.get("name", "").lower()
        port     = int(service.get("port", 0))
        banner   = service.get("banner", "").lower()

        # ─ Despacho por nombre de servicio ─
        if svc_name in ("ssh", "openssh", "dropbear") or port == 22 or port == 2222:
            actions.extend(self._rules_ssh(service, defense_level, owned))

        elif svc_name in ("http", "https", "apache", "nginx", "iis", "tomcat") or port in (80, 443, 8080, 8443, 8172):
            actions.extend(self._rules_http(service, defense_level, os_type))

        elif svc_name in ("smb", "microsoft-ds", "netbios-ssn") or port in (445, 139):
            actions.extend(self._rules_smb(service, defense_level, os_type, owned))

        elif svc_name in ("ftp", "vsftpd", "proftpd") or port == 21:
            actions.extend(self._rules_ftp(service, defense_level))

        elif svc_name in ("mysql", "mariadb") or port == 3306:
            actions.extend(self._rules_mysql(service, defense_level))

        elif svc_name in ("mssql", "ms-sql-s") or port == 1433:
            actions.extend(self._rules_mssql(service, defense_level))

        elif svc_name in ("postgresql", "postgres") or port == 5432:
            actions.extend(self._rules_postgresql(service, defense_level))

        elif svc_name in ("rdp", "ms-wbt-server") or port == 3389:
            actions.extend(self._rules_rdp(service, defense_level, os_type))

        elif svc_name in ("redis",) or port == 6379:
            actions.extend(self._rules_redis(service, defense_level))

        elif svc_name in ("snmp",) or port in (161, 162):
            actions.extend(self._rules_snmp(service, defense_level))

        elif svc_name in ("ldap", "ldaps") or port in (389, 636, 3268, 3269):
            actions.extend(self._rules_ldap(service, defense_level))

        elif svc_name in ("winrm", "wsman") or port in (5985, 5986):
            actions.extend(self._rules_winrm(service, defense_level))

        elif svc_name in ("docker",) or port == 2375 or "docker" in banner:
            actions.extend(self._rules_docker(service, defense_level))

        elif svc_name in ("kubernetes", "kubelet") or port in (10250, 10255, 6443) or "kubernetes" in banner:
            actions.extend(self._rules_kubernetes(service, defense_level))

        else:
            actions.extend(self._rules_generic(service, defense_level))

        # Reajustar prioridades según perfil y ordenar
        for a in actions:
            a.priority = a.adjusted_priority(profile, defense_level)

        actions.sort(key=lambda a: a.priority, reverse=True)
        log.debug(f"[Rules] {svc_name}:{port} → {len(actions)} acciones (profile={profile}, defense={defense_level})")
        return actions

    # ─── SSH ──────────────────────────────────────────────────────

    def _rules_ssh(self, svc: dict, defense: str, owned: bool) -> List[TacticalAction]:
        actions = []
        version = svc.get("version", "").lower()

        if defense in ("none", "low"):
            actions.append(TacticalAction(
                action="ssh_brute_force",
                params={"wordlist": "rockyou_top1000", "user_list": "common_users"},
                priority=0.85, risk=0.6, stealth=0.3,
                mitre_id="T1110.001",
                description="Fuerza bruta de contraseñas SSH con lista corta",
            ))

        actions.append(TacticalAction(
            action="ssh_default_credentials",
            params={"creds": [
                ("root", "root"), ("admin", "admin"), ("ubuntu", "ubuntu"),
                ("pi", "raspberry"), ("admin", "password"), ("root", "toor"),
            ]},
            priority=0.75, risk=0.3, stealth=0.7,
            mitre_id="T1078.001",
            description="Probar credenciales por defecto en SSH",
        ))

        # CVE-2023-38408 (ssh-agent PKCS11)
        if "openssh" in version and any(v in version for v in ["8.9", "9.0", "9.1", "9.2"]):
            actions.append(TacticalAction(
                action="ssh_agent_pkcs11_CVE-2023-38408",
                params={"cve": "CVE-2023-38408"},
                priority=0.90, risk=0.7, stealth=0.5,
                mitre_id="T1203",
                description="Ejecución remota via ssh-agent PKCS11 forwarding",
            ))

        if owned:
            actions.append(TacticalAction(
                action="ssh_key_harvest",
                params={"paths": ["~/.ssh/", "/root/.ssh/", "/home/*/.ssh/"]},
                priority=0.80, risk=0.2, stealth=0.9,
                mitre_id="T1552.004",
                description="Recopilar claves SSH privadas del sistema comprometido",
            ))

        return actions

    # ─── HTTP ─────────────────────────────────────────────────────

    def _rules_http(self, svc: dict, defense: str, os_type: str) -> List[TacticalAction]:
        actions = []
        banner  = svc.get("banner", "").lower()
        version = svc.get("version", "").lower()
        port    = svc.get("port", 80)

        actions.append(TacticalAction(
            action="web_directory_enum",
            params={"wordlist": "dirbuster_medium", "extensions": ["php","asp","aspx","jsp","txt","bak"]},
            priority=0.80, risk=0.4, stealth=0.4,
            mitre_id="T1083",
            description="Enumeración de directorios y archivos web",
        ))

        actions.append(TacticalAction(
            action="web_vuln_scan_nuclei",
            params={"templates": ["cves", "exposures", "misconfigurations"]},
            priority=0.75, risk=0.5, stealth=0.3,
            mitre_id="T1190",
            description="Escaneo de vulnerabilidades web con Nuclei",
        ))

        # Apache 2.4.49/2.4.50 Path Traversal
        if "apache" in banner and any(v in version for v in ["2.4.49", "2.4.50"]):
            actions.append(TacticalAction(
                action="apache_path_traversal_CVE-2021-41773",
                params={"cve": "CVE-2021-41773", "check_cgi": True},
                priority=0.95, risk=0.7, stealth=0.4,
                mitre_id="T1190",
                description="Path Traversal + RCE en Apache 2.4.49/50",
            ))

        # Tomcat Manager
        if "tomcat" in banner or port == 8080:
            actions.append(TacticalAction(
                action="tomcat_manager_brute",
                params={"creds": [("admin","admin"),("tomcat","tomcat"),("manager","manager")]},
                priority=0.80, risk=0.5, stealth=0.4,
                mitre_id="T1078",
                description="Acceso al Tomcat Manager con credenciales por defecto",
            ))
            actions.append(TacticalAction(
                action="tomcat_manager_war_deploy",
                params={"needs_auth": True},
                priority=0.85, risk=0.7, stealth=0.3,
                mitre_id="T1505.003",
                description="Despliegue de WAR malicioso en Tomcat Manager",
            ))

        # IIS Web Deploy
        if "iis" in banner and port == 8172:
            actions.append(TacticalAction(
                action="iis_webdeploy_default_creds",
                params={"creds": [("admin","admin"),("administrator","password")]},
                priority=0.85, risk=0.5, stealth=0.5,
                mitre_id="T1078",
                description="Web Deploy IIS con credenciales por defecto",
            ))

        if defense in ("none", "low"):
            actions.append(TacticalAction(
                action="web_sql_injection_scan",
                params={"tool": "sqlmap", "level": 3, "risk": 2},
                priority=0.70, risk=0.6, stealth=0.2,
                mitre_id="T1190",
                description="Escaner SQLi automatizado con SQLMap",
            ))

        return actions

    # ─── SMB ──────────────────────────────────────────────────────

    def _rules_smb(self, svc: dict, defense: str, os_type: str, owned: bool) -> List[TacticalAction]:
        actions = []

        actions.append(TacticalAction(
            action="smb_enum_shares",
            params={"tool": "crackmapexec"},
            priority=0.85, risk=0.3, stealth=0.6,
            mitre_id="T1135",
            description="Enumerar shares SMB (anon + credenciales)",
        ))

        # EternalBlue — solo si Windows antiguo
        if os_type in ("windows", "unknown") and defense in ("none", "low"):
            actions.append(TacticalAction(
                action="smb_eternalblue_MS17-010",
                params={"cve": "CVE-2017-0144", "payload": "reverse_shell_x64"},
                priority=0.90, risk=0.9, stealth=0.1,
                mitre_id="T1210",
                description="EternalBlue — RCE sin autenticación (Win7/2008)",
            ))

        actions.append(TacticalAction(
            action="smb_pass_the_hash",
            params={"requires": "ntlm_hash"},
            priority=0.80, risk=0.6, stealth=0.5,
            mitre_id="T1550.002",
            description="Pass-the-Hash via SMB con hash NTLM capturado",
        ))

        if owned:
            actions.append(TacticalAction(
                action="smb_lateral_psexec",
                params={"tool": "impacket_psexec"},
                priority=0.75, risk=0.7, stealth=0.3,
                mitre_id="T1021.002",
                description="Movimiento lateral via PsExec sobre SMB",
            ))

        return actions

    # ─── FTP ──────────────────────────────────────────────────────

    def _rules_ftp(self, svc: dict, defense: str) -> List[TacticalAction]:
        actions = []
        banner = svc.get("banner", "").lower()

        if "vsftp" in banner and "2.3.4" in svc.get("version", ""):
            actions.append(TacticalAction(
                action="vsftpd_backdoor_CVE-2011-2523",
                params={"cve": "CVE-2011-2523"},
                priority=0.95, risk=0.5, stealth=0.6,
                mitre_id="T1190",
                description="Backdoor en vsftpd 2.3.4 — shell en puerto 6200",
            ))

        if "proftpd" in banner and "1.3.5" in svc.get("version", ""):
            actions.append(TacticalAction(
                action="proftpd_modcopy_CVE-2015-3306",
                params={"cve": "CVE-2015-3306"},
                priority=0.90, risk=0.6, stealth=0.5,
                mitre_id="T1190",
                description="mod_copy file write via ProFTPD 1.3.5",
            ))

        actions.append(TacticalAction(
            action="ftp_anonymous_login",
            params={},
            priority=0.80, risk=0.1, stealth=0.9,
            mitre_id="T1078.001",
            description="Intentar login anónimo FTP",
        ))

        if defense in ("none", "low"):
            actions.append(TacticalAction(
                action="ftp_brute_force",
                params={"user_list": "ftp_users", "wordlist": "common_passwords"},
                priority=0.60, risk=0.5, stealth=0.3,
                mitre_id="T1110.001",
                description="Fuerza bruta FTP",
            ))

        return actions

    # ─── MYSQL ────────────────────────────────────────────────────

    def _rules_mysql(self, svc: dict, defense: str) -> List[TacticalAction]:
        return [
            TacticalAction(
                action="mysql_default_credentials",
                params={"creds": [("root", ""), ("root", "root"), ("root", "mysql")]},
                priority=0.85, risk=0.3, stealth=0.7,
                mitre_id="T1078", description="Credenciales por defecto MySQL",
            ),
            TacticalAction(
                action="mysql_udf_privilege_escalation",
                params={"requires": "mysql_auth"},
                priority=0.80, risk=0.7, stealth=0.4,
                mitre_id="T1548", description="Escalada de privilegios via UDF en MySQL",
            ),
            TacticalAction(
                action="mysql_file_read",
                params={"target": "/etc/passwd"},
                priority=0.70, risk=0.4, stealth=0.6,
                mitre_id="T1005", description="Lectura de archivos locales via LOAD_FILE()",
            ),
        ]

    # ─── MSSQL ────────────────────────────────────────────────────

    def _rules_mssql(self, svc: dict, defense: str) -> List[TacticalAction]:
        return [
            TacticalAction(
                action="mssql_sa_brute",
                params={"user": "sa", "wordlist": "top500"},
                priority=0.80, risk=0.5, stealth=0.4,
                mitre_id="T1110.001", description="Fuerza bruta a cuenta SA de MSSQL",
            ),
            TacticalAction(
                action="mssql_xp_cmdshell",
                params={"requires": "mssql_auth", "enable_if_disabled": True},
                priority=0.90, risk=0.8, stealth=0.2,
                mitre_id="T1505", description="Ejecución de comandos via xp_cmdshell en MSSQL",
            ),
            TacticalAction(
                action="mssql_linked_server_pivot",
                params={"requires": "mssql_auth"},
                priority=0.70, risk=0.5, stealth=0.6,
                mitre_id="T1021", description="Pivoteo via Linked Servers en MSSQL",
            ),
        ]

    # ─── POSTGRESQL ───────────────────────────────────────────────

    def _rules_postgresql(self, svc: dict, defense: str) -> List[TacticalAction]:
        return [
            TacticalAction(
                action="postgresql_default_creds",
                params={"creds": [("postgres", "postgres"), ("postgres", "password")]},
                priority=0.80, risk=0.3, stealth=0.7,
                mitre_id="T1078", description="Credenciales por defecto PostgreSQL",
            ),
            TacticalAction(
                action="postgresql_copy_rce",
                params={"requires": "pg_auth", "method": "COPY TO/FROM PROGRAM"},
                priority=0.85, risk=0.7, stealth=0.4,
                mitre_id="T1059", description="RCE via COPY TO/FROM PROGRAM en PostgreSQL",
            ),
        ]

    # ─── RDP ──────────────────────────────────────────────────────

    def _rules_rdp(self, svc: dict, defense: str, os_type: str) -> List[TacticalAction]:
        actions = []
        if defense in ("none", "low"):
            actions.append(TacticalAction(
                action="rdp_bluekeep_CVE-2019-0708",
                params={"cve": "CVE-2019-0708"},
                priority=0.85, risk=0.9, stealth=0.1,
                mitre_id="T1210", description="BlueKeep — RCE sin auth en RDP (pre-Win8)",
            ))
            actions.append(TacticalAction(
                action="rdp_brute_force",
                params={"user_list": "windows_users", "wordlist": "top200"},
                priority=0.65, risk=0.6, stealth=0.2,
                mitre_id="T1110.001", description="Fuerza bruta RDP",
            ))
        actions.append(TacticalAction(
            action="rdp_pass_the_hash",
            params={"requires": "ntlm_hash", "tool": "xfreerdp_pth"},
            priority=0.75, risk=0.5, stealth=0.5,
            mitre_id="T1550.002", description="RDP Pass-the-Hash con hash NTLM",
        ))
        return actions

    # ─── REDIS ────────────────────────────────────────────────────

    def _rules_redis(self, svc: dict, defense: str) -> List[TacticalAction]:
        return [
            TacticalAction(
                action="redis_unauth_access",
                params={},
                priority=0.90, risk=0.2, stealth=0.9,
                mitre_id="T1078", description="Acceso Redis sin autenticación",
            ),
            TacticalAction(
                action="redis_config_rewrite_rce",
                params={"method": "cron_or_authorized_keys"},
                priority=0.85, risk=0.6, stealth=0.5,
                mitre_id="T1059", description="RCE via CONFIG REWRITE en Redis (cron/SSH keys)",
            ),
        ]

    # ─── SNMP ─────────────────────────────────────────────────────

    def _rules_snmp(self, svc: dict, defense: str) -> List[TacticalAction]:
        return [
            TacticalAction(
                action="snmp_community_enum",
                params={"communities": ["public", "private", "community", "manager"]},
                priority=0.90, risk=0.1, stealth=0.9,
                mitre_id="T1602.001", description="Enumeración SNMP con community strings comunes",
            ),
            TacticalAction(
                action="snmp_walk_full",
                params={"oid": "1.3.6.1", "requires": "snmp_auth"},
                priority=0.80, risk=0.2, stealth=0.8,
                mitre_id="T1602", description="SNMP Walk completo para extraer configuración",
            ),
        ]

    # ─── LDAP ─────────────────────────────────────────────────────

    def _rules_ldap(self, svc: dict, defense: str) -> List[TacticalAction]:
        return [
            TacticalAction(
                action="ldap_anonymous_bind",
                params={},
                priority=0.85, risk=0.1, stealth=0.9,
                mitre_id="T1087.002", description="LDAP Anonymous Bind — enumeración AD",
            ),
            TacticalAction(
                action="ldap_kerberoasting",
                params={"requires": "domain_user"},
                priority=0.80, risk=0.4, stealth=0.7,
                mitre_id="T1558.003", description="Kerberoasting — extracción de tickets TGS",
            ),
            TacticalAction(
                action="ldap_asrep_roasting",
                params={"requires": "user_list"},
                priority=0.75, risk=0.3, stealth=0.8,
                mitre_id="T1558.004", description="AS-REP Roasting — hashes sin preauth",
            ),
        ]

    # ─── WINRM ────────────────────────────────────────────────────

    def _rules_winrm(self, svc: dict, defense: str) -> List[TacticalAction]:
        return [
            TacticalAction(
                action="winrm_default_creds",
                params={"creds": [("administrator", "password"), ("admin", "admin")]},
                priority=0.80, risk=0.5, stealth=0.5,
                mitre_id="T1021.006", description="WinRM con credenciales por defecto",
            ),
            TacticalAction(
                action="winrm_pass_the_hash",
                params={"requires": "ntlm_hash", "tool": "evil-winrm"},
                priority=0.85, risk=0.5, stealth=0.6,
                mitre_id="T1550.002", description="WinRM Pass-the-Hash con Evil-WinRM",
            ),
        ]

    # ─── DOCKER ───────────────────────────────────────────────────

    def _rules_docker(self, svc: dict, defense: str) -> List[TacticalAction]:
        return [
            TacticalAction(
                action="docker_api_unauth_exec",
                params={"container": "random"},
                priority=0.90, risk=0.4, stealth=0.6,
                mitre_id="T1609", description="Ejecución de código en contenedor existente vía API expuesta",
            ),
            TacticalAction(
                action="docker_api_host_mount_escape",
                params={"image": "alpine", "mount": "/"},
                priority=0.85, risk=0.8, stealth=0.3,
                mitre_id="T1611", description="Privilege Escalation montando el directorio raíz del Host",
            ),
        ]

    # ─── KUBERNETES ───────────────────────────────────────────────

    def _rules_kubernetes(self, svc: dict, defense: str) -> List[TacticalAction]:
        return [
            TacticalAction(
                action="kubelet_unauth_read_pods",
                params={"endpoint": "/pods"},
                priority=0.85, risk=0.1, stealth=0.9,
                mitre_id="T1526", description="Lectura no autenticada de pods vía Kubelet (puerto 10250/10255)",
            ),
            TacticalAction(
                action="kubelet_unauth_exec",
                params={"cmd": "sh"},
                priority=0.90, risk=0.7, stealth=0.5,
                mitre_id="T1609", description="Ejecución remota en pod vía Kubelet API sin autenticar",
            ),
        ]

    # ─── GENERIC ──────────────────────────────────────────────────

    def _rules_generic(self, svc: dict, defense: str) -> List[TacticalAction]:
        return [
            TacticalAction(
                action="banner_grab",
                params={"port": svc.get("port")},
                priority=0.70, risk=0.05, stealth=0.95,
                mitre_id="T1046", description="Banner grabbing para identificar versión",
            ),
            TacticalAction(
                action="service_version_exploit_search",
                params={"service": svc.get("name"), "version": svc.get("version")},
                priority=0.60, risk=0.2, stealth=0.8,
                mitre_id="T1203", description="Buscar exploits por versión en base de CVEs",
            ),
        ]
