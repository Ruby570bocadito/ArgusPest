"""
ctf/defensive_shield.py
───────────────────────
Defensive Shield — Módulo de Defensa para CTF Attack/Defense (A/D).
Monitoriza servicios críticos, mantiene la integridad de archivos y vigila la red.
"""

import hashlib
import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List

try:
    import psutil
except ImportError:
    psutil = None

log = logging.getLogger("argos.defensive_shield")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


class ServiceMonitor:
    """Monitoriza servicios críticos y los reinicia si se detienen."""

    def __init__(self, services: List[str]):
        self.services = services

    def check_and_recover(self) -> None:
        """Verifica el estado de los servicios y los reinicia si es necesario."""
        for svc in self.services:
            if not self._is_active(svc):
                log.warning(f"🚨 [ServiceMonitor] Servicio caído detectado: {svc}. Intentando reiniciar...")
                self._restart_service(svc)

    def _is_active(self, service_name: str) -> bool:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True, text=True, timeout=2
            )
            return result.stdout.strip() == "active"
        except Exception as e:
            log.error(f"[ServiceMonitor] Error verificando {service_name}: {e}")
            return False

    def _restart_service(self, service_name: str) -> None:
        try:
            subprocess.run(["systemctl", "restart", service_name], check=True, timeout=5)
            log.info(f"✅ [ServiceMonitor] Servicio {service_name} reiniciado con éxito.")
        except subprocess.CalledProcessError:
            log.error(f"❌ [ServiceMonitor] Fallo al reiniciar {service_name}.")


class IntegrityGuard:
    """Mantiene backups de directorios críticos y los restaura si hay alteraciones."""

    def __init__(self, target_dirs: List[str], backup_base: str = "/tmp/.argos_shield_bkp"):
        self.target_dirs = [Path(d) for d in target_dirs if Path(d).exists()]
        self.backup_base = Path(backup_base)
        self.state: Dict[str, str] = {}
        self._init_backups()

    def _init_backups(self):
        """Crea copias de seguridad iniciales y calcula los hashes."""
        self.backup_base.mkdir(parents=True, exist_ok=True)
        for d in self.target_dirs:
            bkp_path = self.backup_base / d.name
            if bkp_path.exists():
                shutil.rmtree(bkp_path)
            shutil.copytree(d, bkp_path)
            log.info(f"🛡️ [IntegrityGuard] Backup creado para {d} en {bkp_path}")

            # Calcular estado inicial
            self._update_state(d)

    def _hash_file(self, path: Path) -> str:
        hasher = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    def _update_state(self, directory: Path):
        for item in directory.rglob("*"):
            if item.is_file():
                self.state[str(item)] = self._hash_file(item)

    def check_and_restore(self) -> None:
        """Verifica alteraciones en los archivos y restaura desde el backup si es necesario."""
        for d in self.target_dirs:
            altered = False
            # Check for modifications or deletions
            for file_str, original_hash in list(self.state.items()):
                if not file_str.startswith(str(d)):
                    continue

                current_path = Path(file_str)
                if not current_path.exists():
                    log.warning(f"⚠️ [IntegrityGuard] Archivo eliminado: {file_str}. Restaurando...")
                    altered = True
                elif self._hash_file(current_path) != original_hash:
                    log.warning(f"⚠️ [IntegrityGuard] Archivo modificado: {file_str}. Restaurando...")
                    altered = True

            # Check for new unauthorized files
            for item in d.rglob("*"):
                if item.is_file() and str(item) not in self.state:
                    log.warning(f"⚠️ [IntegrityGuard] Archivo no autorizado detectado: {item}. Eliminando...")
                    try:
                        item.unlink()
                    except Exception as e:
                        log.error(f"[IntegrityGuard] No se pudo eliminar {item}: {e}")

            # Restore the whole directory if altered
            if altered:
                self._restore_directory(d)

    def _restore_directory(self, d: Path):
        bkp_path = self.backup_base / d.name
        try:
            shutil.rmtree(d)
            shutil.copytree(bkp_path, d)
            log.info(f"✅ [IntegrityGuard] Directorio {d} restaurado exitosamente.")
        except Exception as e:
            log.error(f"❌ [IntegrityGuard] Fallo al restaurar {d}: {e}")


class NetworkWatcher:
    """Vigila las conexiones de red activas para detectar intrusos."""

    def __init__(self, allowed_ports: List[int]):
        self.allowed_ports = allowed_ports

    def check_connections(self) -> None:
        """Verifica si hay conexiones establecidas en puertos no autorizados."""
        if psutil is None:
            log.error("[NetworkWatcher] La librería 'psutil' no está instalada. Ejecuta: pip install psutil")
            return

        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    lport = conn.laddr.port
                    if lport not in self.allowed_ports:
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown"
                        log.warning(f"🌐 [NetworkWatcher] Conexión SOSPECHOSA ESTABLECIDA: Local Port {lport} <-> Remote {raddr} (PID: {conn.pid})")
        except psutil.AccessDenied:
            log.error("[NetworkWatcher] Permisos insuficientes para leer conexiones de red (requiere root).")
        except Exception as e:
            log.error(f"[NetworkWatcher] Error: {e}")


class DefensiveShield:
    """Escudo Defensivo Principal para A/D CTFs."""

    def __init__(self, services: List[str], dirs_to_protect: List[str], allowed_ports: List[int], interval: int = 5):
        self.interval = interval
        self.service_mon = ServiceMonitor(services)
        self.integrity_guard = IntegrityGuard(dirs_to_protect)
        self.net_watcher = NetworkWatcher(allowed_ports)

    def run_forever(self):
        log.info(f"🛡️ Iniciando Argos Defensive Shield. Intervalo: {self.interval}s")
        try:
            while True:
                self.service_mon.check_and_recover()
                self.integrity_guard.check_and_restore()
                self.net_watcher.check_connections()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            log.info("🛡️ Defensive Shield detenido.")


if __name__ == "__main__":
    # Ejemplo de configuración para proteger un servidor web típico en CTF
    critical_services = ["apache2", "mysql"]
    critical_dirs = ["/var/www/html", "/etc/apache2"]
    allowed_ports = [80, 443, 22, 3306]  # Puertos esperados para la máquina

    # En un entorno real se importaría y configuraría desde argos CLI
    shield = DefensiveShield(
        services=critical_services,
        dirs_to_protect=critical_dirs,
        allowed_ports=allowed_ports,
        interval=5
    )
    shield.run_forever()
