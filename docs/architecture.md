# Argos — Arquitectura Técnica v2.0

## Visión General

```
┌──────────────────────────────────────────────────────────────────┐
│                 OPERATOR (Human-in-the-Loop)                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  CLI        │  │  Dashboard  │  │  Decision Queue         │  │
│  │ (Click+Rich)│  │ (React/TS)  │  │  approve/reject/custom  │  │
│  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘  │
└─────────┼────────────────┼─────────────────────┼────────────────┘
          │ gRPC           │ gRPC-Web             │ gRPC
          ▼                ▼                      ▼
┌──────────────────────────────────────────────────────────────────┐
│                   DIRECTOR (Python 3.12)                         │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                 Motor de Decisión Híbrido                  │  │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌─────────┐  │  │
│  │  │  A*      │  │  CBR     │  │  Rules     │  │Fusion   │  │  │
│  │  │ Planner  │  │ (Qdrant) │  │  Engine    │  │Weighted │  │  │
│  │  │NetworkX  │  │Mini-LM   │  │  12+ svcs  │  │Scoring  │  │  │
│  │  └──────────┘  └──────────┘  └────────────┘  └─────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │              Grafo Vivo (Knowledge Tree)                    │  │
│  │  Hosts · Services · Credentials · Vulns · Flags · Defenses │  │
│  │  GlobalDefenseState (GDS 0.0–1.0) · Kill Switch @ 0.90    │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  EventBus   │  │  SQLite     │  │  Qdrant (embedded)      │  │
│  │  Async pub  │  │  WAL mode   │  │  CBR vector memory      │  │
│  │  /sub       │  │  Missions   │  │  384-dim embeddings     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└──────────────────────┬───────────────────────────────────────────┘
                       │ gRPC + Protobuf (Chameleon C2)
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                   FIELD AGENTS (Go 1.22)                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │  Stager  │ │   Cell   │ │  Recon   │ │  Exploit │           │
│  │ Mínimo   │ │ Completo │ │ TCP SYN  │ │ Modules  │           │
│  │ Register │ │ Persist  │ │ HTTP ban │ │ MSF wrap │           │
│  │ Beacon   │ │ Keylogger│ │ SMB/LDAP │ │ Custom   │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│  ┌──────────┐ ┌────────────────────────────────────┐            │
│  │ Evasion  │ │        Chameleon C2 Client         │            │
│  │AMSI/ETW  │ │ Protobuf → base64 → Teams/OneDrive │            │
│  │ Unhook   │ │ JSON → WebSocket → uTLS (JA3 spoof)│            │
│  │ Syscalls │ │ HBE: beacon timing = user activity │            │
│  └──────────┘ └────────────────────────────────────┘            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  Arsenal Factory                          │   │
│  │  rootkit · rat · virus · trojan · spyware · webshell     │   │
│  │  Garble + UPX mod + AES-GCM crypter + Loader polimórfico │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## Motor de Decisión Híbrido

### Flujo de Decisión

```
Nuevo hallazgo (servicio/host/vuln)
          │
          ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   A* Planner    │    │   CBR Memory    │    │  Rules Engine   │
│                 │    │                 │    │                 │
│ Grafo de ataque │    │ Qdrant: top-5   │    │ 12+ árboles de  │
│ → ruta óptima  │    │ casos similares │    │ decisión        │
│ P=0.45 del vote│    │ P=0.30 del vote │    │ P=0.25 del vote │
└────────┬────────┘    └────────┬────────┘    └────────┬────────┘
         └──────────────────────┴──────────────────────┘
                                │
                                ▼
                    ┌─────────────────────┐
                    │  Decision Fusion    │
                    │                    │
                    │ confidence = Σ(w×s)│
                    │ Ghost  thresh: 0.85│
                    │ Balanced     : 0.65│
                    │ Blitz        : 0.35│
                    └──────────┬──────────┘
                               │
              ┌────────────────┴─────────────────┐
              │                                  │
    conf > threshold                   conf ≤ threshold
    risk ≤ 0.8                         risk > 0.8
              │                                  │
              ▼                                  ▼
    ┌──────────────────┐              ┌──────────────────┐
    │  Auto-Execute    │              │  Decision Queue  │
    │  (if auto_decide │              │  Operator must   │
    │   or Blitz mode) │              │  approve/reject  │
    └──────────────────┘              └──────────────────┘
```

## Global Defense State (GDS)

| Evento              | Delta   | Nivel        | Acción de Agentes           |
|---------------------|---------|--------------|------------------------------|
| `edr_alert`         | +0.30   | yellow/red   | Reducir frecuencia de beacon |
| `honeypot_detected` | +0.60   | red/critical | Cambiar canal C2             |
| `agent_killed`      | +0.40   | red          | Hibernar agentes vecinos     |
| `scan_detected`     | +0.20   | yellow       | Pausar reconocimiento        |
| `timeout_no_activity`| -0.05  | —            | Decaimiento natural          |
| ≥ 0.90              | KILL SW | critical     | **Todos los agentes hibernan** |

## Stack Tecnológico

| Capa              | Tecnología                                    |
|-------------------|-----------------------------------------------|
| Orquestador       | Python 3.12, NetworkX, Qdrant, FastAPI, gRPC  |
| Motor de Decisión | A* + CBR (Mini-LM) + Rules Engine             |
| Agentes           | Go 1.22 + Garble (ofuscación)                 |
| Rootkits          | Rust + windows-rs / linux-kernel-module        |
| C2                | gRPC + Protobuf + WebSocket + uTLS (JA3 spoof)|
| Dashboard         | React 18, TypeScript, Cytoscape.js, gRPC-Web  |
| CLI               | Click + Rich + Textual                        |
| DB Local          | SQLite (WAL) + Qdrant (embebido)              |
| DB Central        | PostgreSQL 16                                 |
| Ofuscación        | Garble + UPX mod + AES-GCM + Loader polimórf.|

## Perfiles Operativos

| Perfil    | Umbral conf. | Peso sigilo | Beacon | Uso             |
|-----------|-------------|-------------|--------|-----------------|
| `ghost`   | 0.85        | 0.80        | 120s   | APT / Red Team  |
| `balanced`| 0.65        | 0.50        | 60s    | Pentest normal  |
| `blitz`   | 0.35        | 0.10        | 15s    | CTF / urgente   |

## Estructura del Repositorio

```
ArgusPest/
├── core/                 # Orquestador: Director, KT, Planner, CBR, Rules, Fusion
├── api/                  # Servidor gRPC (AgentC2 + OperatorConsole)
├── agents/
│   ├── stager/           # Agente mínimo Go (Register + Beacon)
│   └── cell/             # Agente completo Go (todos los módulos)
├── arsenal/              # Fábrica de malware (Builder + plantillas)
├── evasion/              # Chameleon C2 + traffic templates
├── ctf/                  # Flag Hunter + Auto-Submitter
├── ui/                   # CLI (Click + Rich + Textual)
├── database/             # SQLAlchemy models (SQLite WAL)
├── shared/proto/         # Protobuf definitions (argos.proto)
├── tests/                # Tests unitarios + Docker lab
├── docs/                 # Documentación técnica
├── config.yaml           # Configuración global
├── main.py               # Entry point del orquestador
├── requirements.txt      # Dependencias Python
├── pyproject.toml        # Metadata del paquete
└── Makefile              # Comandos de build/test/deploy
```

## Roadmap de Implementación

| Fase | Estado | Descripción |
|------|--------|-------------|
| **Fase 1: Fundación** | ✅ Completa | Estructura, Protobuf, Director, KT, Planner, CBR, Rules, Fusion, Stager Go, CLI, DB, Tests |
| **Fase 2: Escaneo** | 🔜 Pendiente | Motor de reconocimiento completo (nmap wrapper, banner grabbing, Scapy SYN) |
| **Fase 3: Arsenal** | 🔜 Pendiente | Fábrica completa (RAT, payload, webshell), Chameleon C2 Go, Metasploit RPC |
| **Fase 4: Post-Explot.** | 🔜 Pendiente | Persistencia adaptativa, keylogger, pivoteo automático, rootkit |
| **Fase 5: CTF y TUI** | 🔜 Pendiente | Flag Hunter integrado, Auto-Submitter, TUI Textual completa |
| **Fase 6: Beta** | 🔜 Pendiente | Pruebas HTB/THM, ampliación CBR, soporte macOS/ARM |
