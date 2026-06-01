# ARGOS v2.0

**Semi-Autonomous Offensive Operations Platform**  
APT emulation  ·  Hybrid decision engine  ·  Human-in-the-Loop

---

## Quick Start

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Interactive console (recomendado)
python argos_console.py
```

Dentro de la consola:

```
argos> guide             # Explica la arquitectura y el flujo
argos> start             # Inicia una mision
argos> demo              # Demo narrada de 6 fases con el motor de decision
argos> lab               # Verifica el laboratorio (6 targets vulnerables)
argos> status            # Estado detallado de la mision
argos> test unit         # Corre los 34 tests unitarios
argos> help              # Todos los comandos
```

Tambien podes usar la CLI tradicional:

```bash
python ui/cli.py start -t 10.0.0.0/24 -g domain_admin -p balanced
python ui/cli.py dashboard          # TUI a pantalla completa
python ui/cli.py arsenal build stager --os linux --arch amd64
```

## Console Commands

```
argos> guide               Arquitectura y flujo de ARGOS
argos> start [t] [g] [p]   Iniciar mision (default: 10.100.0.0/24 domain_admin balanced)
argos> start --auto        Iniciar con auto-aprobacion
argos> demo [--fast]       Demo narrada de 6 fases
argos> status              Estado detallado
argos> agent register ...  Registrar agente
argos> agent list           Listar agentes
argos> agent find ...       Simular hallazgo
argos> decide list          Decisiones pendientes
argos> decide approve <id>  Aprobar (HITL)
argos> decide reject <id>   Rechazar (HITL)
argos> lab                  Laboratorio (6 targets)
argos> test unit            34 tests
argos> quit                 Salir
```

---

## Project Structure

```
├── main.py              # Director entrypoint
├── config.yaml          # Global config
├── pyproject.toml       # Dependencies & tooling
├── core/                # Decision engine
│   ├── director.py      # Mission orchestrator
│   ├── event_bus.py     # Async pub/sub
│   ├── knowledge_tree.py# Live World Graph (NetworkX)
│   ├── planner.py       # A* attack path planner
│   ├── cbr.py           # Case-Based Reasoner (Qdrant + embeddings)
│   ├── rules_engine.py  # Tactical rules (~500 lines, 10+ services)
│   ├── decision_fusion.py# Weighted fusion of 3 engines
│   ├── recon_manager.py # Auto-recon dispatch
│   ├── exploit_manager.py# Exploit dispatch (agent / MSF)
│   └── msf_rpc.py       # Metasploit RPC integration
├── database/            # SQLAlchemy models (SQLite WAL)
├── api/                 # gRPC server (protobuf)
├── ui/                  # CLI (Click + Rich) & TUI (Textual)
├── arsenal/             # Malware factory
│   ├── builder.py       # Go/Rust compiler + obfuscation
│   └── crypter.py       # AES-GCM payload crypter + Go loader gen
├── evasion/             # Traffic camouflage (Chameleon C2)
├── ctf/                 # Flag hunter + auto-submitter
├── agents/              # Go field agents
│   ├── stager/          # Initial access payload
│   ├── cell/            # Full persistent agent
│   │   ├── recon/       # Port scanner + SMB enum
│   │   ├── exploit/     # Shellcode injection (syscalls)
│   │   └── post/        # Credential dump + persistence
│   └── python_cell/     # Python test agent
├── tests/               # Test suite
│   ├── test_director.py # 36 unit tests (core engine)
│   ├── mock_agent.py    # Event bus simulation
│   ├── demo_integration.py# End-to-end demo
│   └── docker-compose-lab.yml# Vulnerable lab (6 targets)
└── shared/proto/        # Protobuf schema
```

---

## Decision Engine

The Director evaluates the battlefield via a **Live World Graph** (NetworkX MultiDiGraph). Each agent discovery (host, service, credential, flag) updates the graph. To decide the next move:

| Engine | Weight | How |
|--------|--------|-----|
| **A* Planner** | 45% | Finds silent/fast routes through exploit edges to the goal |
| **CBR Memory** | 30% | Vector similarity search (Qdrant + SentenceTransformers) — what worked before? |
| **Rules Engine** | 25% | Deterministic rules for known services (SSH → brute, SMB 445 + Win7 → EternalBlue, etc.) |

The **Global Defense State (GDS)** tracks enemy network paranoia (0.0–1.0). At 0.90, the **Kill Switch** triggers — all agents hibernate.

---

## Go Agents

```bash
# Compile stager (initial access)
make build-stager          # plain: agents/stager/stager.exe
make build-stager-obf      # garble-obfuscated

# Compile cell (full agent)
make build-cell            # agents/cell/cell.exe

# Cross-compile for Linux
make build-stager-linux
```

---

## Docker Lab

```bash
docker-compose -f tests/docker-compose-lab.yml up -d
```

Launches on `10.100.0.0/24`:
- **10.100.0.20** — Apache 2.4.49 (CVE-2021-41773)
- **10.100.0.21** — SSH weak credentials (admin:admin123)
- **10.100.0.22** — MySQL 5.7 no auth
- **10.100.0.23** — vsftpd 2.3.4 backdoor (CVE-2011-2523)
- **10.100.0.24** — Redis no auth
- **10.100.0.30** — DVWA web app

```bash
docker-compose -f tests/docker-compose-lab.yml down
```

---

## Testing

```bash
# Full suite (34 pass, 2 skip for ML deps)
pytest tests/ -v --tb=short

# Fast — skip CBR/ML tests
pytest tests/ -v --tb=short -k "not cbr"

# Integration demo
python tests/demo_integration.py
```

---

## Dependencies

| Category | Libraries |
|----------|-----------|
| Core | networkx, pyyaml, grpcio, protobuf |
| Decision | qdrant-client, sentence-transformers, torch (optional) |
| API | fastapi, uvicorn, websockets |
| DB | sqlalchemy, aiosqlite |
| CLI/TUI | click, rich, textual |
| Security | impacket, scapy, pymetasploit3 |
| Dev | pytest, pytest-asyncio, pytest-cov, black, ruff |

Full install: `pip install -e ".[all]"`

---

## Warning

> This tool is developed strictly for educational and authorized Red Team exercises.  
> Using it against infrastructure without prior written consent from its owners is illegal.
