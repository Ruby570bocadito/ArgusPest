# ─────────────────────────────────────────────────────────────────
# Argos Makefile
# ─────────────────────────────────────────────────────────────────

.PHONY: help install proto test run build-stager clean lint

PYTHON     = python
PIP        = pip
PROTO_DIR  = shared/proto
PROTO_FILE = $(PROTO_DIR)/argos.proto
STAGER_DIR = agents/stager

help:  ## Mostrar ayuda
	@echo ""
	@echo "  ARGOS — Comandos disponibles"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ─── SETUP ────────────────────────────────────────────────────────

install:  ## Instalar dependencias Python
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "✅ Dependencias instaladas"

install-dev:  ## Instalar dependencias de desarrollo
	$(MAKE) install
	$(PIP) install pytest pytest-asyncio pytest-cov black ruff
	@echo "✅ Dependencias de desarrollo instaladas"

setup-dirs:  ## Crear directorios necesarios
	mkdir -p data/qdrant missions logs certs reports arsenal/output
	@echo "✅ Directorios creados"

# ─── OPSEC / INFRA ────────────────────────────────────────────────

certs:  ## Generar certificados mTLS (OpSec)
	mkdir -p certs
	# Generar CA
	openssl req -x509 -newkey rsa:4096 -days 365 -nodes -keyout certs/ca-key.pem -out certs/ca-cert.pem -subj "/C=US/O=Argos/CN=ArgosCA"
	# Generar cert del Servidor (Director)
	openssl req -newkey rsa:4096 -nodes -keyout certs/server-key.pem -out certs/server-req.pem -subj "/C=US/O=Argos/CN=c2.argos.internal"
	openssl x509 -req -in certs/server-req.pem -days 365 -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/server-cert.pem
	# Generar cert del Operador (CLI)
	openssl req -newkey rsa:4096 -nodes -keyout certs/client-key.pem -out certs/client-req.pem -subj "/C=US/O=Argos/CN=operator"
	openssl x509 -req -in certs/client-req.pem -days 365 -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/client-cert.pem
	@echo "✅ Certificados mTLS generados en ./certs"

# ─── PROTOBUF ─────────────────────────────────────────────────────

proto:  ## Generar stubs Python y Go de Protobuf
	# Python
	$(PYTHON) -m grpc_tools.protoc -I $(PROTO_DIR) --python_out=$(PROTO_DIR) --grpc_python_out=$(PROTO_DIR) $(PROTO_FILE)
	sed -i 's/import argos_pb2 as/from shared.proto import argos_pb2 as/' $(PROTO_DIR)/argos_pb2_grpc.py
	# Go (cell)
	mkdir -p agents/cell/proto
	protoc -I $(PROTO_DIR) --go_opt=module=github.com/argos/shared/proto --go_out=agents/cell/proto --go-grpc_opt=module=github.com/argos/shared/proto --go-grpc_out=agents/cell/proto $(PROTO_FILE)
	# Go (stager)
	mkdir -p agents/stager/proto
	protoc -I $(PROTO_DIR) --go_opt=module=github.com/argos/shared/proto --go_out=agents/stager/proto --go-grpc_opt=module=github.com/argos/shared/proto --go-grpc_out=agents/stager/proto $(PROTO_FILE)
	@echo "Stubs generados [Python + Go]"

proto-go:  ## Solo stubs Go
	mkdir -p agents/cell/proto agents/stager/proto
	protoc -I $(PROTO_DIR) --go_opt=module=github.com/argos/shared/proto --go_out=agents/cell/proto --go-grpc_opt=module=github.com/argos/shared/proto --go-grpc_out=agents/cell/proto $(PROTO_FILE)
	protoc -I $(PROTO_DIR) --go_opt=module=github.com/argos/shared/proto --go_out=agents/stager/proto --go-grpc_opt=module=github.com/argos/shared/proto --go-grpc_out=agents/stager/proto $(PROTO_FILE)
	@echo "Stubs Go generados"

# ─── RUN ──────────────────────────────────────────────────────────

run:  ## Arrancar el orquestador (modo servidor)
	$(PYTHON) main.py

cli:  ## Abrir la CLI de Argos
	$(PYTHON) -m ui.cli --help

# ─── AGENTS ───────────────────────────────────────────────────────

build-stager:  ## Compilar el stager Go (sin ofuscación, para desarrollo)
	cd $(STAGER_DIR) && go build -o stager.exe .
	@echo "✅ Stager compilado: $(STAGER_DIR)/stager.exe"

build-stager-obf:  ## Compilar el stager Go con Garble (ofuscado)
	cd $(STAGER_DIR) && garble -tiny -literals -seed=random build -o stager_obf.exe .
	@echo "✅ Stager ofuscado compilado"

build-cell:  ## Compilar el agente completo (Cell) (sin ofuscación)
	cd agents/cell && go build -o cell.exe .
	@echo "✅ Cell compilado: agents/cell/cell.exe"

build-stager-linux:  ## Compilar stager para Linux
	cd $(STAGER_DIR) && GOOS=linux GOARCH=amd64 go build -o stager_linux .
	@echo "✅ Stager Linux compilado"

build-cell-mac:  ## Compilar Cell para MacOS (Intel)
	cd agents/cell && GOOS=darwin GOARCH=amd64 go build -o cell_mac_intel .
	@echo "✅ Cell compilado para MacOS (Intel)"

build-cell-mac-m1:  ## Compilar Cell para MacOS (Apple Silicon / ARM64)
	cd agents/cell && GOOS=darwin GOARCH=arm64 go build -o cell_mac_m1 .
	@echo "✅ Cell compilado para MacOS (Apple Silicon)"

build-cell-linux-arm:  ## Compilar Cell para Linux ARM (ej. Raspberry Pi)
	cd agents/cell && GOOS=linux GOARCH=arm64 go build -o cell_linux_arm64 .
	@echo "✅ Cell compilado para Linux (ARM64)"

# ─── TEST ─────────────────────────────────────────────────────────

test:  ## Ejecutar todos los tests
	pytest tests/ -v --tb=short

test-cov:  ## Ejecutar tests con cobertura
	pytest tests/ -v --cov=core --cov=database --cov-report=html --cov-report=term-missing
	@echo "✅ Reporte de cobertura en htmlcov/"

test-fast:  ## Ejecutar solo tests rápidos (sin Qdrant)
	pytest tests/ -v --tb=short -k "not cbr"

# ─── LINT ─────────────────────────────────────────────────────────

lint:  ## Lint con ruff
	ruff check core/ database/ ui/ arsenal/ api/ tests/

format:  ## Formatear código con black
	black core/ database/ ui/ arsenal/ api/ tests/ main.py

# ─── DOCKER LAB ───────────────────────────────────────────────────

lab-up:  ## Arrancar el laboratorio vulnerable con Docker
	docker-compose -f tests/docker-compose-lab.yml up -d
	@echo "✅ Laboratorio vulnerable arrancado"

lab-down:  ## Detener el laboratorio
	docker-compose -f tests/docker-compose-lab.yml down

# ─── CLEAN ────────────────────────────────────────────────────────

clean:  ## Limpiar archivos generados
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage
	@echo "✅ Limpieza completada"

clean-all:  ## Limpiar todo (incluyendo datos de misiones)
	$(MAKE) clean
	rm -rf data/ missions/ logs/ arsenal/output/
	@echo "✅ Limpieza completa realizada"
