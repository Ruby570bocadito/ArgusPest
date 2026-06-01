"""
database/models.py
──────────────────
SQLAlchemy models para persistencia de misiones, hosts, credenciales y eventos.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

# ─────────────────────────── BASE ────────────────────────────────

class Base(DeclarativeBase):
    pass


def utcnow():
    return datetime.now(timezone.utc)


def new_uuid():
    return str(uuid.uuid4())


# ─────────────────────────── MODELS ──────────────────────────────

class Mission(Base):
    __tablename__ = "missions"

    id          = Column(String(36), primary_key=True, default=new_uuid)
    target      = Column(String(255), nullable=False)
    goal        = Column(String(255), default="domain_admin")
    profile     = Column(String(50),  default="balanced")
    mode        = Column(String(50),  default="pentest")
    status      = Column(String(50),  default="running")    # running | paused | stopped | completed
    started_at  = Column(DateTime,    default=utcnow)
    ended_at    = Column(DateTime,    nullable=True)
    output_dir  = Column(String(512), default="./missions")
    notes       = Column(Text,        default="")

    hosts       = relationship("Host",       back_populates="mission", cascade="all, delete-orphan")
    events      = relationship("MissionEvent", back_populates="mission", cascade="all, delete-orphan")
    decisions   = relationship("DecisionRecord", back_populates="mission", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Mission id={self.id[:8]} target={self.target} profile={self.profile}>"


class Host(Base):
    __tablename__ = "hosts"

    id           = Column(String(36),  primary_key=True, default=new_uuid)
    mission_id   = Column(String(36),  ForeignKey("missions.id"), nullable=False)
    ip           = Column(String(45),  nullable=False)
    hostname     = Column(String(255), nullable=True)
    os           = Column(String(100), nullable=True)
    arch         = Column(String(50),  nullable=True)
    role         = Column(String(50),  default="unknown")
    asset_value  = Column(Integer,     default=10)
    owned        = Column(Boolean,     default=False)
    agent_id     = Column(String(64),  nullable=True)
    discovered_at = Column(DateTime,   default=utcnow)

    mission    = relationship("Mission", back_populates="hosts")
    services   = relationship("Service",    back_populates="host", cascade="all, delete-orphan")
    creds      = relationship("Credential", back_populates="host", cascade="all, delete-orphan")
    flags      = relationship("Flag",       back_populates="host", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Host ip={self.ip} owned={self.owned}>"


class Service(Base):
    __tablename__ = "services"

    id           = Column(String(36),  primary_key=True, default=new_uuid)
    host_id      = Column(String(36),  ForeignKey("hosts.id"), nullable=False)
    port         = Column(Integer,     nullable=False)
    protocol     = Column(String(10),  default="tcp")
    service_name = Column(String(100), default="unknown")
    banner       = Column(Text,        nullable=True)
    version      = Column(String(100), nullable=True)
    cpe          = Column(String(255), nullable=True)
    discovered_at = Column(DateTime,   default=utcnow)

    host          = relationship("Host", back_populates="services")
    vulnerabilities = relationship("Vulnerability", back_populates="service", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Service {self.service_name}:{self.port}>"


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id             = Column(String(36),  primary_key=True, default=new_uuid)
    service_id     = Column(String(36),  ForeignKey("services.id"), nullable=False)
    cve            = Column(String(50),  nullable=True)
    description    = Column(Text,        default="")
    cvss_score     = Column(Float,       default=0.0)
    exploit_module = Column(String(255), default="")
    verified       = Column(Boolean,     default=False)
    discovered_at  = Column(DateTime,    default=utcnow)

    service = relationship("Service", back_populates="vulnerabilities")


class Credential(Base):
    __tablename__ = "credentials"

    id             = Column(String(36),  primary_key=True, default=new_uuid)
    host_id        = Column(String(36),  ForeignKey("hosts.id"), nullable=False)
    username       = Column(String(255), nullable=False)
    cred_type      = Column(String(50),  default="password")  # password | ntlm_hash | kerberos_ticket | ssh_key
    value          = Column(Text,        nullable=False)
    scope          = Column(String(50),  default="local")     # local | domain
    cracked        = Column(Boolean,     default=False)
    discovered_at  = Column(DateTime,    default=utcnow)

    host = relationship("Host", back_populates="creds")

    def __repr__(self):
        return f"<Credential {self.username} [{self.cred_type}]>"


class Flag(Base):
    __tablename__ = "flags"

    id           = Column(String(36),  primary_key=True, default=new_uuid)
    host_id      = Column(String(36),  ForeignKey("hosts.id"), nullable=False)
    value        = Column(Text,        nullable=False)
    path         = Column(String(512), nullable=True)
    captured_at  = Column(DateTime,    default=utcnow)
    submitted    = Column(Boolean,     default=False)
    submitted_at = Column(DateTime,    nullable=True)

    host = relationship("Host", back_populates="flags")


class DecisionRecord(Base):
    __tablename__ = "decisions"

    id           = Column(String(36),  primary_key=True, default=new_uuid)
    mission_id   = Column(String(36),  ForeignKey("missions.id"), nullable=False)
    agent_id     = Column(String(64),  nullable=True)
    host_id      = Column(String(36),  nullable=True)
    action       = Column(String(255), nullable=False)
    confidence   = Column(Float,       default=0.0)
    source       = Column(String(50),  default="fusion")    # planner | cbr | rules | fusion
    mitre_id     = Column(String(20),  nullable=True)
    risk         = Column(Float,       default=0.5)
    approved     = Column(Boolean,     nullable=True)       # None = pendiente
    custom_cmd   = Column(Text,        nullable=True)
    explanation  = Column(Text,        default="")
    created_at   = Column(DateTime,    default=utcnow)
    resolved_at  = Column(DateTime,    nullable=True)
    params       = Column(JSON,        default=dict)

    mission = relationship("Mission", back_populates="decisions")


class MissionEvent(Base):
    __tablename__ = "mission_events"

    id          = Column(String(36),  primary_key=True, default=new_uuid)
    mission_id  = Column(String(36),  ForeignKey("missions.id"), nullable=False)
    event_type  = Column(String(100), nullable=False)
    agent_id    = Column(String(64),  nullable=True)
    host_id     = Column(String(36),  nullable=True)
    data        = Column(JSON,        default=dict)
    created_at  = Column(DateTime,    default=utcnow)

    mission = relationship("Mission", back_populates="events")

    def __repr__(self):
        return f"<Event {self.event_type} @ {self.created_at}>"


class AgentRecord(Base):
    __tablename__ = "agents"

    id            = Column(String(64),  primary_key=True)   # agent_id
    mission_id    = Column(String(36),  ForeignKey("missions.id"), nullable=True)
    hostname      = Column(String(255), nullable=True)
    ip            = Column(String(45),  nullable=True)
    os            = Column(String(100), nullable=True)
    arch          = Column(String(50),  nullable=True)
    profile       = Column(String(50),  default="balanced")
    is_alive      = Column(Boolean,     default=True)
    registered_at = Column(DateTime,    default=utcnow)
    last_seen_at  = Column(DateTime,    default=utcnow)
    host_id       = Column(String(36),  nullable=True)


# ─────────────────────────── DATABASE ENGINE ─────────────────────

class Database:
    """Wrapper para la base de datos SQLite de Argos."""

    def __init__(self, db_path: str = "./data/argos.db") -> None:
        import os
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self.engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"check_same_thread": False},
            echo=False,
        )
        # WAL mode para mayor rendimiento concurrente
        @event.listens_for(self.engine, "connect")
        def set_wal(dbapi_connection, _):
            dbapi_connection.execute("PRAGMA journal_mode=WAL")
            dbapi_connection.execute("PRAGMA foreign_keys=ON")

        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def get_session(self) -> Session:
        return self.Session()

    def save_event(self, session: Session, mission_id: str, event_type: str,
                   agent_id: str = None, host_id: str = None, data: dict = None) -> None:
        ev = MissionEvent(
            mission_id = mission_id,
            event_type = event_type,
            agent_id   = agent_id,
            host_id    = host_id,
            data       = data or {},
        )
        session.add(ev)
        session.commit()

    def get_mission_summary(self, session: Session, mission_id: str) -> dict:
        mission = session.get(Mission, mission_id)
        if not mission:
            return {}
        hosts   = session.query(Host).filter_by(mission_id=mission_id).count()
        owned   = session.query(Host).filter_by(mission_id=mission_id, owned=True).count()
        flags   = session.query(Flag).join(Host).filter(Host.mission_id == mission_id).count()
        creds   = session.query(Credential).join(Host).filter(Host.mission_id == mission_id).count()
        return {
            "mission_id":   mission_id,
            "target":       mission.target,
            "goal":         mission.goal,
            "profile":      mission.profile,
            "status":       mission.status,
            "hosts_total":  hosts,
            "hosts_owned":  owned,
            "flags":        flags,
            "credentials":  creds,
        }
