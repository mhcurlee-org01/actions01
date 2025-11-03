"""
FastAPI app: Network Security API (Groups, Hosts, Protocols, Profiles, Rules)
- Python 3.10+
- FastAPI, SQLAlchemy 2.0 style ORM, Pydantic v2
- Postgres 16 (psycopg2-binary) — set DATABASE_URL accordingly

Run (dev):
  export DATABASE_URL="postgresql+psycopg2://nsg:nsg@localhost:5432/nsgdb"
  uvicorn app:app --reload --port 8000

Suggested requirements.txt:
  fastapi
  uvicorn[standard]
  SQLAlchemy>=2.0
  pydantic>=2.6
  psycopg2-binary
  python-multipart

Note: To avoid routing ambiguity, this implements
  GET /groups/{id:int}
  GET /groups/by-appcode/{appcode}
which functionally satisfies the YAML.
"""
from __future__ import annotations

from typing import Optional, List
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, Query, Path, status
from pydantic import BaseModel, Field, constr, conint, ConfigDict
from sqlalchemy import (
    create_engine,
    String,
    Integer,
    ForeignKey,
    UniqueConstraint,
    CheckConstraint,
    Text,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
    Session,
)
import os

# ---------------------------------
# Database setup
# ---------------------------------
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    # Default to a local Postgres DSN pattern (adjust as needed)
    "postgresql+psycopg2://postgres:postgres@localhost:5432/postgres",
)

engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


# ---------------------------------
# ORM Models
# ---------------------------------
class DirectionEnum(str, Enum):
    inbound = "inbound"
    outbound = "outbound"


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    env: Mapped[str] = mapped_column(String(60), nullable=False)
    type: Mapped[str] = mapped_column(String(60), nullable=False)
    direction: Mapped[str] = mapped_column(String(10), nullable=False)
    appcode: Mapped[str] = mapped_column(String(20), nullable=False)

    profiles: Mapped[List["Profile"]] = relationship(back_populates="group", cascade="all, delete-orphan")
    rules_as_source: Mapped[List["Rule"]] = relationship(
        back_populates="source_group", foreign_keys=lambda: Rule.source_id, cascade="all, delete-orphan"
    )
    rules_as_destination: Mapped[List["Rule"]] = relationship(
        back_populates="destination_group", foreign_keys=lambda: Rule.destination_id, cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint("length(direction) <= 10", name="ck_groups_direction_len"),
    )


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    profiles: Mapped[List["Profile"]] = relationship(back_populates="host", cascade="all, delete-orphan")


class Protocol(Base):
    __tablename__ = "protocols"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)

    profiles: Mapped[List["Profile"]] = relationship(back_populates="protocol")


class Profile(Base):
    __tablename__ = "profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)

    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), nullable=False)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    protocol_id: Mapped[Optional[int]] = mapped_column(ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True)

    start_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    end_port: Mapped[int] = mapped_column(Integer, nullable=False)

    group: Mapped[Group] = relationship(back_populates="profiles")
    host: Mapped[Host] = relationship(back_populates="profiles")
    protocol: Mapped[Optional[Protocol]] = relationship(back_populates="profiles")

    __table_args__ = (
        CheckConstraint("end_port BETWEEN 1 AND 65535", name="ck_profiles_end_port_range"),
        CheckConstraint("start_port IS NULL OR (start_port BETWEEN 1 AND 65535)", name="ck_profiles_start_port_range"),
        CheckConstraint("start_port IS NULL OR start_port <= end_port", name="ck_profiles_port_order"),
    )


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    source_id: Mapped[int] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), nullable=False)
    destination_id: Mapped[int] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), nullable=False)

    source_group: Mapped[Group] = relationship(back_populates="rules_as_source", foreign_keys=[source_id])
    destination_group: Mapped[Group] = relationship(back_populates="rules_as_destination", foreign_keys=[destination_id])

    __table_args__ = (
        CheckConstraint("source_id <> destination_id", name="ck_rules_src_ne_dst"),
        UniqueConstraint("source_id", "destination_id", name="uq_rules_src_dst"),
    )


# ---------------------------------
# Pydantic Schemas (v2)
# ---------------------------------
Str50 = constr(max_length=50)
Str60 = constr(max_length=60)
Str20 = constr(max_length=20)
Str255 = constr(max_length=255)
Port = conint(ge=1, le=65535)


class GroupBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: Str50
    description: Optional[Str255] = None
    env: Str60
    type: Str60
    direction: constr(max_length=10)  # consider Enum validation if you want strict values
    appcode: Str20


class GroupCreate(GroupBase):
    pass


class GroupUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: Optional[Str50] = None
    description: Optional[Str255] = None
    env: Optional[Str60] = None
    type: Optional[Str60] = None
    direction: Optional[constr(max_length=10)] = None
    appcode: Optional[Str20] = None


class GroupOut(GroupBase):
    id: int


class HostBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: constr(max_length=255)


class HostCreate(HostBase):
    pass


class HostUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: Optional[constr(max_length=255)] = None


class HostOut(HostBase):
    id: int


class ProtocolBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: Str60


class ProtocolCreate(ProtocolBase):
    pass


class ProtocolOut(ProtocolBase):
    id: int


class ProfileBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: Str60
    group_id: int
    host_id: int
    protocol_id: Optional[int] = None
    start_port: Optional[Port] = None
    end_port: Port


class ProfileCreate(ProfileBase):
    pass


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: Optional[Str60] = None
    group_id: Optional[int] = None
    host_id: Optional[int] = None
    protocol_id: Optional[int] = None
    start_port: Optional[Port] = None
    end_port: Optional[Port] = None


class ProfileOut(ProfileBase):
    id: int


class RuleBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    description: Optional[Str255] = None
    source_id: int
    destination_id: int


class RuleCreate(RuleBase):
    pass


class RuleUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    description: Optional[Str255] = None
    source_id: Optional[int] = None
    destination_id: Optional[int] = None


class RuleOut(RuleBase):
    id: int


# ---------------------------------
# FastAPI app and dependencies
# ---------------------------------
app = FastAPI(title="Network Security API", version="1.0.0")


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Optionally auto-create tables for demos; use migrations in prod
if os.getenv("AUTO_CREATE", "0") == "1":
    Base.metadata.create_all(bind=engine)


# ---------------------------------
# Helpers
# ---------------------------------

def ensure_group_exists(db: Session, group_id: int) -> Group:
    group = db.get(Group, group_id)
    if not group:
        raise HTTPException(status_code=404, detail=f"Group {group_id} not found")
    return group


def ensure_host_exists(db: Session, host_id: int) -> Host:
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail=f"Host {host_id} not found")
    return host


def ensure_protocol_exists_if_set(db: Session, protocol_id: Optional[int]) -> Optional[Protocol]:
    if protocol_id is None:
        return None
    protocol = db.get(Protocol, protocol_id)
    if not protocol:
        raise HTTPException(status_code=404, detail=f"Protocol {protocol_id} not found")
    return protocol


# ---------------------------------
# /groups endpoints
# ---------------------------------
@app.get("/groups", response_model=List[GroupOut])
def list_groups(
    db: Session = Depends(get_db),
    appcode: Optional[str] = Query(None),
    env: Optional[str] = Query(None),
    type: Optional[str] = Query(None, alias="type"),
    direction: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    q = db.query(Group)
    if appcode:
        q = q.filter(Group.appcode == appcode)
    if env:
        q = q.filter(Group.env == env)
    if type:
        q = q.filter(Group.type == type)
    if direction:
        q = q.filter(Group.direction == direction)
    return q.offset(offset).limit(limit).all()


@app.post("/groups", response_model=GroupOut, status_code=status.HTTP_201_CREATED)
def create_group(payload: GroupCreate, db: Session = Depends(get_db)):
    g = Group(**payload.model_dump())
    db.add(g)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        # Likely uniqueness violation on name
        raise HTTPException(status_code=409, detail=str(e))
    db.refresh(g)
    return g


@app.get("/groups/{id:int}", response_model=GroupOut)
def get_group(id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    g = db.get(Group, id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    return g


@app.get("/groups/by-appcode/{appcode}", response_model=List[GroupOut])
def get_groups_by_appcode(appcode: str, db: Session = Depends(get_db)):
    return db.query(Group).filter(Group.appcode == appcode).all()


@app.put("/groups/{id:int}", response_model=GroupOut)
def update_group(id: int, payload: GroupUpdate, db: Session = Depends(get_db)):
    g = db.get(Group, id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(g, k, v)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(e))
    db.refresh(g)
    return g


@app.delete("/groups/{id:int}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(id: int, db: Session = Depends(get_db)):
    g = db.get(Group, id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    # Rely on cascade delete for child objects as defined in ORM
    db.delete(g)
    db.commit()
    return None


# ---------------------------------
# /hosts endpoints
# ---------------------------------
@app.get("/hosts", response_model=List[HostOut])
def list_hosts(db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    return db.query(Host).offset(offset).limit(limit).all()


@app.post("/hosts", response_model=HostOut, status_code=status.HTTP_201_CREATED)
def create_host(payload: HostCreate, db: Session = Depends(get_db)):
    h = Host(**payload.model_dump())
    db.add(h)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(e))
    db.refresh(h)
    return h


@app.get("/hosts/{id:int}", response_model=HostOut)
def get_host(id: int, db: Session = Depends(get_db)):
    h = db.get(Host, id)
    if not h:
        raise HTTPException(status_code=404, detail="Host not found")
    return h


@app.put("/hosts/{id:int}", response_model=HostOut)
def update_host(id: int, payload: HostUpdate, db: Session = Depends(get_db)):
    h = db.get(Host, id)
    if not h:
        raise HTTPException(status_code=404, detail="Host not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(h, k, v)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(e))
    db.refresh(h)
    return h


@app.delete("/hosts/{id:int}", status_code=status.HTTP_204_NO_CONTENT)
def delete_host(id: int, db: Session = Depends(get_db)):
    h = db.get(Host, id)
    if not h:
        raise HTTPException(status_code=404, detail="Host not found")
    db.delete(h)
    db.commit()
    return None


# ---------------------------------
# /protocols endpoints
# ---------------------------------
@app.get("/protocols", response_model=List[ProtocolOut])
def list_protocols(db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    return db.query(Protocol).offset(offset).limit(limit).all()


@app.post("/protocols", response_model=ProtocolOut, status_code=status.HTTP_201_CREATED)
def create_protocol(payload: ProtocolCreate, db: Session = Depends(get_db)):
    p = Protocol(**payload.model_dump())
    db.add(p)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(e))
    db.refresh(p)
    return p


@app.delete("/protocols/{id:int}", status_code=status.HTTP_204_NO_CONTENT)
def delete_protocol(id: int, db: Session = Depends(get_db)):
    p = db.get(Protocol, id)
    if not p:
        raise HTTPException(status_code=404, detail="Protocol not found")
    db.delete(p)
    db.commit()
    return None


# ---------------------------------
# /profiles endpoints
# ---------------------------------
@app.get("/profiles", response_model=List[ProfileOut])
def list_profiles(
    db: Session = Depends(get_db),
    group_id: Optional[int] = Query(None),
    host_id: Optional[int] = Query(None),
    protocol_id: Optional[int] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    q = db.query(Profile)
    if group_id is not None:
        q = q.filter(Profile.group_id == group_id)
    if host_id is not None:
        q = q.filter(Profile.host_id == host_id)
    if protocol_id is not None:
        q = q.filter(Profile.protocol_id == protocol_id)
    return q.offset(offset).limit(limit).all()


@app.post("/profiles", response_model=ProfileOut, status_code=status.HTTP_201_CREATED)
def create_profile(payload: ProfileCreate, db: Session = Depends(get_db)):
    ensure_group_exists(db, payload.group_id)
    ensure_host_exists(db, payload.host_id)
    ensure_protocol_exists_if_set(db, payload.protocol_id)
    pr = Profile(**payload.model_dump())
    db.add(pr)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(e))
    db.refresh(pr)
    return pr


@app.get("/profiles/{id:int}", response_model=ProfileOut)
def get_profile(id: int, db: Session = Depends(get_db)):
    pr = db.get(Profile, id)
    if not pr:
        raise HTTPException(status_code=404, detail="Profile not found")
    return pr


@app.put("/profiles/{id:int}", response_model=ProfileOut)
def update_profile(id: int, payload: ProfileUpdate, db: Session = Depends(get_db)):
    pr = db.get(Profile, id)
    if not pr:
        raise HTTPException(status_code=404, detail="Profile not found")

    data = payload.model_dump(exclude_unset=True)

    # Validate FKs if they are provided in update
    if "group_id" in data:
        ensure_group_exists(db, data["group_id"])
    if "host_id" in data:
        ensure_host_exists(db, data["host_id"])
    if "protocol_id" in data:
        ensure_protocol_exists_if_set(db, data["protocol_id"])

    for k, v in data.items():
        setattr(pr, k, v)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(e))
    db.refresh(pr)
    return pr


@app.delete("/profiles/{id:int}", status_code=status.HTTP_204_NO_CONTENT)
def delete_profile(id: int, db: Session = Depends(get_db)):
    pr = db.get(Profile, id)
    if not pr:
        raise HTTPException(status_code=404, detail="Profile not found")
    db.delete(pr)
    db.commit()
    return None


# ---------------------------------
# /rules endpoints
# ---------------------------------
@app.get("/rules", response_model=List[RuleOut])
def list_rules(
    db: Session = Depends(get_db),
    source_id: Optional[int] = Query(None),
    destination_id: Optional[int] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    q = db.query(Rule)
    if source_id is not None:
        q = q.filter(Rule.source_id == source_id)
    if destination_id is not None:
        q = q.filter(Rule.destination_id == destination_id)
    return q.offset(offset).limit(limit).all()


@app.post("/rules", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(payload: RuleCreate, db: Session = Depends(get_db)):
    if payload.source_id == payload.destination_id:
        raise HTTPException(status_code=400, detail="source_id and destination_id must differ")
    ensure_group_exists(db, payload.source_id)
    ensure_group_exists(db, payload.destination_id)

    r = Rule(**payload.model_dump())
    db.add(r)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        # Likely uniqueness violation on (source_id, destination_id)
        raise HTTPException(status_code=409, detail=str(e))
    db.refresh(r)
    return r


@app.get("/rules/{id:int}", response_model=RuleOut)
def get_rule(id: int, db: Session = Depends(get_db)):
    r = db.get(Rule, id)
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")
    return r


@app.put("/rules/{id:int}", response_model=RuleOut)
def update_rule(id: int, payload: RuleUpdate, db: Session = Depends(get_db)):
    r = db.get(Rule, id)
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")

    data = payload.model_dump(exclude_unset=True)
    if "source_id" in data:
        ensure_group_exists(db, data["source_id"])
    if "destination_id" in data:
        ensure_group_exists(db, data["destination_id"])
    if data.get("source_id", r.source_id) == data.get("destination_id", r.destination_id):
        raise HTTPException(status_code=400, detail="source_id and destination_id must differ")

    for k, v in data.items():
        setattr(r, k, v)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(e))
    db.refresh(r)
    return r


@app.delete("/rules/{id:int}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(id: int, db: Session = Depends(get_db)):
    r = db.get(Rule, id)
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(r)
    db.commit()
    return None
