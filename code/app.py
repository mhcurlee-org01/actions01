from __future__ import annotations

from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, Query, Path, status, Request, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, constr, conint
from sqlalchemy import (
    create_engine,
    String,
    Integer,
    ForeignKey,
    UniqueConstraint,
    CheckConstraint,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    mapped_column,
    Mapped,
    relationship,
    sessionmaker,
    Session,
)
import os


bearer_scheme = HTTPBearer(auto_error=False)


# =========================
# DB setup
# =========================
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://postgres:postgres@localhost:5432/postgres",
)

engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


# =========================
# ORM MODELS
# =========================
class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    env: Mapped[str] = mapped_column(String(60), nullable=False)
    type: Mapped[str] = mapped_column(String(60), nullable=False)
    direction: Mapped[str] = mapped_column(String(10), nullable=False)
    appcode: Mapped[str] = mapped_column(String(20), nullable=False)

    profiles: Mapped[List["Profile"]] = relationship(
        back_populates="group", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint("length(direction) <= 10", name="ck_groups_direction_len"),
    )


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    profiles: Mapped[List["Profile"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )


class Protocol(Base):
    __tablename__ = "protocols"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)

    profiles: Mapped[List["Profile"]] = relationship(back_populates="protocol")


class Profile(Base):
    __tablename__ = "profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)

    # required
    group_id: Mapped[int] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), nullable=False
    )
    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
    )
    protocol_id: Mapped[int] = mapped_column(
        ForeignKey("protocols.id", ondelete="RESTRICT"), nullable=False
    )

    start_port: Mapped[int] = mapped_column(Integer, nullable=False)
    end_port: Mapped[int] = mapped_column(Integer, nullable=False)

    group: Mapped[Group] = relationship(back_populates="profiles")
    host: Mapped[Host] = relationship(back_populates="profiles")
    protocol: Mapped[Protocol] = relationship(back_populates="profiles")
    rules_as_source: Mapped[List["Rule"]] = relationship(
        back_populates="source_profile",
        foreign_keys=lambda: Rule.source_id,
        cascade="all, delete-orphan",
    )
    rules_as_destination: Mapped[List["Rule"]] = relationship(
        back_populates="destination_profile",
        foreign_keys=lambda: Rule.destination_id,
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        CheckConstraint("start_port BETWEEN 1 AND 65535", name="ck_profiles_start"),
        CheckConstraint("end_port BETWEEN 1 AND 65535", name="ck_profiles_end"),
        CheckConstraint("start_port <= end_port", name="ck_profiles_order"),
    )


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # NOW these point to PROFILE ids
    source_id: Mapped[int] = mapped_column(
        ForeignKey("profiles.id", ondelete="CASCADE"), nullable=False
    )
    destination_id: Mapped[int] = mapped_column(
        ForeignKey("profiles.id", ondelete="CASCADE"), nullable=False
    )

    source_profile: Mapped[Profile] = relationship(
        back_populates="rules_as_source", foreign_keys=[source_id]
    )
    destination_profile: Mapped[Profile] = relationship(
        back_populates="rules_as_destination", foreign_keys=[destination_id]
    )

    __table_args__ = (
        CheckConstraint("source_id <> destination_id", name="ck_rules_src_ne_dst"),
        UniqueConstraint("source_id", "destination_id", name="uq_rules_src_dst"),
    )


# =========================
# Pydantic Schemas
# =========================
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
    direction: constr(max_length=10)
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
    protocol_id: int              # now required
    start_port: Port              # now required
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
    source_id: int        # profile id
    destination_id: int   # profile id


class RuleCreate(RuleBase):
    pass


class RuleUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    description: Optional[Str255] = None
    source_id: Optional[int] = None
    destination_id: Optional[int] = None


class RuleOut(RuleBase):
    id: int


# =========================
# FastAPI app
# =========================


API_TOKEN = os.getenv("API_TOKEN", "changeme")  # set via env var


def verify_token(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
):
    """Require a static Bearer token for all requests (Swagger supported)."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    if token != API_TOKEN:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


app = FastAPI(
    title="Network Security API",
    version="1.1.0",
    dependencies=[Depends(verify_token)]   # every route requires token
)

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# auto-create for dev
if os.getenv("AUTO_CREATE", "0") == "1":
    Base.metadata.create_all(bind=engine)


# =========================
# Helpers
# =========================
def ensure_group(db: Session, group_id: int) -> Group:
    g = db.get(Group, group_id)
    if not g:
        raise HTTPException(404, f"group {group_id} not found")
    return g


def ensure_host(db: Session, host_id: int) -> Host:
    h = db.get(Host, host_id)
    if not h:
        raise HTTPException(404, f"host {host_id} not found")
    return h


def ensure_protocol(db: Session, protocol_id: int) -> Protocol:
    p = db.get(Protocol, protocol_id)
    if not p:
        raise HTTPException(404, f"protocol {protocol_id} not found")
    return p


def ensure_profile(db: Session, profile_id: int) -> Profile:
    p = db.get(Profile, profile_id)
    if not p:
        raise HTTPException(404, f"profile {profile_id} not found")
    return p


# =========================
# /groups
# =========================
@app.get("/groups", response_model=List[GroupOut])
def list_groups(
    db: Session = Depends(get_db),
    appcode: Optional[str] = Query(None),
    env: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    q = db.query(Group)
    if appcode:
        q = q.filter(Group.appcode == appcode)
    if env:
        q = q.filter(Group.env == env)
    return q.offset(offset).limit(limit).all()


@app.post("/groups", response_model=GroupOut, status_code=status.HTTP_201_CREATED)
def create_group(payload: GroupCreate, db: Session = Depends(get_db)):
    g = Group(**payload.model_dump())
    db.add(g)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(409, str(e))
    db.refresh(g)
    return g


@app.get("/groups/{id:int}", response_model=GroupOut)
def get_group(id: int, db: Session = Depends(get_db)):
    g = db.get(Group, id)
    if not g:
        raise HTTPException(404, "group not found")
    return g


@app.get("/groups/by-name/{name}", response_model=GroupOut)
def get_group_by_name(name: str, db: Session = Depends(get_db)):
    g = db.query(Group).filter(Group.name == name).first()
    if not g:
        raise HTTPException(404, "group not found")
    return g


@app.get("/groups/groups-by-appcode/{appcode}", response_model=List[GroupOut])
def get_groups_by_appcode(appcode: str, db: Session = Depends(get_db)):
    return db.query(Group).filter(Group.appcode == appcode).all()


@app.put("/groups/{id:int}", response_model=GroupOut)
def update_group(id: int, payload: GroupUpdate, db: Session = Depends(get_db)):
    g = db.get(Group, id)
    if not g:
        raise HTTPException(404, "group not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(g, k, v)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(409, str(e))
    db.refresh(g)
    return g


@app.delete("/groups/{id:int}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(id: int, db: Session = Depends(get_db)):
    g = db.get(Group, id)
    if not g:
        raise HTTPException(404, "group not found")
    db.delete(g)
    db.commit()
    return None


# =========================
# /hosts
# =========================
@app.get("/hosts", response_model=List[HostOut])
def list_hosts(db: Session = Depends(get_db)):
    return db.query(Host).all()


@app.post("/hosts", response_model=HostOut, status_code=status.HTTP_201_CREATED)
def create_host(payload: HostCreate, db: Session = Depends(get_db)):
    h = Host(**payload.model_dump())
    db.add(h)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(409, str(e))
    db.refresh(h)
    return h


@app.get("/hosts/{id:int}", response_model=HostOut)
def get_host(id: int, db: Session = Depends(get_db)):
    h = db.get(Host, id)
    if not h:
        raise HTTPException(404, "host not found")
    return h


@app.put("/hosts/{id:int}", response_model=HostOut)
def update_host(id: int, payload: HostUpdate, db: Session = Depends(get_db)):
    h = db.get(Host, id)
    if not h:
        raise HTTPException(404, "host not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(h, k, v)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(409, str(e))
    db.refresh(h)
    return h


@app.delete("/hosts/{id:int}", status_code=status.HTTP_204_NO_CONTENT)
def delete_host(id: int, db: Session = Depends(get_db)):
    h = db.get(Host, id)
    if not h:
        raise HTTPException(404, "host not found")
    db.delete(h)
    db.commit()
    return None


# =========================
# /protocols
# =========================
@app.get("/protocols", response_model=List[ProtocolOut])
def list_protocols(db: Session = Depends(get_db)):
    return db.query(Protocol).all()


@app.post("/protocols", response_model=ProtocolOut, status_code=status.HTTP_201_CREATED)
def create_protocol(payload: ProtocolCreate, db: Session = Depends(get_db)):
    p = Protocol(**payload.model_dump())
    db.add(p)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(409, str(e))
    db.refresh(p)
    return p


@app.delete("/protocols/{id:int}", status_code=status.HTTP_204_NO_CONTENT)
def delete_protocol(id: int, db: Session = Depends(get_db)):
    p = db.get(Protocol, id)
    if not p:
        raise HTTPException(404, "protocol not found")
    db.delete(p)
    db.commit()
    return None


# =========================
# /profiles
# =========================
@app.get("/profiles", response_model=List[ProfileOut])
def list_profiles(
    db: Session = Depends(get_db),
    group_id: Optional[int] = Query(None),
    host_id: Optional[int] = Query(None),
    protocol_id: Optional[int] = Query(None),
):
    q = db.query(Profile)
    if group_id is not None:
        q = q.filter(Profile.group_id == group_id)
    if host_id is not None:
        q = q.filter(Profile.host_id == host_id)
    if protocol_id is not None:
        q = q.filter(Profile.protocol_id == protocol_id)
    return q.all()


@app.post("/profiles", response_model=ProfileOut, status_code=status.HTTP_201_CREATED)
def create_profile(payload: ProfileCreate, db: Session = Depends(get_db)):
    # all required now
    ensure_group(db, payload.group_id)
    ensure_host(db, payload.host_id)
    ensure_protocol(db, payload.protocol_id)

    pr = Profile(**payload.model_dump())
    db.add(pr)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(409, str(e))
    db.refresh(pr)
    return pr


@app.get("/profiles/{id:int}", response_model=ProfileOut)
def get_profile(id: int, db: Session = Depends(get_db)):
    pr = db.get(Profile, id)
    if not pr:
        raise HTTPException(404, "profile not found")
    return pr


@app.put("/profiles/{id:int}", response_model=ProfileOut)
def update_profile(id: int, payload: ProfileUpdate, db: Session = Depends(get_db)):
    pr = db.get(Profile, id)
    if not pr:
        raise HTTPException(404, "profile not found")

    data = payload.model_dump(exclude_unset=True)
    if "group_id" in data:
        ensure_group(db, data["group_id"])
    if "host_id" in data:
        ensure_host(db, data["host_id"])
    if "protocol_id" in data:
        ensure_protocol(db, data["protocol_id"])

    for k, v in data.items():
        setattr(pr, k, v)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(409, str(e))
    db.refresh(pr)
    return pr


@app.delete("/profiles/{id:int}", status_code=status.HTTP_204_NO_CONTENT)
def delete_profile(id: int, db: Session = Depends(get_db)):
    pr = db.get(Profile, id)
    if not pr:
        raise HTTPException(404, "profile not found")
    db.delete(pr)
    db.commit()
    return None


# =========================
# /rules  (profile → profile)
# =========================
@app.get("/rules", response_model=List[RuleOut])
def list_rules(
    db: Session = Depends(get_db),
    source_id: Optional[int] = Query(None),
    destination_id: Optional[int] = Query(None),
):
    q = db.query(Rule)
    if source_id is not None:
        q = q.filter(Rule.source_id == source_id)
    if destination_id is not None:
        q = q.filter(Rule.destination_id == destination_id)
    return q.all()


@app.post("/rules", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(payload: RuleCreate, db: Session = Depends(get_db)):
    if payload.source_id == payload.destination_id:
        raise HTTPException(400, "source and destination must differ")

    ensure_profile(db, payload.source_id)
    ensure_profile(db, payload.destination_id)

    r = Rule(**payload.model_dump())
    db.add(r)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(409, str(e))
    db.refresh(r)
    return r


@app.get("/rules/{id:int}", response_model=RuleOut)
def get_rule(id: int, db: Session = Depends(get_db)):
    r = db.get(Rule, id)
    if not r:
        raise HTTPException(404, "rule not found")
    return r


@app.put("/rules/{id:int}", response_model=RuleOut)
def update_rule(id: int, payload: RuleUpdate, db: Session = Depends(get_db)):
    r = db.get(Rule, id)
    if not r:
        raise HTTPException(404, "rule not found")

    data = payload.model_dump(exclude_unset=True)

    # check updated FKs
    new_source = data.get("source_id", r.source_id)
    new_dest = data.get("destination_id", r.destination_id)

    ensure_profile(db, new_source)
    ensure_profile(db, new_dest)

    if new_source == new_dest:
        raise HTTPException(400, "source and destination must differ")

    for k, v in data.items():
        setattr(r, k, v)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(409, str(e))
    db.refresh(r)
    return r


@app.delete("/rules/{id:int}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(id: int, db: Session = Depends(get_db)):
    r = db.get(Rule, id)
    if not r:
        raise HTTPException(404, "rule not found")
    db.delete(r)
    db.commit()
    return None

