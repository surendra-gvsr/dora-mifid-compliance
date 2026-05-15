import hashlib
import os

from sqlalchemy import Boolean, Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(100), unique=True, index=True)
    password_hash = Column(String(255))
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)


def _get_database_url() -> str:
    url = os.getenv("DATABASE_URL", "sqlite:///./compliance.db")
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


_db_url = _get_database_url()
engine = create_engine(
    _db_url,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if "sqlite" in _db_url else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    salt = os.getenv("PASSWORD_SALT", "dora_compliance_salt_2025").encode()
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()


def verify_password(password: str, password_hash: str) -> bool:
    return _hash_password(password) == password_hash


def create_user(
    db, user_id: str, password: str,
    first_name: str = None, last_name: str = None,
) -> User:
    user = User(
        user_id=user_id,
        password_hash=_hash_password(password),
        first_name=first_name,
        last_name=last_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db, user_id: str, password: str):
    user = db.query(User).filter(User.user_id == user_id).first()
    if user and verify_password(password, user.password_hash):
        return user
    return None
