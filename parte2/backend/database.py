from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = "sqlite:///./location_tracker.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True, nullable=False)
    hashed_token = Column(String, nullable=False)
    otp_code = Column(String, nullable=True)
    otp_expires_at = Column(DateTime, nullable=True)
    is_verified = Column(Boolean, default=False)
    consent_given_at = Column(DateTime, nullable=True)
    tracking_enabled = Column(Boolean, default=True)
    geofence_lat = Column(Float, nullable=True)
    geofence_lon = Column(Float, nullable=True)
    geofence_radius = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class LocationRecord(Base):
    __tablename__ = "location_records"

    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, index=True, nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    accuracy_meters = Column(Float, nullable=True)
    source = Column(String, default="app")  # 'app', 'telegram_bot'
    recorded_at = Column(DateTime, default=datetime.utcnow)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
