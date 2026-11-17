"""
Sistema de rastreo de ubicación por consentimiento — Backend FastAPI
Taller 2 - Mecanismos de Seguridad — Universidad Distrital FJDC

Uso académico. El rastreo requiere consentimiento explícito del usuario rastreado.
"""
import os
import random
import string
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from database import User, LocationRecord, get_db, init_db

# ── Configuración ────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "cambiar-en-produccion-clave-segura-aleatoria")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
OTP_EXPIRE_MINUTES = 10

pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

app = FastAPI(
    title="Location Tracker API",
    description="Sistema de rastreo de ubicación basado en consentimiento explícito",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Conexiones WebSocket activas por teléfono
active_connections: dict[str, list[WebSocket]] = {}


# ── Schemas Pydantic ─────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    phone: str
    consent_accepted: bool

    @field_validator("phone")
    @classmethod
    def phone_must_be_digits(cls, v: str) -> str:
        digits = v.replace("+", "").replace("-", "").replace(" ", "")
        if not digits.isdigit() or len(digits) < 7:
            raise ValueError("Número de teléfono inválido")
        return v

    @field_validator("consent_accepted")
    @classmethod
    def consent_required(cls, v: bool) -> bool:
        if not v:
            raise ValueError("El consentimiento es obligatorio para usar el servicio")
        return v


class VerifyRequest(BaseModel):
    phone: str
    otp: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    phone: str


class LocationUpdate(BaseModel):
    latitude: float
    longitude: float
    accuracy_meters: float | None = None
    source: str = "app"

    @field_validator("latitude")
    @classmethod
    def lat_range(cls, v: float) -> float:
        if not (-90 <= v <= 90):
            raise ValueError("Latitud fuera de rango")
        return v

    @field_validator("longitude")
    @classmethod
    def lon_range(cls, v: float) -> float:
        if not (-180 <= v <= 180):
            raise ValueError("Longitud fuera de rango")
        return v


class LocationResponse(BaseModel):
    phone: str
    latitude: float
    longitude: float
    accuracy_meters: float | None
    source: str
    recorded_at: datetime


class HistoryResponse(BaseModel):
    phone: str
    total: int
    records: list[LocationResponse]


# ── Utilidades JWT / OTP ──────────────────────────────────────────────────────
def _generate_otp(length: int = 6) -> str:
    return "".join(random.choices(string.digits, k=length))


def _create_access_token(phone: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": phone, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def _get_current_phone(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> str:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        phone: str | None = payload.get("sub")
        if phone is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        return phone
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")


def _get_verified_user(phone: str, db: Session) -> User:
    user = db.query(User).filter(User.phone == phone, User.is_verified == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no verificado")
    if not user.tracking_enabled:
        raise HTTPException(status_code=403, detail="Rastreo desactivado por el usuario")
    return user


# ── Inicialización ────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup():
    init_db()


# ── Endpoints de autenticación ────────────────────────────────────────────────
@app.post("/auth/register", summary="Registrar número telefónico")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    """
    Registra un número y envía OTP. El usuario debe haber aceptado los términos.
    En producción, enviar OTP por SMS (Twilio, etc.). Aquí se devuelve en la respuesta
    solo para propósitos de demostración académica.
    """
    user = db.query(User).filter(User.phone == req.phone).first()
    otp = _generate_otp()
    otp_expires = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)

    if user is None:
        user = User(
            phone=req.phone,
            hashed_token=pwd_context.hash(otp),
            otp_code=otp,
            otp_expires_at=otp_expires,
            consent_given_at=datetime.utcnow(),
        )
        db.add(user)
    else:
        user.otp_code = otp
        user.otp_expires_at = otp_expires
        user.hashed_token = pwd_context.hash(otp)
        if req.consent_accepted:
            user.consent_given_at = datetime.utcnow()

    db.commit()

    # En producción: enviar OTP por SMS y NO devolverlo aquí
    return {
        "message": "OTP generado. En producción se enviaría por SMS.",
        "otp_demo": otp,  # Solo para demo académica
        "expires_in_minutes": OTP_EXPIRE_MINUTES,
    }


@app.post("/auth/verify", response_model=TokenResponse, summary="Verificar OTP")
def verify_otp(req: VerifyRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.phone == req.phone).first()
    if not user or user.otp_code != req.otp:
        raise HTTPException(status_code=400, detail="OTP inválido")
    if user.otp_expires_at and datetime.utcnow() > user.otp_expires_at:
        raise HTTPException(status_code=400, detail="OTP expirado")

    user.is_verified = True
    user.otp_code = None
    db.commit()

    token = _create_access_token(user.phone)
    return TokenResponse(access_token=token, phone=user.phone)


@app.delete("/auth/revoke", summary="Revocar consentimiento y eliminar datos")
def revoke_consent(
    phone: str = Depends(_get_current_phone),
    db: Session = Depends(get_db),
):
    db.query(LocationRecord).filter(LocationRecord.phone == phone).delete()
    db.query(User).filter(User.phone == phone).delete()
    db.commit()
    return {"message": "Consentimiento revocado y datos eliminados correctamente"}


@app.patch("/auth/toggle-tracking", summary="Activar/desactivar rastreo")
def toggle_tracking(
    enabled: bool,
    phone: str = Depends(_get_current_phone),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.phone == phone).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    user.tracking_enabled = enabled
    db.commit()
    return {"tracking_enabled": enabled}


# ── Endpoints de ubicación ────────────────────────────────────────────────────
@app.post("/location/update", summary="Enviar ubicación actual")
async def update_location(
    loc: LocationUpdate,
    phone: str = Depends(_get_current_phone),
    db: Session = Depends(get_db),
):
    _get_verified_user(phone, db)

    record = LocationRecord(
        phone=phone,
        latitude=loc.latitude,
        longitude=loc.longitude,
        accuracy_meters=loc.accuracy_meters,
        source=loc.source,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # Notificar conexiones WebSocket activas para este teléfono
    if phone in active_connections:
        payload = {
            "latitude": loc.latitude,
            "longitude": loc.longitude,
            "recorded_at": record.recorded_at.isoformat(),
        }
        dead = []
        for ws in active_connections[phone]:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            active_connections[phone].remove(ws)

    return {"message": "Ubicación registrada", "id": record.id}


@app.get(
    "/location/current/{phone}",
    response_model=LocationResponse,
    summary="Última ubicación conocida",
)
def get_current_location(
    phone: str,
    viewer_phone: str = Depends(_get_current_phone),
    db: Session = Depends(get_db),
):
    record = (
        db.query(LocationRecord)
        .filter(LocationRecord.phone == phone)
        .order_by(LocationRecord.recorded_at.desc())
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Sin ubicación registrada para este número")
    return LocationResponse(
        phone=record.phone,
        latitude=record.latitude,
        longitude=record.longitude,
        accuracy_meters=record.accuracy_meters,
        source=record.source,
        recorded_at=record.recorded_at,
    )


@app.get(
    "/location/history/{phone}",
    response_model=HistoryResponse,
    summary="Historial de ubicaciones",
)
def get_location_history(
    phone: str,
    limit: int = 50,
    offset: int = 0,
    viewer_phone: str = Depends(_get_current_phone),
    db: Session = Depends(get_db),
):
    total = db.query(LocationRecord).filter(LocationRecord.phone == phone).count()
    records = (
        db.query(LocationRecord)
        .filter(LocationRecord.phone == phone)
        .order_by(LocationRecord.recorded_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return HistoryResponse(
        phone=phone,
        total=total,
        records=[
            LocationResponse(
                phone=r.phone,
                latitude=r.latitude,
                longitude=r.longitude,
                accuracy_meters=r.accuracy_meters,
                source=r.source,
                recorded_at=r.recorded_at,
            )
            for r in records
        ],
    )


@app.post("/geofence/set", summary="Definir zona de geofencing")
def set_geofence(
    lat: float,
    lon: float,
    radius_meters: float,
    phone: str = Depends(_get_current_phone),
    db: Session = Depends(get_db),
):
    """Define una zona circular. El cliente debe consultar /geofence/check periodicamente."""
    db.query(User).filter(User.phone == phone).update({
        "geofence_lat": lat,
        "geofence_lon": lon,
        "geofence_radius": radius_meters,
    })
    db.commit()
    return {"message": f"Geofence definido: {lat},{lon} r={radius_meters}m"}


@app.get("/location/stats/{phone}", summary="Estadísticas de movimiento")
def get_movement_stats(
    phone: str,
    viewer_phone: str = Depends(_get_current_phone),
    db: Session = Depends(get_db),
):
    from math import radians, sin, cos, sqrt, atan2
    records = (
        db.query(LocationRecord)
        .filter(LocationRecord.phone == phone)
        .order_by(LocationRecord.recorded_at.asc())
        .all()
    )
    if len(records) < 2:
        return {"total_records": len(records), "distance_km": 0, "duration_min": 0}

    def haversine(lat1, lon1, lat2, lon2):
        R = 6371
        dlat = radians(lat2 - lat1)
        dlon = radians(lon2 - lon1)
        a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
        return R * 2 * atan2(sqrt(a), sqrt(1-a))

    total_km = sum(
        haversine(records[i].latitude, records[i].longitude,
                  records[i+1].latitude, records[i+1].longitude)
        for i in range(len(records) - 1)
    )
    duration = (records[-1].recorded_at - records[0].recorded_at).total_seconds() / 60
    return {
        "total_records": len(records),
        "distance_km": round(total_km, 3),
        "duration_min": round(duration, 1),
        "avg_speed_kmh": round(total_km / (duration / 60), 2) if duration > 0 else 0,
        "first_seen": records[0].recorded_at.isoformat(),
        "last_seen": records[-1].recorded_at.isoformat(),
    }


# ── WebSocket para actualizaciones en tiempo real ─────────────────────────────
@app.websocket("/ws/live/{phone}")
async def websocket_live(websocket: WebSocket, phone: str):
    """
    Canal en tiempo real: el cliente se conecta aquí y recibe actualizaciones
    cada vez que el dispositivo rastreado envía una nueva ubicación.
    """
    await websocket.accept()
    active_connections.setdefault(phone, []).append(websocket)
    try:
        while True:
            await websocket.receive_text()  # Mantener conexión viva (ping del cliente)
    except WebSocketDisconnect:
        if phone in active_connections:
            active_connections[phone].discard(websocket) if hasattr(
                active_connections[phone], "discard"
            ) else None
            try:
                active_connections[phone].remove(websocket)
            except ValueError:
                pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
