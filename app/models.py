import uuid
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.dialects.sqlite import BLOB
from flask_sqlalchemy import SQLAlchemy
from .extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.LargeBinary(60), nullable=False)
    twofa_enabled = db.Column(db.Boolean, default=False)
    twofa_secret = db.Column(db.String(32), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sensitive_data = db.relationship("SensitiveData", backref="user", lazy=True, cascade="all, delete-orphan")
    consents = db.relationship("OAuthConsent", backref="user", lazy=True, cascade="all, delete-orphan")
    email_verifications = db.relationship("EmailVerification", backref="user", lazy=True, cascade="all, delete-orphan")


class SensitiveData(db.Model):
    __tablename__ = "sensitive_data"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # store AES-GCM ciphertext and nonce per field as BLOBs
    full_name_ct = db.Column(BLOB, nullable=True)
    full_name_nonce = db.Column(BLOB, nullable=True)

    cpf_ct = db.Column(BLOB, nullable=True)
    cpf_nonce = db.Column(BLOB, nullable=True)

    birthdate_ct = db.Column(BLOB, nullable=True)
    birthdate_nonce = db.Column(BLOB, nullable=True)

    phone_ct = db.Column(BLOB, nullable=True)
    phone_nonce = db.Column(BLOB, nullable=True)

    address_ct = db.Column(BLOB, nullable=True)
    address_nonce = db.Column(BLOB, nullable=True)

    integrity_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class OAuthClient(db.Model):
    __tablename__ = "oauth_clients"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    client_secret_hash = db.Column(db.LargeBinary(60), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    redirect_uris = db.Column(db.Text, nullable=False)  # comma-separated
    allowed_scopes = db.Column(db.Text, default="openid profile email")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class OAuthConsent(db.Model):
    __tablename__ = "oauth_consents"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    client_id = db.Column(db.String(64), nullable=False, index=True)
    scope = db.Column(db.Text, default="openid profile email")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class EmailVerification(db.Model):
    __tablename__ = "email_verifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    code = db.Column(db.String(6), nullable=False, index=True)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow() + timedelta(minutes=15))


def init_db():
    db.create_all()
