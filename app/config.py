import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(os.getcwd(), 'app.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Rate limiting
    RATELIMIT_DEFAULT = "60 per minute"
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

    # OAuth / JWT
    OAUTH_JWT_SECRET = os.environ.get("OAUTH_JWT_SECRET", os.urandom(32))
    OAUTH_JWT_ALG = "HS256"
    OAUTH_ACCESS_TOKEN_EXPIRES = int(os.environ.get("OAUTH_ACCESS_TOKEN_EXPIRES", 3600))

    # AES key (32 bytes)
    AES_KEY = os.environ.get("AES_KEY")

    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=6)

    # Email (SendGrid SMTP via Flask-Mail)
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.sendgrid.net")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "True").lower() == "true"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "apikey")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "SUA_API_KEY")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "equipepisid@gmail.com")
