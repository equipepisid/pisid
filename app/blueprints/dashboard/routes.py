from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from ...extensions import db
from ...forms import SensitiveDataForm
from ...models import User, SensitiveData, OAuthConsent
from ...security import aes_encrypt, aes_decrypt, integrity_hash_str, get_aes_key, generate_totp_secret, verify_totp
import qrcode
import io, base64


dashboard_bp = Blueprint("dashboard", __name__, template_folder="../../templates/dashboard")


def _require_login():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


@dashboard_bp.route("/", methods=["GET"]) 
def home():
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))
    data = SensitiveData.query.filter_by(user_id=user.id).first()
    return render_template("dashboard/home.html", user=user, data=data)


@dashboard_bp.route("/data", methods=["GET", "POST"]) 
def manage_data():
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))

    form = SensitiveDataForm()
    data = SensitiveData.query.filter_by(user_id=user.id).first()

    if form.validate_on_submit():
        key = get_aes_key(current_app.config.get("AES_KEY"), current_app.config.get("SECRET_KEY").encode("utf-8"))
        if not data:
            data = SensitiveData(user_id=user.id)
        # Encrypt each field if provided
        full_name = form.full_name.data or ""
        cpf = form.cpf.data or ""
        birthdate = form.birthdate.data.isoformat() if form.birthdate.data else ""
        phone = form.phone.data or ""
        address = form.address.data or ""

        if full_name:
            data.full_name_ct, data.full_name_nonce = aes_encrypt(full_name, key)
        if cpf:
            data.cpf_ct, data.cpf_nonce = aes_encrypt(cpf, key)
        if birthdate:
            data.birthdate_ct, data.birthdate_nonce = aes_encrypt(birthdate, key)
        if phone:
            data.phone_ct, data.phone_nonce = aes_encrypt(phone, key)
        if address:
            data.address_ct, data.address_nonce = aes_encrypt(address, key)

        data.integrity_hash = integrity_hash_str(full_name, cpf, birthdate, phone, address)
        db.session.add(data)
        db.session.commit()
        flash("Dados atualizados com sucesso.", "success")
        return redirect(url_for("dashboard.home"))

    return render_template("dashboard/data.html", form=form, data=data)


@dashboard_bp.route("/data/view") 
def view_data():
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))
    data = SensitiveData.query.filter_by(user_id=user.id).first()
    if not data:
        flash("Nenhum dado cadastrado.", "info")
        return redirect(url_for("dashboard.manage_data"))
    key = get_aes_key(current_app.config.get("AES_KEY"), current_app.config.get("SECRET_KEY").encode("utf-8"))
    def _dec(ct, nonce):
        return aes_decrypt(ct, nonce, key) if ct and nonce else ""
    decoded = {
        "full_name": _dec(data.full_name_ct, data.full_name_nonce),
        "cpf": _dec(data.cpf_ct, data.cpf_nonce),
        "birthdate": _dec(data.birthdate_ct, data.birthdate_nonce),
        "phone": _dec(data.phone_ct, data.phone_nonce),
        "address": _dec(data.address_ct, data.address_nonce),
        "integrity_hash": data.integrity_hash,
    }
    return render_template("dashboard/view_data.html", data=decoded)


@dashboard_bp.route("/apps", methods=["GET"]) 
def oauth_consents():
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))
    consents = OAuthConsent.query.filter_by(user_id=user.id).all()
    return render_template("dashboard/apps.html", consents=consents)


@dashboard_bp.route("/apps/revoke/<int:consent_id>", methods=["POST"]) 
def revoke_consent(consent_id: int):
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))
    consent = OAuthConsent.query.filter_by(id=consent_id, user_id=user.id).first()
    if not consent:
        flash("Acesso não encontrado.", "warning")
        return redirect(url_for("dashboard.oauth_consents"))
    db.session.delete(consent)
    db.session.commit()
    flash("Acesso revogado.", "success")
    return redirect(url_for("dashboard.oauth_consents"))


@dashboard_bp.route("/2fa", methods=["GET", "POST"]) 
def twofa_settings():
    user = _require_login()
    if not user:
        return redirect(url_for("auth.login"))

    # If enabling: generate or reuse a pending secret stored in session
    pending_secret = session.get("pending_2fa_secret")
    qr_data_uri = None

    if not user.twofa_enabled:
        if not pending_secret:
            pending_secret = generate_totp_secret()
            session["pending_2fa_secret"] = pending_secret
        # Build provisioning URI and QR code
        import pyotp
        issuer = "PISID"
        uri = pyotp.totp.TOTP(pending_secret).provisioning_uri(name=user.email, issuer_name=issuer)
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        b64 = base64.b64encode(buf.getvalue()).decode('ascii')
        qr_data_uri = f"data:image/png;base64,{b64}"

    if request.method == "POST":
        action = request.form.get("action")
        token = (request.form.get("token") or "").strip()
        # Enable 2FA
        if action == "enable" and not user.twofa_enabled:
            secret = pending_secret
            if not secret:
                flash("Erro ao gerar segredo 2FA. Tente novamente.", "danger")
                return redirect(url_for("dashboard.twofa_settings"))
            if not token:
                flash("Informe o código 2FA do seu app autenticador.", "warning")
                return redirect(url_for("dashboard.twofa_settings"))
            if not verify_totp(secret, token):
                flash("Código 2FA inválido.", "danger")
                return redirect(url_for("dashboard.twofa_settings"))
            user.twofa_enabled = True
            user.twofa_secret = secret
            db.session.commit()
            session.pop("pending_2fa_secret", None)
            flash("2FA ativado com sucesso.", "success")
            return redirect(url_for("dashboard.twofa_settings"))
        # Disable 2FA (require current token)
        if action == "disable" and user.twofa_enabled:
            if not token or not verify_totp(user.twofa_secret, token):
                flash("Código 2FA inválido.", "danger")
                return redirect(url_for("dashboard.twofa_settings"))
            user.twofa_enabled = False
            user.twofa_secret = None
            db.session.commit()
            flash("2FA desativado.", "success")
            return redirect(url_for("dashboard.twofa_settings"))

    return render_template("dashboard/2fa.html", user=user, qr_data_uri=qr_data_uri, has_2fa=user.twofa_enabled)
