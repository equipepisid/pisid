from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask import current_app
from flask_limiter.util import get_remote_address
from ...extensions import db, limiter, mail
from ...forms import RegisterForm, LoginForm
from ...models import User, EmailVerification
from ...security import bcrypt_hash, bcrypt_verify, verify_totp
from flask_mail import Message
import secrets
from datetime import datetime


auth_bp = Blueprint("auth", __name__, template_folder="../../templates/auth")


def _is_email_verified(user: User) -> bool:
    rec = EmailVerification.query.filter_by(user_id=user.id, verified=True).first()
    return bool(rec)


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5/minute")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash("Email já cadastrado.", "warning")
            return render_template("auth/register.html", form=form)
        user = User(
            email=form.email.data.lower(),
            password_hash=bcrypt_hash(form.password.data),
        )
        db.session.add(user)
        db.session.commit()
        # Create verification code and send email
        code = f"{secrets.randbelow(1000000):06d}"
        ver = EmailVerification(user_id=user.id, code=code)
        db.session.add(ver)
        db.session.commit()
        try:
            msg = Message(
                subject="Confirme seu e-mail - PISID",
                recipients=[user.email],
                body=f"Seu código de verificação é: {code}. Ele expira em 15 minutos.",
            )
            mail.send(msg)
        except Exception as e:
            current_app.logger.exception("Falha ao enviar email de verificação")
            flash("Não foi possível enviar o email de verificação. Tente novamente mais tarde.", "danger")
        # Store pending user for verification flow
        session["pending_verify_user_id"] = user.id
        return redirect(url_for("auth.verify_email"))
    return render_template("auth/register.html", form=form)


@auth_bp.route("/verify-email", methods=["GET", "POST"])
@limiter.limit("10/minute")
def verify_email():
    user_id = session.get("pending_verify_user_id")
    if not user_id:
        flash("Nenhuma verificação pendente.", "info")
        return redirect(url_for("auth.login"))
    user = User.query.get(user_id)
    if not user:
        session.pop("pending_verify_user_id", None)
        return redirect(url_for("auth.register"))

    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        rec = EmailVerification.query.filter_by(user_id=user.id, code=code, verified=False).first()
        if not rec:
            flash("Código inválido.", "danger")
            return render_template("auth/verify_email.html", email=user.email)
        if rec.expires_at < datetime.utcnow():
            flash("Código expirado.", "warning")
            return render_template("auth/verify_email.html", email=user.email)
        rec.verified = True
        db.session.commit()
        session.pop("pending_verify_user_id", None)
        # Auto-login after verification
        session["user_id"] = user.id
        session.permanent = True
        flash("E-mail verificado com sucesso!", "success")
        return redirect(url_for("dashboard.home"))

    return render_template("auth/verify_email.html", email=user.email)


@auth_bp.route("/resend-code", methods=["POST"]) 
@limiter.limit("5/minute")
def resend_code():
    user_id = session.get("pending_verify_user_id")
    if not user_id:
        return jsonify({"status": "erro", "message": "Sem verificação pendente."}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({"status": "erro", "message": "Usuário não encontrado."}), 404
    # invalidate previous codes (optional)
    EmailVerification.query.filter_by(user_id=user.id, verified=False).delete()
    db.session.commit()
    code = f"{secrets.randbelow(1000000):06d}"
    ver = EmailVerification(user_id=user.id, code=code)
    db.session.add(ver)
    db.session.commit()
    try:
        msg = Message(
            subject="Confirme seu e-mail - PISID",
            recipients=[user.email],
            body=f"Seu novo código de verificação é: {code}. Ele expira em 15 minutos.",
        )
        mail.send(msg)
        return jsonify({"status": "ok", "message": "Código reenviado."})
    except Exception as e:
        return jsonify({"status": "erro", "message": str(e)}), 500


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10/minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if not user or not bcrypt_verify(form.password.data, user.password_hash):
            flash("Credenciais inválidas.", "danger")
            return render_template("auth/login.html", form=form)
        # Block if email not verified
        if not _is_email_verified(user):
            session["pending_verify_user_id"] = user.id
            flash("Confirme seu e-mail para continuar.", "warning")
            return redirect(url_for("auth.verify_email"))
        # If user has 2FA enabled, ask for token on a separate step
        if user.twofa_enabled:
            session["pending_2fa_user_id"] = user.id
            flash("Informe seu código 2FA para continuar.", "info")
            return redirect(url_for("auth.verify_2fa"))
        # Otherwise, complete login
        session["user_id"] = user.id
        session.permanent = True
        flash("Bem-vindo!", "success")
        return redirect(url_for("dashboard.home"))
    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("Sessão encerrada.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/2fa", methods=["GET", "POST"])
@limiter.limit("10/minute")
def verify_2fa():
    pending_user_id = session.get("pending_2fa_user_id")
    if not pending_user_id:
        return redirect(url_for("auth.login"))
    user = User.query.get(pending_user_id)
    if not user or not user.twofa_enabled:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        if not token or not verify_totp(user.twofa_secret, token):
            flash("Código 2FA inválido.", "danger")
            return render_template("auth/verify_2fa.html")
        session.pop("pending_2fa_user_id", None)
        session["user_id"] = user.id
        session.permanent = True
        flash("Autenticação 2FA confirmada.", "success")
        return redirect(url_for("dashboard.home"))
    return render_template("auth/verify_2fa.html")


@auth_bp.route("/test-email")
@limiter.limit("5/minute")
def test_email():
    to = request.args.get("to") or current_app.config.get("MAIL_DEFAULT_SENDER")
    try:
        msg = Message(
            subject="Teste SendGrid Flask",
            recipients=[to],
            body="Olá, este é um teste de envio de e-mail via SendGrid + Flask!",
        )
        mail.send(msg)
        return jsonify({"status": "ok", "message": "E-mail enviado com sucesso!"})
    except Exception as e:
        return jsonify({"status": "erro", "message": str(e)}), 500
