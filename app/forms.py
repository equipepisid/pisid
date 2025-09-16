from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, DateField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Optional


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    confirm_email = StringField("Confirmar Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Senha", validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField("Confirmar Senha", validators=[DataRequired(), Length(min=8, max=128)])
    submit = SubmitField("Registrar")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Senha", validators=[DataRequired()])
    submit = SubmitField("Entrar")


class SensitiveDataForm(FlaskForm):
    full_name = StringField("Nome completo", validators=[Optional(), Length(max=255)])
    cpf = StringField("CPF", validators=[Optional(), Length(min=11, max=14)])
    birthdate = DateField("Data de nascimento", validators=[Optional()])
    phone = StringField("Telefone", validators=[Optional(), Length(max=20)])
    address = StringField("Endereço", validators=[Optional(), Length(max=255)])
    submit = SubmitField("Salvar")


class TwoFAConfirmForm(FlaskForm):
    token = StringField("Código 2FA", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Ativar 2FA")
