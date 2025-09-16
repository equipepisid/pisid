from flask import Flask, render_template, session, request, jsonify
from .config import Config
from .extensions import db, limiter, mail
from .models import init_db
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import hashlib
from datetime import datetime


class LeakChecker:
    """Sistema para verificar dados vazados em bases de dados conhecidas"""
    
    def __init__(self):
        self.known_leaks = self._load_known_leaks()
        self.cache = {}
    
    def _load_known_leaks(self):
        """Carrega dados de vazamentos conhecidos (simulado para demonstração)"""
        return {
            "emails": {
                "test@example.com": ["LinkedIn 2021", "Adobe 2013"],
                "admin@company.com": ["Dropbox 2012", "Yahoo 2013-2014"],
                "user@gmail.com": ["Facebook 2019", "Twitter 2020"],
                "john.doe@hotmail.com": ["Microsoft 2020", "Adobe 2013"],
                "maria@yahoo.com": ["Yahoo 2013-2014", "MySpace 2016"],
                "pedro@outlook.com": ["Microsoft 2020", "LinkedIn 2021"],
                "ana@bol.com": ["UOL 2018", "Globo 2019"],
                "carlos@terra.com": ["Terra 2017", "UOL 2018"],
                "julia@ig.com": ["IG 2016", "Globo 2019"],
                "roberto@r7.com": ["R7 2015", "UOL 2018"],
                "contato@empresa.com": ["Serasa 2020", "Receita Federal 2019"],
                "usuario@hotmail.com": ["Microsoft 2020", "LinkedIn 2021"],
                "exemplo@gmail.com": ["Google 2018", "Facebook 2019"],
                "teste123@yahoo.com": ["Yahoo 2013-2014", "MySpace 2016"]
            },
            "cpfs": {
                "12345678901": ["Serasa 2020", "Receita Federal 2019"],
                "98765432100": ["Banco Central 2021", "Serasa 2020"],
                "11122233344": ["Receita Federal 2019", "Banco Central 2021"],
                "55566677788": ["Serasa 2020", "Receita Federal 2019"],
                "99988877766": ["Banco Central 2021", "Serasa 2020"],
                "12312312312": ["Receita Federal 2019", "Banco Central 2021"],
                "45645645645": ["Serasa 2020", "Receita Federal 2019"],
                "78978978978": ["Banco Central 2021", "Serasa 2020"],
                "32132132132": ["Receita Federal 2019", "Banco Central 2021"],
                "65465465465": ["Serasa 2020", "Receita Federal 2019"],
                "14725836900": ["LGPD Breach 2022", "Serasa 2020"],
                "36925814700": ["Receita Federal 2019", "SPC 2021"]
            },
            "names": {
                "joão silva": ["Facebook 2019", "LinkedIn 2021"],
                "maria santos": ["Twitter 2020", "Facebook 2019"],
                "pedro oliveira": ["LinkedIn 2021", "Twitter 2020"],
                "ana costa": ["Facebook 2019", "LinkedIn 2021"],
                "carlos rodrigues": ["Twitter 2020", "Facebook 2019"],
                "julia ferreira": ["LinkedIn 2021", "Twitter 2020"],
                "roberto almeida": ["Facebook 2019", "LinkedIn 2021"],
                "lucia martins": ["Twitter 2020", "Facebook 2019"],
                "fernando lima": ["LinkedIn 2021", "Twitter 2020"],
                "patricia gomes": ["Facebook 2019", "LinkedIn 2021"],
                "antonio silva": ["Serasa 2020", "Receita Federal 2019"],
                "mariana costa": ["UOL 2018", "Globo 2019"]
            }
        }
    
    def _normalize_email(self, email):
        """Normaliza email para comparação"""
        return email.lower().strip()
    
    def _normalize_cpf(self, cpf):
        """Normaliza CPF removendo pontuação"""
        return re.sub(r'[^\d]', '', cpf)
    
    def _normalize_name(self, name):
        """Normaliza nome para comparação"""
        return re.sub(r'\s+', ' ', name.lower().strip())
    
    def _is_valid_email(self, email):
        """Valida formato de email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _is_valid_cpf(self, cpf):
        """Valida formato de CPF"""
        cpf_clean = self._normalize_cpf(cpf)
        if len(cpf_clean) != 11:
            return False
        
        # Validação básica de CPF
        if cpf_clean == cpf_clean[0] * 11:
            return False
        
        # Cálculo dos dígitos verificadores
        soma = sum(int(cpf_clean[i]) * (10 - i) for i in range(9))
        resto = soma % 11
        digito1 = 0 if resto < 2 else 11 - resto
        
        soma = sum(int(cpf_clean[i]) * (11 - i) for i in range(10))
        resto = soma % 11
        digito2 = 0 if resto < 2 else 11 - resto
        
        return cpf_clean[-2:] == f"{digito1}{digito2}"
    
    def check_data(self, data):
        """
        Verifica se os dados fornecidos foram vazados
        
        Args:
            data: Email, CPF ou nome para verificar
            
        Returns:
            Dict com informações sobre vazamentos encontrados
        """
        data = data.strip()
        if not data:
            return {"error": "Dados não fornecidos"}
        
        # Verificar cache
        cache_key = hashlib.md5(data.encode()).hexdigest()
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        result = {
            "input": data,
            "leaked": False,
            "leaks": [],
            "data_type": None,
            "timestamp": datetime.now().isoformat(),
            "recommendations": []
        }
        
        # Verificar se é email
        if self._is_valid_email(data):
            result["data_type"] = "email"
            normalized_email = self._normalize_email(data)
            if normalized_email in self.known_leaks["emails"]:
                result["leaked"] = True
                result["leaks"] = self.known_leaks["emails"][normalized_email]
                result["recommendations"] = [
                    "Altere sua senha imediatamente",
                    "Ative a autenticação de dois fatores (2FA)",
                    "Monitore suas contas regularmente",
                    "Considere usar um gerenciador de senhas"
                ]
        
        # Verificar se é CPF
        elif self._is_valid_cpf(data):
            result["data_type"] = "cpf"
            normalized_cpf = self._normalize_cpf(data)
            if normalized_cpf in self.known_leaks["cpfs"]:
                result["leaked"] = True
                result["leaks"] = self.known_leaks["cpfs"][normalized_cpf]
                result["recommendations"] = [
                    "Monitore seu CPF nos órgãos de proteção ao crédito",
                    "Verifique movimentações suspeitas em suas contas",
                    "Considere fazer um boletim de ocorrência",
                    "Ative alertas de uso do CPF"
                ]
        
        # Verificar se é nome
        else:
            result["data_type"] = "name"
            normalized_name = self._normalize_name(data)
            if normalized_name in self.known_leaks["names"]:
                result["leaked"] = True
                result["leaks"] = self.known_leaks["names"][normalized_name]
                result["recommendations"] = [
                    "Revise suas configurações de privacidade nas redes sociais",
                    "Considere usar pseudônimos em cadastros não essenciais",
                    "Monitore seu nome em mecanismos de busca",
                    "Seja cauteloso com informações pessoais online"
                ]
        
        # Adicionar ao cache
        self.cache[cache_key] = result
        return result
    
    def get_statistics(self):
        """Retorna estatísticas sobre vazamentos conhecidos"""
        total_emails = len(self.known_leaks["emails"])
        total_cpfs = len(self.known_leaks["cpfs"])
        total_names = len(self.known_leaks["names"])
        
        all_leaks = set()
        for leaks in self.known_leaks.values():
            for leak_list in leaks.values():
                all_leaks.update(leak_list)
        
        return {
            "total_emails_leaked": total_emails,
            "total_cpfs_leaked": total_cpfs,
            "total_names_leaked": total_names,
            "unique_leak_sources": len(all_leaks),
            "leak_sources": list(all_leaks)
        }


# Instância global do verificador
leak_checker = LeakChecker()


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    # Init extensions
    db.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)

    # Logging (audit)
    logs_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(logs_dir, exist_ok=True)
    handler = RotatingFileHandler(os.path.join(logs_dir, "security.log"), maxBytes=1_000_000, backupCount=3)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    if not any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers):
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)

    with app.app_context():
        init_db()

    # Blueprints
    from .blueprints.auth.routes import auth_bp
    from .blueprints.dashboard.routes import dashboard_bp
    from .blueprints.oauth.routes import oauth_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
    app.register_blueprint(oauth_bp, url_prefix="/oauth")

    # Home page
    @app.route("/")
    def index():
        return render_template("index.html")

    # API para verificação de dados vazados
    @app.route("/api/check-leak", methods=["POST"])
    @limiter.limit("10/minute")
    def check_leak_api():
        try:
            data = request.get_json()
            if not data or "data" not in data:
                return jsonify({"error": "Dados não fornecidos"}), 400
            
            result = leak_checker.check_data(data["data"])
            
            # Log da verificação
            app.logger.info(f"Verificação de vazamento: {data['data'][:10]}... - Resultado: {result.get('leaked', False)}")
            
            return jsonify(result)
        except Exception as e:
            app.logger.error(f"Erro na verificação de vazamento: {str(e)}")
            return jsonify({"error": "Erro interno do servidor"}), 500

    @app.route("/api/check-leak/<data>", methods=["GET"])
    @limiter.limit("10/minute")
    def check_leak_get(data):
        try:
            result = leak_checker.check_data(data)
            
            # Log da verificação
            app.logger.info(f"Verificação de vazamento: {data[:10]}... - Resultado: {result.get('leaked', False)}")
            
            return jsonify(result)
        except Exception as e:
            app.logger.error(f"Erro na verificação de vazamento: {str(e)}")
            return jsonify({"error": "Erro interno do servidor"}), 500

    @app.route("/api/leak-stats", methods=["GET"])
    @limiter.limit("5/minute")
    def leak_stats():
        try:
            stats = leak_checker.get_statistics()
            return jsonify(stats)
        except Exception as e:
            app.logger.error(f"Erro ao obter estatísticas: {str(e)}")
            return jsonify({"error": "Erro interno do servidor"}), 500

    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response

    return app
