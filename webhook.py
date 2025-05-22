from flask import Flask
from criptografias import SHA256, Base64, RSA

app = Flask(__name__)


@app.route("/")
def index():
    return "Index de envio"

@app.route("/receber")
def receber():
    # Checa o Hash com SHA256
    # Descriptografa em Base64
    # Descriptografa em RSA
    # Mostra na Tela
    return "recebe"