from flask import Flask
from criptografias import Base64, SHA256, RSA

app = Flask(__name__)

@app.route("/")
def index():

    return "Index"

@app.route("/enviar", methods=["POST"])
def enviar():
    # Criptografa a mensagem com RSA
    # Criptografa o RSA em Base64
    # Faz o Hash do Base64 em SHA256
    # Envia a mensagem criptografada e o Hash
    return "Envio de mensagem"

if __name__ == "__main__":
    app.run(debug=True)