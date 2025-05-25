from flask import Flask, render_template, request
from criptografias import Base64, SHA256, RSA
import requests

app = Flask("receber")

p_key = ""
msg = ""

@app.route("/", methods=["GET"])
def index():
    global msg
    return render_template("receber.html", msg=msg)


@app.route("/receber", methods=["POST"])
def receber():
    global msg, p_key
    
    json = request.get_json()
    sha = SHA256(json["msg"])
    csrf = sha.criptografar()
    
    if (json["_csrf"] != csrf):
        return "Mensagem alterada"
    
    msg_rsa = Base64().descriptografar(json["msg"])
    
    msg = RSA().descriptografar(msg_rsa, p_key)
    return "Mensagem recebida"
    
    


@app.route("/publickey", methods=["POST"])
def publickey():
    global p_key
    p_key = request.get_json()["public_key"]
    
    return "Recibido"


if __name__ == "__main__":
    app.run(debug=True, port=5001)