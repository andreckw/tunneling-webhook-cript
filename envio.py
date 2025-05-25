from flask import Flask, render_template, request
from criptografias import Base64, SHA256, RSA
import requests

app = Flask(__name__)

rsa = RSA()
keys = rsa.criar_chaves()

requests.post("http://127.0.0.1:5001/publickey", json={
            "public_key": keys["public_key"]
        })

@app.route("/", methods=["GET"])
def index():

    return render_template("envio.html")

@app.route("/enviar", methods=["GET"])
def enviar():
    msg = request.values.get("msg")
    
    # Criptografa a mensagem com RSA
    rsa_cript = RSA()
    msg_rs = rsa_cript.criptografar(msg, keys["private_key"])
    # Criptografa o RSA em Base64
    msg_base = Base64()
    msg_base = msg_base.criptografar(msg_rs)
    # Faz o Hash do Base64 em SHA256
    msg_hash = SHA256(msg_base)
    msg_hash = msg_hash.criptografar()

    # Envia a mensagem criptografada e o Hash
    requests.post("http://127.0.0.1:5001/receber", json={
        "msg": msg_base,
        "_csrf": msg_hash
    })
    
    return "Envio de mensagem"

if __name__ == "__main__":
    app.run(debug=True)