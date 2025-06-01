from flask import Flask, render_template, request, url_for, redirect
from criptografias import Base64, SHA256, RSA
import requests

app = Flask(__name__)

url_base = "http://127.0.0.1:5001"
my_key_private = ""
key_public = ""
msgs = []
conectado = False

@app.route("/", methods=["GET"])
def index():
    global conectado
    return render_template("app.html", conectado=conectado)


@app.route("/mensagens", methods=["GET"])
def mensagens():
    global msgs
    
    return render_template("mensagens.html", msgs=msgs)

@app.route("/conectar", methods=["POST"])
def conectar():
    global my_key_private, conectado
    rsa = RSA()
    keys = rsa.criar_chaves()

    requests.post(f"{url_base}/publickey", json={
            "public_key": keys["public_key"]
        })
    
    my_key_private = keys["private_key"]
    conectado = True
    
    return redirect(url_for("index"))

@app.route("/enviar", methods=["GET"])
def enviar():
    global msgs, key_public
    msg = request.values.get("msg")
    msgs.append(msg)
    
    # Criptografa a mensagem com RSA
    rsa_cript = RSA()
    msg_rs = rsa_cript.criptografar(msg, key_public)
    # Criptografa o RSA em Base64
    msg_base = Base64()
    msg_base = msg_base.criptografar(msg_rs)
    # Faz o Hash do Base64 em SHA256
    msg_hash = SHA256(msg_base)
    msg_hash = msg_hash.criptografar()
    print(f"Msg original: {msg}")
    print(f"Msg cript: {msg_rs}")

    # Envia a mensagem criptografada e o Hash
    requests.post(f"{url_base}/receber", json={
        "msg": msg_base,
        "_csrf": msg_hash
    })
    
    return "Envio de mensagem"

@app.route("/receber", methods=["POST"])
def receber():
    global msgs, my_key_private
    
    json = request.get_json()
    sha = SHA256(json["msg"])
    csrf = sha.criptografar()
    
    if (json["_csrf"] != csrf):
        return {"Mensagem alterada"}
    
    msg_rsa = Base64().descriptografar(json["msg"])
    
    msgs.append(RSA().descriptografar(msg_rsa, my_key_private))
    return "Mensagem recebida"


@app.route("/publickey", methods=["POST"])
def publickey():
    global key_public
    key_public = request.get_json()["public_key"]
    print(key_public)
    
    return "Recibido"

if __name__ == "__main__":
    app.run(debug=True)