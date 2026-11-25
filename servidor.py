"""Central de Consultas - servidor do Grupo 1 (Autenticacao, usuarios e permissoes).

Implementa as 8 rotas comuns do contrato. O aprofundamento do grupo esta em:
  - USUARIOS            : somente hash SHA-256 das senhas (sem senha em claro)
  - verificar_senha()   : compara hash com hmac.compare_digest
  - exige()             : decorator que aplica 401 (token) e 403 (permissao)
  - registrar()         : log que nunca grava senha, hash ou token
"""
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from datetime import datetime
from functools import wraps

import requests
from flask import Flask, g, jsonify, request

PORTA = int(os.environ.get("PORTA", "8000"))
TIMEOUT_EXTERNO = 5  # segundos
N_MAXIMO = 5_000_000  # limite de n em /processamento/* para evitar DoS por memoria/CPU
TOKEN_TTL_SEGUNDOS = 3600  # tokens expiram 1h apos o login

# ---------------------------------------------------------------- usuarios
# Somente hashes SHA-256. A senha em claro nao existe no codigo.
USUARIOS = {
    "admin": {
        "senha_hash": "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9",
        "algoritmo_hash": "sha256",
        "perfil": "administrador",
        "permissoes": ["basico", "avancado"],
    },
    "aluno": {
        "senha_hash": "fd5675ae2e933b4070e682938203dcbb978966909cf03f3d9c4f271ad1b3107b",
        "algoritmo_hash": "sha256",
        "perfil": "usuario",
        "permissoes": ["basico"],
    },
}

TOKENS = {}  # token -> {"usuario": nome, "expira": timestamp}
LOGS = []
trava = threading.Lock()

app = Flask(__name__)
app.json.sort_keys = False
app.json.ensure_ascii = False


def erro(mensagem, codigo):
    return jsonify({"erro": mensagem}), codigo


def registrar(texto):
    linha = f"{datetime.now().isoformat(timespec='seconds')} {texto}"
    with trava:
        LOGS.append(linha)
        del LOGS[:-500]


@app.before_request
def inicio():
    g.t0 = time.perf_counter()


@app.after_request
def depois(resp):
    ms = int((time.perf_counter() - g.get("t0", time.perf_counter())) * 1000)
    usuario = g.get("usuario")
    extra = f" usuario={usuario}" if usuario else ""
    registrar(f"{request.method} {request.path}{extra} status={resp.status_code} tempo_ms={ms}")
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/<path:_qualquer>", methods=["OPTIONS"])
def preflight_cors(_qualquer):
    return "", 204


# ---------------------------------------------------------------- autenticacao
def verificar_senha(usuario, senha):
    cadastro = USUARIOS.get(usuario)
    # calcula o hash mesmo para usuario desconhecido (tempo parecido)
    hash_informado = hashlib.sha256(senha.encode("utf-8")).hexdigest()
    guardado = cadastro["senha_hash"] if cadastro else "0" * 64
    return cadastro is not None and hmac.compare_digest(hash_informado, guardado)


def exige(permissao=None):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            cab = request.headers.get("Authorization", "")
            partes = cab.split(" ", 1)
            if len(partes) != 2 or partes[0].lower() != "bearer" or not partes[1].strip():
                return erro("token ausente", 401)
            token = partes[1].strip()
            with trava:
                registro = TOKENS.get(token)
                if registro is not None and registro["expira"] < time.time():
                    del TOKENS[token]
                    registro = None
            if registro is None:
                return erro("token invalido ou expirado", 401)
            usuario = registro["usuario"]
            g.usuario = usuario
            if permissao and permissao not in USUARIOS[usuario]["permissoes"]:
                return erro("sem permissao", 403)
            return f(*a, **kw)
        return wrapper
    return deco


def corpo_json():
    dados = request.get_json(silent=True, force=True)
    return dados if isinstance(dados, dict) else None


# ---------------------------------------------------------------- rotas
@app.get("/saude")
def saude():
    return jsonify({"status": "ok", "servico": "central-consultas"})


@app.post("/login")
def login():
    dados = corpo_json()
    if dados is None:
        return erro("JSON ausente ou invalido", 400)
    usuario, senha = dados.get("usuario"), dados.get("senha")
    if not isinstance(usuario, str) or not isinstance(senha, str) or not usuario or not senha:
        return erro("campos usuario e senha sao obrigatorios", 400)
    if not verificar_senha(usuario, senha):
        registrar(f"login falhou usuario={usuario[:40]!r}")
        return erro("usuario ou senha invalidos", 401)
    token = secrets.token_urlsafe(32)
    with trava:
        TOKENS[token] = {"usuario": usuario, "expira": time.time() + TOKEN_TTL_SEGUNDOS}
    g.usuario = usuario
    cad = USUARIOS[usuario]
    return jsonify({"token": token, "perfil": cad["perfil"], "permissoes": cad["permissoes"]})


@app.get("/perfil")
@exige()
def perfil():
    cad = USUARIOS[g.usuario]
    return jsonify({"usuario": g.usuario, "perfil": cad["perfil"], "permissoes": cad["permissoes"]})


def contar_primos(n):
    marcados = bytearray(b"\x01") * (n + 1)
    marcados[0:2] = b"\x00\x00"
    for v in range(2, int(n ** 0.5) + 1):
        if marcados[v]:
            marcados[v * v::v] = b"\x00" * len(range(v * v, n + 1, v))
    return sum(marcados)


def processar():
    dados = corpo_json()
    if dados is None:
        return erro("JSON ausente ou invalido", 400)
    n = dados.get("n")
    if isinstance(n, bool) or not isinstance(n, int) or n < 2 or n > N_MAXIMO:
        return erro(f"n deve ser inteiro entre 2 e {N_MAXIMO}", 400)
    t0 = time.perf_counter()
    r = contar_primos(n)
    return jsonify({"resultado": r, "tempo_ms": int((time.perf_counter() - t0) * 1000),
                    "modo": "sequencial"})


@app.post("/processamento/basico")
@exige("basico")
def basico():
    return processar()


@app.post("/processamento/avancado")
@exige("avancado")
def avancado():
    return processar()


@app.get("/consultas/cep/<cep>")
def cep(cep):
    if not re.fullmatch(r"\d{8}", cep):
        return erro("CEP deve ter 8 digitos", 400)
    try:
        r = requests.get(f"https://viacep.com.br/ws/{cep}/json/", timeout=TIMEOUT_EXTERNO)
        if r.status_code in (400, 404):
            return erro("CEP nao encontrado", 404)
        r.raise_for_status()
        d = r.json()
        if d.get("erro"):
            return erro("CEP nao encontrado", 404)
        return jsonify({"cep": cep, "logradouro": d.get("logradouro", ""),
                        "bairro": d.get("bairro", ""), "cidade": d.get("localidade", ""),
                        "uf": d.get("uf", "")})
    except (requests.RequestException, ValueError):
        pass
    try:  # fallback BrasilAPI
        r = requests.get(f"https://brasilapi.com.br/api/cep/v1/{cep}", timeout=TIMEOUT_EXTERNO)
        if r.status_code == 404:
            return erro("CEP nao encontrado", 404)
        r.raise_for_status()
        d = r.json()
        return jsonify({"cep": cep, "logradouro": d.get("street", ""),
                        "bairro": d.get("neighborhood", ""), "cidade": d.get("city", ""),
                        "uf": d.get("state", "")})
    except (requests.RequestException, ValueError):
        return erro("falha na API externa de CEP", 502)


@app.get("/consultas/clima")
def clima():
    try:
        lat = float(request.args["latitude"])
        lon = float(request.args["longitude"])
    except (KeyError, ValueError):
        return erro("latitude e longitude numericas sao obrigatorias", 400)
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return erro("coordenadas fora do intervalo", 400)
    try:
        r = requests.get("https://api.open-meteo.com/v1/forecast",
                         params={"latitude": lat, "longitude": lon, "current_weather": "true"},
                         timeout=TIMEOUT_EXTERNO)
        r.raise_for_status()
        c = r.json()["current_weather"]
        return jsonify({"latitude": lat, "longitude": lon,
                        "temperatura_c": c["temperature"], "vento_kmh": c["windspeed"]})
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return erro("falha na API externa de clima", 502)


@app.get("/logs")
@exige("avancado")  # somente administrador
def logs():
    with trava:
        return jsonify({"linhas": LOGS[-100:]})


@app.errorhandler(404)
def nao_encontrada(_):
    return erro("rota nao encontrada", 404)


@app.errorhandler(405)
def metodo(_):
    return erro("metodo nao permitido", 405)


@app.errorhandler(Exception)
def inesperado(e):
    return erro("erro interno", 500)


if __name__ == "__main__":
    print(f"Servidor na porta {PORTA}")
    app.run(host="0.0.0.0", port=PORTA, threaded=True)
