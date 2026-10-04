"""
Teste de tentativas de senha e bloqueio temporário.

Como executar no Kali:
1. Em um terminal, inicie o servidor: python3 Servidor.py
2. Em outro terminal, na pasta do projeto, rode:
   export SECBANK_SERVER_PORT=8081
   python3 3-ataque_fuerza_bruta.py
   (Use a porta 8081 se o servidor também estiver configurado nessa porta.)
3. O teste cria um usuário temporário com nome aleatório.
4. O esperado são três logins errados com HTTP 401 e, depois, HTTP 429
   quando tenta usar a senha correta, pois a conta foi bloqueada.

O script envia requisições reais de login ao servidor local. Não use uma
conta real: a conta criada fica bloqueada por cinco minutos.
"""

import json
import os
import time
import urllib.error
import urllib.request
import uuid

import hasher


# O usuário aleatório mantém este teste separado de contas existentes.
SERVER_PORT = os.environ.get(
    "SECBANK_SERVER_PORT", os.environ.get("SECBANK_PORT", "8080")
)
BASE_URL = f"http://127.0.0.1:{SERVER_PORT}"


def enviar(ruta: str, datos: bytes) -> tuple[int, str]:
    nonce = str(uuid.uuid4())
    timestamp = str(time.time())
    mensaje = datos + nonce.encode("utf-8") + timestamp.encode("utf-8")
    request = urllib.request.Request(
        f"{BASE_URL}{ruta}",
        data=datos,
        headers={
            "Content-Type": "application/json",
            "X-Signature": hasher.crear_hash_signature(mensaje),
            "X-Nonce": nonce,
            "X-Timestamp": timestamp,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request) as respuesta:
            return respuesta.status, respuesta.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")


usuario = f"fuerza_{uuid.uuid4().hex[:8]}"
password_correcta = "SuperClave2026!"
datos_registro = json.dumps(
    {"usuario": usuario, "password": password_correcta}
).encode("utf-8")
codigo, mensaje = enviar("/signin", datos_registro)
if codigo != 200:
    raise RuntimeError(f"No fue posible crear el usuario: HTTP {codigo}: {mensaje}")

print("Probando tres contraseñas incorrectas...")
for intento in range(1, hasher.MAX_INTENTOS + 1):
    datos_login = json.dumps(
        {"usuario": usuario, "password": f"incorrecta{intento}"}
    ).encode("utf-8")
    codigo, mensaje = enviar("/login", datos_login)
    print(f"Intento {intento}: HTTP {codigo} - {mensaje}")
    if codigo != 401:
        raise RuntimeError(
            f"El intento incorrecto {intento} respondió HTTP {codigo}: {mensaje}"
        )

print("Probando a seguir con la contraseña correcta...")
datos_login = json.dumps(
    {"usuario": usuario, "password": password_correcta}
).encode("utf-8")
codigo, mensaje = enviar("/login", datos_login)
if codigo == 429:
    print(f"Defensa activa: cuenta bloqueada - HTTP {codigo}: {mensaje}")
else:
    raise RuntimeError(
        f"La cuenta no quedó bloqueada: HTTP {codigo}: {mensaje}"
    )
