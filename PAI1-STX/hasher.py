import base64
import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path


KEY_FILE = Path(__file__).resolve().with_name("secret.key")
try:
    with KEY_FILE.open("xb") as file_key:
        SECRET_KEY = secrets.token_bytes(32)
        file_key.write(SECRET_KEY)
except FileExistsError:
    SECRET_KEY = KEY_FILE.read_bytes()

if len(SECRET_KEY) < 32:
    raise ValueError("La clave HMAC debe tener al menos 32 bytes.")

MAX_INTENTOS = 3
TIEMPO_BLOQUEO = 300


def crear_hash_contraseña(contraseña: str) -> list:
    salt = os.urandom(16)
    hash_resultado = hashlib.pbkdf2_hmac(
        "sha256",
        contraseña.encode("utf-8"),
        salt,
        600000,
    )
    return [
        base64.b64encode(hash_resultado).decode("ascii"),
        base64.b64encode(salt).decode("ascii"),
        0,
        None,
    ]


def cuenta_bloqueada(datos_usuario: list) -> bool:
    if datos_usuario[3] is None:
        return False

    if time.time() - datos_usuario[3] < TIEMPO_BLOQUEO:
        return True

    datos_usuario[2] = 0
    datos_usuario[3] = None
    return False


def verificar_contraseña(contraseña_ingresada: str, datos_usuario: list) -> bool:
    if cuenta_bloqueada(datos_usuario):
        return False

    nuevo_hash = hashlib.pbkdf2_hmac(
        "sha256",
        contraseña_ingresada.encode("utf-8"),
        base64.b64decode(datos_usuario[1]),
        600000,
    )

    if hmac.compare_digest(nuevo_hash, base64.b64decode(datos_usuario[0])):
        datos_usuario[2] = 0
        datos_usuario[3] = None
        return True

    datos_usuario[2] += 1
    if datos_usuario[2] >= MAX_INTENTOS:
        datos_usuario[3] = time.time()
    return False


def crear_hash_signature(data: bytes, secret_key: bytes = SECRET_KEY) -> str:
    return hmac.new(secret_key, data, hashlib.sha256).hexdigest()


def verificar_signature(
    data: bytes, signature: str, secret_key: bytes = SECRET_KEY
) -> bool:
    firma_esperada = crear_hash_signature(data, secret_key)
    return hmac.compare_digest(firma_esperada, signature)
