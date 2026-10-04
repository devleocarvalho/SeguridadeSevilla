import http.server
import json
import math
import os
import time
import uuid
import urllib.parse
from http.cookies import SimpleCookie
from pathlib import Path

import hasher


DATA_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = DATA_DIR / "credenciales.json"
TRANSACTIONS_FILE = DATA_DIR / "transacciones.json"
NONCES_FILE = DATA_DIR / "nonces.json"
secret_key = hasher.SECRET_KEY
sesiones_activas = set()

with CREDENTIALS_FILE.open("r", encoding="utf-8") as file_credenciales:
    credenciales = json.load(file_credenciales)
with TRANSACTIONS_FILE.open("r", encoding="utf-8") as file_transacciones:
    transacciones = json.load(file_transacciones)
with NONCES_FILE.open("r", encoding="utf-8") as file_nonces:
    nonces_guardados = json.load(file_nonces)
nonces = nonces_guardados if isinstance(nonces_guardados, list) else []


def guardar_json(ruta: Path, datos: object) -> None:
    with ruta.open("w", encoding="utf-8") as archivo:
        json.dump(datos, archivo, indent=4)


class Handler(http.server.BaseHTTPRequestHandler):
    def responder(self, codigo: int, mensaje: str, cookie: str = "") -> None:
        self.send_response(codigo)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(mensaje.encode("utf-8"))

    def do_POST(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.responder(400, "Longitud de mensaje no válida.")
            return
        if content_length <= 0:
            self.responder(400, "El mensaje está vacío.")
            return

        byte_data = self.rfile.read(content_length)
        try:
            if "application/json" in self.headers.get("Content-Type", ""):
                params = json.loads(byte_data.decode("utf-8"))
                if not isinstance(params, dict):
                    raise ValueError("El cuerpo JSON debe ser un objeto.")
            else:
                valores = urllib.parse.parse_qs(byte_data.decode("utf-8"))
                params = {nombre: valor[0] for nombre, valor in valores.items()}
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.responder(400, "Cuerpo de mensaje no válido.")
            return

        signature = self.headers.get("X-Signature", "")
        nonce = self.headers.get("X-Nonce", "")
        timestamp = self.headers.get("X-Timestamp", "")
        try:
            timestamp_numero = float(timestamp)
        except ValueError:
            self.responder(403, "Mensaje no seguro detectado.")
            return

        mensaje_firmado = byte_data + nonce.encode("utf-8") + timestamp.encode("utf-8")
        if (
            not nonce
            or not math.isfinite(timestamp_numero)
            or abs(time.time() - timestamp_numero) > 60
            or nonce in nonces
            or not hasher.verificar_signature(mensaje_firmado, signature, secret_key)
        ):
            self.responder(403, "Mensaje no seguro detectado.")
            return

        nonces.append(nonce)
        guardar_json(NONCES_FILE, nonces)

        if self.path == "/signin":
            usuario = str(params.get("usuario", "")).strip()
            password = str(params.get("password", ""))
            if not usuario or not password:
                self.responder(400, "Usuario y contraseña son obligatorios.")
            elif usuario in credenciales:
                self.responder(403, "Usuario ya existe.")
            else:
                credenciales[usuario] = hasher.crear_hash_contraseña(password)
                guardar_json(CREDENTIALS_FILE, credenciales)
                self.responder(200, "Registro exitoso.")

        elif self.path == "/login":
            usuario = str(params.get("usuario", ""))
            password = str(params.get("password", ""))
            datos_usuario = credenciales.get(usuario)

            if datos_usuario is None:
                self.responder(401, "Credenciales incorrectas.")
            elif hasher.cuenta_bloqueada(datos_usuario):
                guardar_json(CREDENTIALS_FILE, credenciales)
                self.responder(429, "Cuenta bloqueada temporalmente.")
            elif hasher.verificar_contraseña(password, datos_usuario):
                guardar_json(CREDENTIALS_FILE, credenciales)
                id_sesion = str(uuid.uuid4())
                sesiones_activas.add(id_sesion)
                self.responder(
                    200,
                    "Inicio de sesión exitoso.",
                    f"session_id={id_sesion}; Path=/; HttpOnly",
                )
            else:
                guardar_json(CREDENTIALS_FILE, credenciales)
                self.responder(401, "Credenciales incorrectas.")

        elif self.path == "/logout":
            cookie_value = None
            cookie = self.headers.get("Cookie")
            if cookie:
                data_cookie = SimpleCookie()
                data_cookie.load(cookie)
                if "session_id" in data_cookie:
                    cookie_value = data_cookie["session_id"].value

            if cookie_value not in sesiones_activas:
                self.responder(403, "No hay una sesión activa.")
            else:
                sesiones_activas.remove(cookie_value)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header(
                    "Set-Cookie",
                    "session_id=; Path=/; HttpOnly; Max-Age=0",
                )
                self.end_headers()
                self.wfile.write("Sesión cerrada correctamente.".encode("utf-8"))

        elif self.path == "/transfer":
            cookie_value = None
            cookie = self.headers.get("Cookie")
            if cookie:
                data_cookie = SimpleCookie()
                data_cookie.load(cookie)
                if "session_id" in data_cookie:
                    cookie_value = data_cookie["session_id"].value

            if cookie_value not in sesiones_activas:
                self.responder(403, "Inicie sesión antes de realizar una transferencia.")
                return

            tx_id = str(params.get("tx_id", ""))
            origin_account = str(params.get("origin_account", ""))
            destination_account = str(params.get("destination_account", ""))
            amount = params.get("amount", "")
            currency = str(params.get("currency", ""))
            try:
                transaction_timestamp = float(params.get("timestamp", timestamp_numero))
            except (TypeError, ValueError):
                self.responder(400, "Timestamp de transacción no válido.")
                return

            if (
                not tx_id
                or not origin_account
                or not destination_account
                or not currency
                or not math.isfinite(transaction_timestamp)
            ):
                self.responder(400, "Faltan datos de la transferencia.")
            elif tx_id in transacciones:
                self.responder(403, "Transacción duplicada.")
            else:
                transacciones[tx_id] = [
                    origin_account,
                    destination_account,
                    amount,
                    currency,
                    transaction_timestamp,
                ]
                guardar_json(TRANSACTIONS_FILE, transacciones)
                self.responder(200, "Transacción exitosa.")

        else:
            self.responder(404, "Ruta no encontrada.")


host = "127.0.0.1"
port = int(
    os.environ.get("SECBANK_SERVER_PORT", os.environ.get("SECBANK_PORT", "8080"))
)
http.server.HTTPServer((host, port), Handler).serve_forever()
