import json
from pathlib import Path

import hasher

data_dir = Path(__file__).resolve().parent

base_users = {"admin": hasher.crear_hash_contraseña("1234")}
with (data_dir / "credenciales.json").open("w", encoding="utf-8") as file_credenciales:
    json.dump(base_users, file_credenciales, indent=4)
with (data_dir / "transacciones.json").open("w", encoding="utf-8") as file_transacciones:
    json.dump({}, file_transacciones)
with (data_dir / "nonces.json").open("w", encoding="utf-8") as file_nonces:
    json.dump([], file_nonces)