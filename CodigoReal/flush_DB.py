import json
import hasher

with open("CodigoReal/credenciales.json", "w", encoding="utf-8") as file_credenciales, open("CodigoReal/transacciones.json", "w", encoding="utf-8") as file_transacciones,open("CodigoReal/nonces.json", "w", encoding="utf-8") as file_nonces:
    base_users = dict()
    base_users["admin"]=hasher.crear_hash_contraseña("1234")
    json.dump(base_users,file_credenciales, indent=4)
    json.dump(dict(),file_transacciones)
    json.dump(dict(),file_nonces)