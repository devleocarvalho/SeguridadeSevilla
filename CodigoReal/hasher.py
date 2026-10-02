import hashlib
import hmac
import os
import time
import base64




def crear_hash_contraseña(contraseña: str):
    # 1. Generar una sal aleatoria segura de 16 bytes
    salt = os.urandom(16)
    
    # 2. Aplicar PBKDF2-HMAC-SHA256 con 600,000 iteraciones (mínimo recomendado por OWASP)
    hash_resultado = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=contraseña.encode('utf-8'),
        salt=salt,
        iterations=600000
    )
    
    # Debes guardar tanto la sal como el hash en tu base de datos
    return [base64.b64encode(hash_resultado).decode("ascii"),base64.b64encode(salt).decode("ascii"),0,None]

def verificar_contraseña(contraseña_ingresada: str, DB) -> bool:
    # Generar el hash de la contraseña ingresada usando la misma sal e iteraciones
    nuevo_hash = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=contraseña_ingresada.encode('utf-8'),
        salt=base64.b64decode(DB[1]),
        iterations=600000
    )
    
    # Comparar en tiempo constante para evitar ataques de temporización
    if DB[3] is None or time.time()-DB[3] > 600:
        if hmac.compare_digest(nuevo_hash, base64.b64decode(DB[0])):
            return True
        else:
            DB[2] += 1
            if DB[2]>=2:
                DB[3] = time.time()
                print("Too many tries")
            return False
    else:
        print("Time left until next try:",600-(time.time()-DB[3]))
        return False


def crear_hash_signature(data: str, secret_key: str):
    hmac_resultado = hmac.new(signature,secret_key)
    
    return hmac_resultado

def verificar_signature(data:str, signature: str, secret_key: str) -> bool:
    # Generar el hash de la contraseña ingresada usando la misma sal e iteraciones
    hmac_resultado = hmac.new(signature,secret_key)
    return hmac.compare_digest(hmac_resultado, signature)