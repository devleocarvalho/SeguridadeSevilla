import hmac, hashlib, json, time, uuid, urllib.request
from urllib.error import HTTPError

SECRET_KEY = b"Ahi_se_va_el_dinero_para_o_hacker_32_bytes_val_minimo!!"

payload = json.dumps({"tx_id": str(uuid.uuid4()), "amount": 100.00}).encode('utf-8')
nonce = str(uuid.uuid4())
timestamp = str(int(time.time()))

msg = payload + nonce.encode('utf-8') + timestamp.encode('utf-8')
signature = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()

headers = {"X-Signature": signature, "X-Nonce": nonce, "X-Timestamp": timestamp}
req = urllib.request.Request("http://127.0.0.1:8080", data=payload, headers=headers, method="POST")

print("--- INICIANDO ATAQUE DE REPLAY ---")
try:
    print("[1] Enviando transação original...")
    urllib.request.urlopen(req)
    print("    -> Sucesso! O servidor aceitou.")
    
    print("[2] O hacker capturou o pacote e está a tentar reenviar (Replay)...")
    urllib.request.urlopen(req)
except HTTPError as e:
    print(f"    -> BLOQUEADO! O servidor detetou o ataque: Erro {e.code}")

