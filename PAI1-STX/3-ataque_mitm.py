import hmac, hashlib, json, time, uuid, urllib.request
from urllib.error import HTTPError

SECRET_KEY = b"Ahi_se_va_el_dinero_para_o_hacker_32_bytes_val_minimo!!"

# 1. O cliente cria a transação original de 100 euros e assina
tx_id = str(uuid.uuid4())
payload_original = json.dumps({"tx_id": tx_id, "amount": 100.00}).encode('utf-8')
nonce = str(uuid.uuid4())
timestamp = str(int(time.time()))

msg = payload_original + nonce.encode('utf-8') + timestamp.encode('utf-8')
signature = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
headers = {"X-Signature": signature, "X-Nonce": nonce, "X-Timestamp": timestamp}

# 2. O HACKER altera o payload na rede antes de chegar ao servidor!
print("--- INICIANDO ATAQUE MitM ---")
print("[!] O hacker alterou o valor para 99999.00 no meio da rede!")
payload_falso = json.dumps({"tx_id": tx_id, "amount": 99999.00}).encode('utf-8')

# O hacker envia o payload falso, mas com a assinatura original do cliente
req = urllib.request.Request("http://127.0.0.1:8080", data=payload_falso, headers=headers, method="POST")

try:
    urllib.request.urlopen(req)
except HTTPError as e:
    print(f"    -> BLOQUEADO! O servidor detetou a manipulação: Erro {e.code}")
