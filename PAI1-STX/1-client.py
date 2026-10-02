import hmac, hashlib, json, time, uuid, urllib.request

SECRET_KEY = b"Ahi_se_va_el_dinero_para_o_hacker_32_bytes_val_minimo!!"

# Dados da transação (JSON)
payload = json.dumps({"tx_id": str(uuid.uuid4()), "amount": 500050.75}).encode('utf-8')

# Geração de Nonce e Timestamp
nonce = str(uuid.uuid4())
timestamp = str(int(time.time()))

# Criando a Assinatura (HMAC)
msg = payload + nonce.encode('utf-8') + timestamp.encode('utf-8')
signature = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()

headers = {
    "X-Signature": signature,
    "X-Nonce": nonce,
    "X-Timestamp": timestamp
}

req = urllib.request.Request("http://127.0.0.1:8080", data=payload, headers=headers, method="POST")
try:
    urllib.request.urlopen(req)
    print("Transferência enviada com sucesso!")
except Exception as e:
    print(f"Erro: {e}")
    