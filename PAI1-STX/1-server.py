import hmac, hashlib, json, time, secrets
from http.server import HTTPServer, BaseHTTPRequestHandler

SECRET_KEY = b"Ahi_se_va_el_dinero_para_o_hacker_32_bytes_val_minimo!!"
seen_nonces = set()

class SecBankHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body_bytes = self.rfile.read(content_length)
        
        # Pega as chaves de segurança dos cabeçalhos
        sig_received = self.headers.get('X-Signature', '')
        nonce = self.headers.get('X-Nonce', '')
        timestamp_str = self.headers.get('X-Timestamp', '')
        
        # 1. Defesa contra Replay (Tempo e Nonce)
        if abs(int(time.time()) - int(timestamp_str)) > 30:
            self.send_response(401)
            self.end_headers()
            return
            
        if nonce in seen_nonces:
            self.send_response(401) # Se já viu este nonce, bloqueia!
            self.end_headers()
            return
        seen_nonces.add(nonce)
        
        # 2. Defesa contra Alteração (Calcula HMAC local)
        message_to_sign = body_bytes + nonce.encode('utf-8') + timestamp_str.encode('utf-8')
        computed_hmac = hmac.new(SECRET_KEY, message_to_sign, hashlib.sha256).hexdigest()
        
        # 3. Defesa contra Timing Attack (Tempo constante)
        if not secrets.compare_digest(computed_hmac, sig_received):
            self.send_response(403)
            self.end_headers()
            return
            
        print("[SUCESSO] Transferencia aprovada e segura!")
        self.send_response(200)
        self.end_headers()

HTTPServer(('127.0.0.1', 8080), SecBankHandler).serve_forever()
