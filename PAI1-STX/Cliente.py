"""
Cliente de teste: registro, login e transferência.

Uso normal no Kali:
1. Em outro terminal, inicie o servidor com: python3 Servidor.py
2. Execute: python3 Cliente.py
3. Digite signin e informe um usuário e senha de teste.
4. Digite login e use o mesmo usuário e senha.
5. Digite transfer e informe origem, destino, valor e moeda.
6. Digite logout para encerrar a sessão no servidor.
7. Digite exit para fechar o cliente.

Para observar as mesmas requisições no Burp, configure o servidor em 8081,
o listener do Burp em 8082 e, antes de executar este cliente, rode:
export SECBANK_SERVER_PORT=8081
export SECBANK_BURP_PROXY=http://127.0.0.1:8082

Se SECBANK_BURP_PROXY não estiver definida, o cliente conecta diretamente
ao servidor, sem passar pelo Burp.
"""

import urllib.request
import urllib.parse
import json
from http.cookiejar import CookieJar
import os
from urllib.parse import urlsplit
import time
import uuid
import hasher

#Cookie de inicio de sesion
cookies = CookieJar()


class BurpProxyHandler(urllib.request.ProxyHandler):
    # ProxyHandler normalmente ignora endereços locais; aqui forçamos o tráfego
    # para o Burp mesmo quando o servidor está em 127.0.0.1.
    def proxy_open(self, req, proxy, proxy_type):
        if proxy_type != "http":
            raise ValueError("Este teste usa somente o proxy HTTP do Burp.")

        partes_proxy = urlsplit(proxy)
        if partes_proxy.scheme != "http" or not partes_proxy.netloc:
            raise ValueError(
                "Use o proxy HTTP do Burp, por exemplo http://127.0.0.1:8082"
            )

        servidor_original = req.host
        req.add_unredirected_header("Host", servidor_original)
        req.set_proxy(partes_proxy.netloc, "http")
        return None


# Defina SECBANK_BURP_PROXY para enviar as requisições pelo Burp.
burp_proxy = os.environ.get("SECBANK_BURP_PROXY")
if burp_proxy:
    opener = urllib.request.build_opener(
        BurpProxyHandler({"http": burp_proxy}),
        urllib.request.HTTPCookieProcessor(cookies),
    )
else:
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookies)
    )
urllib.request.install_opener(opener)

#Direcciones Web
# Use uma porta de servidor diferente da porta do listener do Burp.
client_port = os.environ.get(
    "SECBANK_SERVER_PORT",
    os.environ.get("SECBANK_CLIENT_PORT", os.environ.get("SECBANK_PORT", "8080")),
)
base_URL = f"http://127.0.0.1:{client_port}"
signin_URL = f"{base_URL}/signin"
login_URL = f"{base_URL}/login"
transfer_URL = f"{base_URL}/transfer"
logout_URL = f"{base_URL}/logout"

#Clave Secreta
secret_key = hasher.SECRET_KEY




# A ordem normal de uso é registrar (se necessário), entrar e depois transferir.
print("Comandos disponíveis: signin | login | transfer | logout | exit")
while True:
    console_text = input()
    # Cria uma conta de teste no servidor.
    if console_text=="signin":
        print("Nuevo Usuario: ")
        usuario = input()
        print("Contraseña: ")
        password = input()
        datos = urllib.parse.urlencode({'usuario': usuario, 'password': password}).encode('utf-8')
        nonce = str(uuid.uuid4())
        timestamp = str(time.time())
        headers = {
            "X-Signature": hasher.crear_hash_signature(datos+nonce.encode('utf-8')+timestamp.encode('utf-8'), secret_key),
            "X-Nonce": nonce,
            "X-Timestamp": timestamp
        }
        req_login = urllib.request.Request(signin_URL, data=datos, headers=headers, method='POST')
        try:
            with urllib.request.urlopen(req_login) as respuesta:
                print("Respuesta Sign In:", respuesta.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            mensaje_error = e.read().decode('utf-8')
            print(f"Error en login ({e.code}): {mensaje_error}")
        except Exception as e:
            print("Error en login:", e)

    # Autentica e guarda o cookie da sessão para a transferência.
    elif console_text=="login" and cookies.__len__()==0:
        print("Usuario: ")
        usuario = input()
        print("Contraseña: ")
        password = input()
        datos = urllib.parse.urlencode({'usuario': usuario, 'password': password}).encode('utf-8')
        nonce = str(uuid.uuid4())
        timestamp = str(time.time())
        headers = {
            "X-Signature": hasher.crear_hash_signature(datos+nonce.encode('utf-8')+timestamp.encode('utf-8'), secret_key),
            "X-Nonce": nonce,
            "X-Timestamp": timestamp
        }
        req_login = urllib.request.Request(login_URL, data=datos, headers=headers, method='POST')
        try:
            with urllib.request.urlopen(req_login) as respuesta:
                print("Respuesta Login:", respuesta.read().decode('utf-8'))
        
        # Verificar que la cookie se guardó en nuestro contenedor
                print("\nCookies guardadas localmente:")
                for cookie in cookies:  
                    print(f"- {cookie.name}: {cookie.value}")
        except urllib.error.HTTPError as e:
            mensaje_error = e.read().decode('utf-8')
            print(f"Error en login ({e.code}): {mensaje_error}")
        except Exception as e:
            print("Error en login:", e)

    # Envia a transferência com assinatura, nonce e timestamp próprios.
    elif console_text=="transfer":
        tx_id = str(uuid.uuid4())
        print("Cuenta de Origen: ")
        origin_account = input()
        print("Cuenta de Destio: ")
        destination_account = input()
        print("Cantidad: ")
        amount = input()
        print("Moneda: ")
        currency = input()
        nonce = str(uuid.uuid4())
        timestamp = str(time.time())
        datos = json.dumps({
            'tx_id': tx_id,
            'origin_account': origin_account,
            'destination_account': destination_account,
            'amount': float(amount),
            'currency': currency,
            'timestamp': float(timestamp)
        }).encode('utf-8')
        headers = {
            "Content-Type": "application/json",
            "X-Signature": hasher.crear_hash_signature(datos+nonce.encode('utf-8')+timestamp.encode('utf-8'), secret_key),
            "X-Nonce": nonce,
            "X-Timestamp": timestamp
        }
        req_transferencia = urllib.request.Request(
            transfer_URL, data=datos, headers=headers, method='POST'
        )
        try:
            with urllib.request.urlopen(req_transferencia) as respuesta:
                print("Respuesta Transferencia:", respuesta.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            mensaje_error = e.read().decode('utf-8')
            print(f"Error en transferencia ({e.code}): {mensaje_error}")
        except Exception as e:
            print("Error en transferencia:", e)

    # Invalida a sessão no servidor e remove o cookie local.
    elif console_text=="logout":
        if len(cookies) == 0:
            print("Nenhuma sessão ativa. Faça login primeiro.")
            continue

        datos = b"logout=1"
        nonce = str(uuid.uuid4())
        timestamp = str(time.time())
        headers = {
            "X-Signature": hasher.crear_hash_signature(
                datos + nonce.encode("utf-8") + timestamp.encode("utf-8"),
                secret_key,
            ),
            "X-Nonce": nonce,
            "X-Timestamp": timestamp,
        }
        req_logout = urllib.request.Request(
            logout_URL, data=datos, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req_logout) as respuesta:
                print("Respuesta Logout:", respuesta.read().decode("utf-8"))
                cookies.clear()
        except urllib.error.HTTPError as e:
            mensaje_error = e.read().decode("utf-8")
            print(f"Error en logout ({e.code}): {mensaje_error}")
        except Exception as e:
            print("Error en logout:", e)
    

    # Fecha o programa. Use logout antes para encerrar também a sessão no servidor.
    elif console_text=="exit":
        print("Bye bye!")
        break


    console_text = None