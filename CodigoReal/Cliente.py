import urllib.request
import urllib.parse
from http.cookiejar import CookieJar
import time
import uuid

#Cookie de inicio de sesion
cookies = CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
urllib.request.install_opener(opener)

#Direcciones Web
signin_URL = "http://127.0.0.1:8080/signin"
login_URL = "http://127.0.0.1:8080/login"
transfer_URL = "http://127.0.0.1:8080/transfer"

#Clave Secreta
secret_key = "mi_clave_secreta".encode("utf-8")

headers = {
    "X-Signature": "None",
    "X-Nonce": str(uuid.uuid4()),
    "X-Timestamp": str(time.time())
}


print("Avilable Commands: signin | login | transfer | exit ")
while True:
    console_text = input()
    #Sign In
    if console_text=="signin":
        print("Nuevo Usuario: ")
        usuario = input()
        print("Contraseña: ")
        password = input()
        datos = urllib.parse.urlencode({'usuario': usuario, 'password': password}).encode('utf-8')
        
        headers = {
            "X-Signature": "None",
            "X-Nonce": str(uuid.uuid4()),
            "X-Timestamp": str(time.time())
        }
        req_login = urllib.request.Request(signin_URL, data=datos, headers=headers, method='POST')
        try:
            with urllib.request.urlopen(req_login) as respuesta:
                print("Respuesta Sign In:", respuesta.read().decode('utf-8'))
        except Exception as e:
            print("Error en login:", e)

    #Login
    elif console_text=="login" and cookies.__len__()==0:
        print("Usuario: ")
        usuario = input()
        print("Contraseña: ")
        password = input()
        datos = urllib.parse.urlencode({'usuario': usuario, 'password': password}).encode('utf-8')
        req_login = urllib.request.Request(login_URL, data=datos, headers=headers, method='POST')
        try:
            with urllib.request.urlopen(req_login) as respuesta:
                print("Respuesta Login:", respuesta.read().decode('utf-8'))
        
        # Verificar que la cookie se guardó en nuestro contenedor
                print("\nCookies guardadas localmente:")
                for cookie in cookies:
                    print(f"- {cookie.name}: {cookie.value}")

        except Exception as e:
            print("Error en login:", e)

    #Transfer
        if console_text=="signin":
            print("Cuenta de Origen: ")
            origin_account = input()
            print("Cuenta de Destio: ")
            destination_account = input()
            print("Cantidad: ")
            amount = input()
            print("Moneda: ")
            currency = input()
            datos = urllib.parse.urlencode({'origin_account': origin_account, 
                                            'destination_account': destination_account,
                                            'amount': amount,
                                            'currency': currency}).encode('utf-8')
            req_login = urllib.request.Request(transfer_URL, data=datos, headers=headers, method='POST')
            try:
                with urllib.request.urlopen(req_login) as respuesta:
                    print("Respuesta Sign In:", respuesta.read().decode('utf-8'))
            except Exception as e:
                print("Error en login:", e)
    


    #Exit
    elif console_text=="exit":
        print("Bye bye!")
        break


    console_text = None