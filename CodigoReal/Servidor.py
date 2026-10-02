import http.server
import urllib.parse
import hasher
import hashlib
import os
import time
import json


#Clave Secreta
secret_key = "mi_clave_secreta".encode("utf-8")
#RAM
sesiones_activas = set()
#Memoria
with open("CodigoReal/credenciales.json", "r", encoding="utf-8") as file_credenciales, open("CodigoReal/transacciones.json", "r", encoding="utf-8") as file_transacciones,open("CodigoReal/nonces.json", "r", encoding="utf-8") as file_nonces:
    credenciales = json.load(file_credenciales)
    transacciones = json.load(file_transacciones)
    nonces = json.load(file_nonces)
    

#Funcionalidad del Servidor
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        #Registro de usuario

        #Inicio de sesion
        if self.path == "/login":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            
            usuario = params.get('usuario', [''])[0]
            password = params.get('password', [''])[0]
            # Validación simple (credenciales "hardcodeadas")
            print("DB:",credenciales)
            if usuario in credenciales.keys() and hasher.verificar_contraseña(password,credenciales[usuario]):
                # Generar un ID de sesión simulado
                id_sesion = "token_secreto_12345"
                sesiones_activas.add(id_sesion)
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                # Enviar la cookie al cliente para persistir la sesión
                self.send_header('Set-Cookie', f'session_id={id_sesion}; Path=/; HttpOnly')
                self.end_headers()
                self.wfile.write("Inicio de sesión exitoso.".encode('utf-8'))
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write("Credenciales incorrectas.".encode('utf-8'))




#Inicio indefinido del servidor
http.server.HTTPServer(('127.0.0.1', 8080), Handler).serve_forever()
    