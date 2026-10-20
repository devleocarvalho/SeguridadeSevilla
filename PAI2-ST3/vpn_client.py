#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
CLIENTE BYOD ROAD WARRIOR VPN SSL/TLS 1.3 - UNIVERSIDAD U-SECURE
Módulo: vpn_client.py
Equipo: Security Team 3 (Grupo 3)
Asignatura: Seguridad en Sistemas Informáticos y en Internet - PAI 2 (BYODSEC)
Fecha: Octubre 2026
========================================================================================
Descripción General:
Este módulo implementa la aplicación cliente para dispositivos personales (BYOD) del personal
docente (PDI), administración (PTGAS) e investigadores de la Universidad Pública U-Secure.
Establece túneles cifrados basados exclusivamente en TLS 1.3 con autenticación mutua (mTLS).

Requisitos Cumplidos:
1. Autenticación en Dos Capas (RF2): Presenta certificado criptográfico X.509 de cliente
   en la capa de transporte y credenciales corporativas en la capa de aplicación.
2. Cumplimiento Estricto de TLS 1.3 (RS2): Excluye cualquier versión obsoleta de SSL/TLS.
3. Validación Criptográfica del Servidor (RS1): Verifica la identidad del gateway institucional
   frente al certificado raíz de la U-Secure Root CA.
4. Desmontaje Explícito de Túnel (RF4): Envía comando seguro de fin de sesión y destruye claves efímeras.
5. Interfaz Interactiva CLI y Modo Programático para Benchmarking Masivo (RS3).
========================================================================================
"""

import os
import sys
import json
import socket
import ssl
import getpass
import time
from datetime import datetime
from typing import Optional, Dict, Any

# Importamos funciones de emisión PKI y base de datos institucional
from pki_manager import issue_client_certificate_for_user
from database import register_user

# Definición de rutas base para certificados
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca.crt")

# Parámetros por defecto de conexión
DEFAULT_SERVER_HOST = "127.0.0.1"
DEFAULT_SERVER_PORT = 8443
DEFAULT_SERVER_HOSTNAME = "vpn.usecure.edu.es"


class VpnClient:
    """
    Qué hace:
        Encapsula toda la lógica criptográfica y de comunicación de red para el cliente BYOD.
    Cuál es su función:
        Establecer el túnel TLS 1.3, autenticar al usuario frente a la pasarela VPN corporativa,
        consultar recursos institucionales y desmontar el túnel de forma segura.
    Cómo lo hace:
        1. Configura el contexto TLS con ssl.create_default_context exigiendo TLS 1.3.
        2. Carga el certificado y clave privada del cliente BYOD (client.crt / client.key).
        3. Realiza el handshake mTLS con el gateway VPN verificando el certificado del servidor.
        4. Envía tramas JSON serializadas por el socket TLS.
    """

    def __init__(
        self,
        cert_path: str,
        key_path: str,
        ca_path: str = CA_CERT_PATH,
        server_host: str = DEFAULT_SERVER_HOST,
        server_port: int = DEFAULT_SERVER_PORT,
        server_hostname: str = DEFAULT_SERVER_HOSTNAME
    ):
        """
        Inicializa los parámetros criptográficos del cliente BYOD.
        """
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        self.server_host = server_host
        self.server_port = server_port
        self.server_hostname = server_hostname

        self.ssl_sock: Optional[ssl.SSLSocket] = None
        self.raw_sock: Optional[socket.socket] = None
        self.session_info: Optional[Dict[str, Any]] = None
        self.is_connected = False

        # Construimos el contexto criptográfico cliente
        self.ssl_context = self._build_tls13_client_context()

    def _build_tls13_client_context(self) -> ssl.SSLContext:
        """
        Qué hace:
            Crea el contexto criptográfico de cliente forzando TLS 1.3 y mTLS.
        Cuál es su función:
            Garantizar que el cliente solo negocie TLS 1.3 y provea su certificado de dispositivo.
        Cómo lo hace:
            1. ssl.create_default_context con Purpose.SERVER_AUTH y cafile corporativo.
            2. Fija minimum_version y maximum_version en TLSVersion.TLSv1_3.
            3. Carga el par certificado/clave del dispositivo BYOD con load_cert_chain.
        """
        # Verificamos la existencia de los certificados necesarios
        if not os.path.exists(self.ca_path):
            raise FileNotFoundError(f"Certificado de CA no encontrado: {self.ca_path}")
        if not os.path.exists(self.cert_path):
            raise FileNotFoundError(f"Certificado de cliente no encontrado: {self.cert_path}")
        if not os.path.exists(self.key_path):
            raise FileNotFoundError(f"Clave privada de cliente no encontrada: {self.key_path}")

        # Creamos el contexto configurado para autenticar al servidor con la CA raíz corporativa
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_path)

        # Forzamos estrictamente el protocolo seguro TLS 1.3 (RS2)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        # Habilitamos la verificación del nombre de host del servidor (SAN)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        # Cargamos el certificado digital y la clave privada del dispositivo BYOD (mTLS - RS1)
        context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)

        return context

    def connect(self) -> bool:
        """
        Qué hace:
            Abre la conexión TCP y ejecuta el handshake TLS 1.3 con autenticación mutua (mTLS).
        Cuál es su función:
            Establecer la capa segura de transporte cifrada entre el dispositivo BYOD y el servidor VPN.
        Cómo lo hace:
            1. socket.create_connection hacia el host y puerto del servidor.
            2. wrap_socket con server_hostname para verificación estricta de SAN en TLS 1.3.
        """
        try:
            # Creamos el socket TCP crudo
            self.raw_sock = socket.create_connection((self.server_host, self.server_port), timeout=10.0)

            # Envolvemos el socket en el túnel TLS 1.3 ejecutando el handshake mTLS
            self.ssl_sock = self.ssl_context.wrap_socket(self.raw_sock, server_hostname=self.server_hostname)

            self.is_connected = True
            return True
        except ssl.SSLCertVerificationError as cert_err:
            print(f"[!] Error de Validación Criptográfica en Certificado del Servidor: {cert_err}")
            self.close()
            return False
        except ssl.SSLError as ssl_err:
            print(f"[!] Error de Protocolo TLS: {ssl_err}")
            self.close()
            return False
        except Exception as err:
            print(f"[!] Fallo al conectar con el Gateway VPN: {err}")
            self.close()
            return False

    def send_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Qué hace:
            Envía una petición JSON a través del túnel seguro y espera la respuesta del servidor.
        Cuál es su función:
            Intercambiar tramas de control de aplicación encapsuladas en el canal TLS 1.3.
        Cómo lo hace:
            Serializa a JSON terminado en '\n', escribe en ssl_sock y lee del búfer hasta recibir el salto de línea.
        """
        if not self.ssl_sock or not self.is_connected:
            return {"status": 500, "error": "No hay túnel TLS activo"}

        # Enviamos la trama JSON cifrada
        data_to_send = (json.dumps(payload) + "\n").encode("utf-8")
        self.ssl_sock.sendall(data_to_send)

        # Leemos la respuesta cifrada
        buffer = ""
        while "\n" not in buffer:
            chunk = self.ssl_sock.recv(4096)
            if not chunk:
                break
            buffer += chunk.decode("utf-8")

        if not buffer:
            return {"status": 500, "error": "Conexión cerrada por el servidor"}

        line, _ = buffer.split("\n", 1)
        return json.loads(line)

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Qué hace:
            Ejecuta la autenticación de segunda capa (Capa de Aplicación - RF2).
        Cuál es su función:
            Validar el usuario y contraseña corporativa dentro del túnel seguro establecido.
        Cómo lo hace:
            Envía acción 'LOGIN' con usuario y contraseña; guarda session_info en caso de éxito.
        """
        req = {
            "action": "LOGIN",
            "username": username,
            "password": password,
            "client_version": "1.3"
        }
        res = self.send_request(req)
        if res.get("status") == 200 and res.get("authenticated"):
            self.session_info = res
        return res

    def access_service(self, service_code: str) -> Dict[str, Any]:
        """
        Qué hace:
            Solicita acceso a un servicio específico de la intranet institucional de U-Secure.
        Cuál es su función:
            Demostrar el uso funcional del túnel VPN para navegar recursos universitarios según rol.
        Cómo lo hace:
            Envía acción 'ACCESS_SERVICE' indicando el código del servicio deseado.
        """
        if not self.session_info:
            return {"status": 401, "error": "Debe autenticarse en el túnel antes de acceder a recursos"}

        req = {
            "action": "ACCESS_SERVICE",
            "session_id": self.session_info.get("session_id"),
            "service": service_code
        }
        return self.send_request(req)

    def list_emails(self, unread_only: bool = False) -> Dict[str, Any]:
        """
        Qué hace:
            Solicita la lista de correos de la bandeja de entrada del usuario autenticado en la VPN.
        Cuál es su función:
            Permitir al cliente consultar los mensajes recibidos en el servicio webmail institucional.
        Cómo lo hace:
            Envía una trama ACCESS_SERVICE con service='CORREO_CORPORATIVO' y email_action='LIST'.
        """
        # Verificamos que exista una sesión activa
        if not self.session_info:
            return {"status": 401, "error": "Debe autenticarse antes de acceder al correo"}

        # Construimos la petición estructurada JSON
        req = {
            "action": "ACCESS_SERVICE",
            "session_id": self.session_info.get("session_id"),
            "service": "CORREO_CORPORATIVO",
            "email_action": "LIST",
            "unread_only": unread_only
        }
        # Enviamos la solicitud a través del canal seguro TLS 1.3
        return self.send_request(req)

    def read_email(self, email_id: int) -> Dict[str, Any]:
        """
        Qué hace:
            Solicita la lectura del cuerpo y metadatos de un mensaje específico identificado por su ID.
        Cuál es su función:
            Permitir al usuario visualizar el texto completo de un correo institucional y marcarlo como leído.
        Cómo lo hace:
            Envía una trama ACCESS_SERVICE con service='CORREO_CORPORATIVO', email_action='READ' y el email_id.
        """
        if not self.session_info:
            return {"status": 401, "error": "Debe autenticarse antes de acceder al correo"}

        req = {
            "action": "ACCESS_SERVICE",
            "session_id": self.session_info.get("session_id"),
            "service": "CORREO_CORPORATIVO",
            "email_action": "READ",
            "email_id": email_id
        }
        return self.send_request(req)

    def send_email(self, recipient: str, subject: str, body: str) -> Dict[str, Any]:
        """
        Qué hace:
            Envía un nuevo mensaje de correo electrónico a otro usuario o servicio dentro de la red corporativa.
        Cuál es su función:
            Materializar la capacidad bidireccional de comunicación segura dentro del perímetro VPN.
        Cómo lo hace:
            Envía una trama ACCESS_SERVICE con service='CORREO_CORPORATIVO', email_action='SEND', recipient, subject y body.
        """
        if not self.session_info:
            return {"status": 401, "error": "Debe autenticarse antes de enviar correos"}

        req = {
            "action": "ACCESS_SERVICE",
            "session_id": self.session_info.get("session_id"),
            "service": "CORREO_CORPORATIVO",
            "email_action": "SEND",
            "recipient": recipient,
            "subject": subject,
            "body": body
        }
        return self.send_request(req)

    def ping(self) -> Dict[str, Any]:
        """
        Envía un paquete PING para medir latencia y comprobar la vigencia del túnel.
        """
        return self.send_request({"action": "PING"})

    def disconnect(self) -> Dict[str, Any]:
        """
        Qué hace:
            Desmonta el túnel VPN de manera explícita y forzada (RF4).
        Cuál es su función:
            Asegurar la destrucción inmediata de las claves de sesión efímeras (PFS) y liberar la IP virtual.
        Cómo lo hace:
            Envía acción 'DISCONNECT', procesa la confirmación del servidor y cierra los sockets de red.
        """
        res = {}
        try:
            if self.is_connected and self.ssl_sock:
                res = self.send_request({"action": "DISCONNECT"})
        finally:
            self.close()
        return res

    def close(self) -> None:
        """
        Cierra y destruye los descriptores de socket locales.
        """
        self.is_connected = False
        self.session_info = None
        if self.ssl_sock:
            try:
                self.ssl_sock.close()
            except Exception:
                pass
            self.ssl_sock = None
        if self.raw_sock:
            try:
                self.raw_sock.close()
            except Exception:
                pass
            self.raw_sock = None


def handle_webmail_cli(client: VpnClient, current_user: str) -> None:
    """
    Qué hace:
        Gestiona la interfaz interactiva del buzón de correo institucional (Webmail).
    Cuál es su función:
        Permitir al usuario listar mensajes de su bandeja de entrada, leer correos detallados y redactar nuevos mensajes.
    Cómo lo hace:
        Presenta un submenú, envía solicitudes JSON encapsuladas en TLS 1.3 y formatea las respuestas para el usuario.
    """
    while True:
        print("\n" + "=" * 65)
        print(f" BUZÓN INSTITUCIONAL WEBMAIL - USUARIO: {current_user}")
        print("=" * 65)
        print("  [1] Ver Bandeja de Entrada (Listar y Leer Correos)")
        print("  [2] Redactar y Enviar Nuevo Correo")
        print("  [3] Volver al Menú de Servicios Corporativos")

        choice = input("\nSeleccione opción [1-3]: ").strip()
        if choice == "1":
            # Listar correos recibidos
            res = client.list_emails()
            if res.get("status") != 200:
                print(f"[!] Error al recuperar bandeja de entrada: {res.get('error')}")
                continue

            emails = res.get("emails", [])
            unread_cnt = res.get("unread_count", 0)
            print(f"\n--- Bandeja de Entrada ({len(emails)} mensajes, {unread_cnt} sin leer) ---")
            if not emails:
                print("  (No hay correos en su buzón)")
                continue

            print(f" {'ID':<4} | {'ESTADO':<8} | {'DE':<20} | {'ASUNTO':<35} | {'FECHA'}")
            print("-" * 85)
            for em in emails:
                status_str = "[NUEVO]" if not em.get("is_read") else "[LEÍDO]"
                ts = em.get("timestamp", 0)
                date_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "N/A"
                print(f" {em['id']:<4} | {status_str:<8} | {em['sender']:<20} | {em['subject'][:33]:<35} | {date_str}")

            email_id_str = input("\nIngrese el ID (#) del correo que desea leer (o '0' para volver): ").strip()
            if email_id_str and email_id_str != "0":
                try:
                    eid = int(email_id_str)
                    read_res = client.read_email(eid)
                    if read_res.get("status") != 200:
                        print(f"[!] Error: {read_res.get('error')}")
                    else:
                        e = read_res.get("email", {})
                        ts = e.get("timestamp", 0)
                        date_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"
                        print("\n" + "=" * 70)
                        print(f" ASUNTO:  {e.get('subject')}")
                        print(f" DE:      {e.get('sender')}")
                        print(f" PARA:    {e.get('recipient')}")
                        print(f" FECHA:   {date_str}")
                        print("-" * 70)
                        print(e.get("body", ""))
                        print("=" * 70)
                        input("\nPresione [Enter] para continuar...")
                except ValueError:
                    print("[!] Por favor ingrese un número de ID válido.")

        elif choice == "2":
            # Redactar nuevo correo
            print("\n--- REDACTAR NUEVO CORREO INSTITUCIONAL ---")
            dest = input("Destinatario (username o email, ej: manuel_ptgas): ").strip()
            if not dest:
                print("[!] El destinatario no puede estar vacío.")
                continue

            subj = input("Asunto: ").strip()
            if not subj:
                print("[!] El asunto no puede estar vacío.")
                continue

            print("Cuerpo del mensaje (escriba el texto y presione Enter):")
            body = input("> ").strip()
            if not body:
                print("[!] El mensaje no puede estar vacío.")
                continue

            send_res = client.send_email(dest, subj, body)
            if send_res.get("status") == 200:
                print(f"\n[OK] {send_res.get('message')} (ID de mensaje: {send_res.get('email_id')})")
            else:
                print(f"\n[!] Error al enviar correo: {send_res.get('error')}")

        elif choice == "3":
            break
        else:
            print("[!] Opción no válida.")


def register_new_user_cli() -> Optional[str]:
    """
    Qué hace:
        Gestiona el registro de un nuevo usuario corporativo y emite su certificado digital BYOD X.509 v3.
    Cuál es su función:
        Vincular el alta de usuario y contraseña con la generación criptográfica de claves RSA y certificado mTLS.
    Cómo lo hace:
        Solicita datos por terminal, genera par de claves con la Root CA y registra la identidad en SQLite.
    """
    print("\n" + "=" * 70)
    print(" REGISTRO DE NUEVO USUARIO Y EMISIÓN DE CERTIFICADO BYOD (X.509 v3)")
    print("=" * 70)

    username = input("Introduzca nombre de usuario (ej: nuevo_docente): ").strip()
    if not username:
        print("[!] El nombre de usuario no puede estar vacío.")
        return None

    # Solicitud segura de contraseña con confirmación
    password = getpass.getpass("Introduzca contraseña corporativa: ")
    if len(password) < 8:
        print("[!] Por seguridad, la contraseña debe contener al menos 8 caracteres.")
        return None

    password_confirm = getpass.getpass("Confirme la contraseña corporativa: ")
    if password != password_confirm:
        print("[!] Las contraseñas no coinciden.")
        return None

    # Selección de rol universitario
    print("\nSeleccione Rol Institucional:")
    print("  [1] PDI (Personal Docente e Investigador)")
    print("  [2] PTGAS (Personal Técnico de Gestión y Administración)")
    print("  [3] Investigador")
    role_choice = input("Opción [1-3] (por defecto 1): ").strip() or "1"
    role_map = {"1": "PDI", "2": "PTGAS", "3": "Investigador"}
    role = role_map.get(role_choice, "PDI")

    full_name = input("Nombre completo del titular: ").strip() or f"Usuario {username}"
    email_default = f"{username}@usecure.edu.es"
    email = input(f"Correo institucional [{email_default}]: ").strip() or email_default

    print(f"\n[*] Solicitando y emitiendo certificado digital X.509 v3 para '{username}'...")
    try:
        # Generamos la clave privada RSA 2048 y el certificado cliente firmado por la Root CA
        cert_path, key_path = issue_client_certificate_for_user(username, role=role, email=email)
        print(f"[OK] Certificado digital generado: {os.path.basename(cert_path)}")
        print(f"[OK] Clave privada RSA 2048 guardada: {os.path.basename(key_path)}")

        # Registramos al usuario en el directorio corporativo
        reg_ok = register_user(
            username=username,
            password=password,
            role=role,
            full_name=full_name,
            email=email,
            cert_cn=username
        )

        if not reg_ok:
            print(f"[!] El usuario '{username}' ya se encontraba registrado en la base de datos.")
        else:
            print(f"[OK] Usuario '{username}' registrado exitosamente en el directorio de U-Secure.")

        return username
    except Exception as e:
        print(f"[!] Error durante el proceso de registro/emisión: {e}")
        return None


def login_user_cli(username: Optional[str] = None) -> None:
    """
    Qué hace:
        Solicita el nombre de usuario, localiza su certificado BYOD, establece túnel TLS 1.3 y autentica.
    Cuál es su función:
        Cumplir el requerimiento de introducir manualmente el nombre de usuario y verificar su certificado.
    Cómo lo hace:
        Valida la existencia física de client_{username}.crt/.key, establece mTLS y solicita contraseña con getpass.
    """
    if not username:
        username = input("\nIngrese su nombre de usuario corporativo: ").strip()
    if not username:
        print("[!] Nombre de usuario no válido.")
        return

    safe_name = username.replace("@", "_").replace(".", "_")
    cert_path = os.path.join(CERTS_DIR, f"client_{safe_name}.crt")
    key_path = os.path.join(CERTS_DIR, f"client_{safe_name}.key")

    # Si no existe el certificado para este usuario, ofrecemos emitirlo
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"\n[!] No se encontró certificado digital local ('client_{safe_name}.crt') para el usuario '{username}'.")
        print("    Para acceder a la VPN TLS 1.3 con mTLS, el dispositivo debe disponer de un certificado emitido por la U-Secure Root CA.")
        emit_opt = input("    ¿Desea emitir y solicitar el certificado para este usuario ahora? (s/n): ").strip().lower()
        if emit_opt == "s":
            created_user = register_new_user_cli()
            if created_user:
                username = created_user
                safe_name = username.replace("@", "_").replace(".", "_")
                cert_path = os.path.join(CERTS_DIR, f"client_{safe_name}.crt")
                key_path = os.path.join(CERTS_DIR, f"client_{safe_name}.key")
            else:
                return
        else:
            return

    print(f"\n[*] Iniciando cliente con credenciales criptográficas BYOD:")
    print(f"     Certificado: {os.path.basename(cert_path)}")
    print(f"     Clave:       {os.path.basename(key_path)}")

    client = VpnClient(cert_path=cert_path, key_path=key_path)

    print("[*] Estableciendo canal seguro TLS 1.3 con autenticación mutua (mTLS)...")
    if not client.connect():
        print("[!] No se pudo establecer la conexión TLS 1.3 con el gateway VPN.")
        return

    print(f"[OK] Túnel TLS 1.3 cifrado establecido con éxito.")
    print(f"     Protocolo: {client.ssl_sock.version()} | Suite Criptográfica: {client.ssl_sock.cipher()[0]}")

    # Solicitud de contraseña corporativa de forma oculta
    password = getpass.getpass(f"\nIngrese contraseña corporativa para '{username}': ")
    print("[*] Autenticando en Capa de Aplicación (Doble Factor RF2)...")
    login_res = client.login(username, password)

    if login_res.get("status") != 200:
        print(f"[!] Autenticación fallida: {login_res.get('error')}")
        client.close()
        return

    print(f"[OK] {login_res.get('message')}")
    print(f"     IP Virtual Asignada: {login_res.get('virtual_ip')}")
    print(f"     Rol Corporativo:     {login_res.get('role')}")
    print(f"     Session ID:          {login_res.get('session_id')}")

    # Menú de recursos de la intranet corporativa
    while True:
        print("\n--- Recursos Corporativos de U-Secure Disponibles ---")
        print("  [1] Correo Institucional Webmail (Bandeja y Envío)")
        print("  [2] Campus Virtual y Docencia")
        print("  [3] Gestión Administrativa y Nóminas (PTGAS)")
        print("  [4] Repositorio Científico y Clúster HPC (Investigación/PDI)")
        print("  [5] Comprobar Latencia del Túnel (PING)")
        print("  [6] Desconectar Túnel VPN y Salir (RF4)")

        sub_choice = input("\nSeleccione acción [1-6]: ").strip()
        if sub_choice == "1":
            handle_webmail_cli(client, username)
        elif sub_choice == "2":
            res = client.access_service("CAMPUS_VIRTUAL")
            print(f"\n[RESPUESTA] {json.dumps(res, indent=2, ensure_ascii=False)}")
        elif sub_choice == "3":
            res = client.access_service("SISTEMAS_ADMINISTRATIVOS")
            print(f"\n[RESPUESTA] {json.dumps(res, indent=2, ensure_ascii=False)}")
        elif sub_choice == "4":
            res = client.access_service("INVESTIGACION_DB")
            print(f"\n[RESPUESTA] {json.dumps(res, indent=2, ensure_ascii=False)}")
        elif sub_choice == "5":
            t0 = time.time()
            res = client.ping()
            rtt_ms = (time.time() - t0) * 1000
            print(f"\n[PING-PONG] RTT: {rtt_ms:.2f} ms | Servidor: {res.get('message')}")
        elif sub_choice == "6":
            print("\n[*] Solicitando desmontaje seguro del túnel (RF4)...")
            res = client.disconnect()
            print(f"[OK] {res.get('message')}")
            break
        else:
            print("[!] Opción no reconocida.")


def interactive_cli():
    """
    Qué hace:
        Proporciona el menú interactivo principal para usuarios de la comunidad universitaria.
    Cuál es su función:
        Permitir el acceso mediante introducción manual de usuario, o el registro de nuevos usuarios con emisión PKI.
    Cómo lo hace:
        Muestra menú en consola, bifurca entre login manual o registro, y coordina las llamadas correspondientes.
    """
    print("=" * 70)
    print(" CLIENTE ROAD WARRIOR VPN SSL/TLS 1.3 - UNIVERSIDAD PÚBLICA U-SECURE")
    print("=" * 70)

    while True:
        print("\nOpciones de Acceso:")
        print("  [1] Iniciar Sesión en la VPN (Introducir nombre de usuario)")
        print("  [2] Registrar Nuevo Usuario y Solicitar Certificado BYOD")
        print("  [3] Salir")

        opt = input("\nSeleccione opción [1-3] (por defecto 1): ").strip() or "1"
        if opt == "1":
            login_user_cli()
        elif opt == "2":
            new_u = register_new_user_cli()
            if new_u:
                connect_now = input(f"\n¿Desea iniciar sesión ahora como '{new_u}'? (s/n): ").strip().lower()
                if connect_now == "s":
                    login_user_cli(new_u)
        elif opt == "3":
            print("\nCerrando cliente VPN U-Secure. ¡Hasta pronto!")
            break
        else:
            print("[!] Opción no válida.")


if __name__ == "__main__":
    interactive_cli()
