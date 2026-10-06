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
from typing import Optional, Dict, Any

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


def interactive_cli():
    """
    Qué hace:
        Proporciona un menú de consola interactivo e intuitivo para usuarios de la comunidad universitaria.
    Cuál es su función:
        Permitir al usuario final seleccionar su perfil BYOD, conectarse, consultar servicios y desconectarse.
    Cómo lo hace:
        Muestra opciones visuales en terminal, solicita contraseñas mediante getpass y ejecuta métodos de VpnClient.
    """
    print("=" * 70)
    print(" CLIENTE ROAD WARRIOR VPN SSL/TLS 1.3 - UNIVERSIDAD PÚBLICA U-SECURE")
    print("=" * 70)

    # Menú de perfiles preconfigurados (RF5)
    profiles = {
        "1": {"user": "carmen_pdi", "name": "Carmen Sánchez (PDI)", "cert": "client_carmen_pdi.crt", "key": "client_carmen_pdi.key"},
        "2": {"user": "manuel_ptgas", "name": "Manuel Rodríguez (PTGAS)", "cert": "client_manuel_ptgas.crt", "key": "client_manuel_ptgas.key"},
        "3": {"user": "lucia_inv", "name": "Lucía Morales (Investigador)", "cert": "client_lucia_inv.crt", "key": "client_lucia_inv.key"},
        "4": {"user": "eval_user", "name": "Auditor Security Team 3", "cert": "client_eval_user.crt", "key": "client_eval_user.key"}
    }

    print("\nSeleccione el Perfil de Usuario Corporativo BYOD:")
    for k, v in profiles.items():
        print(f"  [{k}] {v['name']} ({v['user']})")

    choice = input("\nIngrese opción [1-4] (por defecto 1): ").strip() or "1"
    selected = profiles.get(choice, profiles["1"])

    cert_path = os.path.join(CERTS_DIR, selected["cert"])
    key_path = os.path.join(CERTS_DIR, selected["key"])

    print(f"\n[*] Iniciando cliente con certificado BYOD: {selected['cert']}")
    client = VpnClient(cert_path=cert_path, key_path=key_path)

    print("[*] Estableciendo canal seguro TLS 1.3 con autenticación mutua (mTLS)...")
    if not client.connect():
        print("[!] No se pudo establecer la conexión TLS 1.3 con el gateway VPN.")
        sys.exit(1)

    print(f"[OK] Túnel TLS 1.3 cifrado establecido con éxito.")
    print(f"     Protocolo: {client.ssl_sock.version()} | Suite Criptográfica: {client.ssl_sock.cipher()[0]}")

    # Solicitud de contraseña corporativa de forma oculta
    password = getpass.getpass(f"\nIngrese contraseña corporativa para '{selected['user']}': ")
    print("[*] Autenticando en Capa de Aplicación (Doble Factor RF2)...")
    login_res = client.login(selected["user"], password)

    if login_res.get("status") != 200:
        print(f"[!] Autenticación fallida: {login_res.get('error')}")
        client.close()
        sys.exit(1)

    print(f"[OK] {login_res.get('message')}")
    print(f"     IP Virtual Asignada: {login_res.get('virtual_ip')}")
    print(f"     Rol Corporativo:     {login_res.get('role')}")
    print(f"     Session ID:          {login_res.get('session_id')}")

    # Menú de recursos de la intranet
    while True:
        print("\n--- Recursos Corporativos de U-Secure Disponibles ---")
        print("  [1] Correo Institucional Webmail")
        print("  [2] Campus Virtual y Docencia")
        print("  [3] Gestión Administrativa y Nóminas (PTGAS)")
        print("  [4] Repositorio Científico y Clúster HPC (Investigación/PDI)")
        print("  [5] Comprobar Latencia del Túnel (PING)")
        print("  [6] Desconectar Túnel VPN y Salir (RF4)")

        sub_choice = input("\nSeleccione acción [1-6]: ").strip()
        if sub_choice == "1":
            res = client.access_service("CORREO_CORPORATIVO")
            print(f"\n[RESPUESTA] {json.dumps(res, indent=2, ensure_ascii=False)}")
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


if __name__ == "__main__":
    interactive_cli()
