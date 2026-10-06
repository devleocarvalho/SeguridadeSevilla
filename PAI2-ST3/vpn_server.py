#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
PASARELA DE ACCESO REMOTO ROAD WARRIOR VPN SSL/TLS 1.3 - UNIVERSIDAD U-SECURE
Módulo: vpn_server.py
Equipo: Security Team 3 (Grupo 3)
Asignatura: Seguridad en Sistemas Informáticos y en Internet - PAI 2 (BYODSEC)
Fecha: Octubre 2026
========================================================================================
Descripción General:
Este módulo implementa el servidor central de la pasarela VPN Road Warrior con soporte
estricto para el protocolo TLS 1.3 y autenticación mutua obligatoria (mTLS). Proporciona
acceso controlado a los recursos corporativos e intranet de la Universidad Pública U-Secure
para dispositivos BYOD autorizados.

Requisitos Técnicos y de Seguridad Satisfechos:
1. Protocolo TLS 1.3 Estricto (RS2): Exclusión total de SSLv3, TLS 1.0, TLS 1.1 y TLS 1.2.
2. Autenticación Mutua Bidireccional (mTLS - RS1): Exigencia de certificado digital X.509
   emitido por la Root CA institucional antes de aceptar cualquier intercambio de datos.
3. Doble Capa de Autenticación (RF2): Validación combinada del certificado de dispositivo
   (Capa de Transporte) y credenciales de usuario PBKDF2 (Capa de Aplicación).
4. Control de Acceso Basado en Roles (RBAC): Filtrado de acceso a servicios según rol
   (PDI, PTGAS, Investigador).
5. Desmontaje Seguro del Túnel (RF4): Cierre explícito de sesión y destrucción de claves PFS.
6. Arquitectura de Alta Concurrencia (RS3): Capacidad para atender hasta 300 sesiones simultáneas.
7. Trazabilidad y Registro de Auditoría (RS4): Generación continua de logs estructurados.
========================================================================================
"""

import os
import sys
import json
import time
import socket
import ssl
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple, Dict, Any, Optional

# Importamos el módulo de base de datos local para validación y persistencia
from database import (
    authenticate_user,
    create_vpn_session,
    destroy_vpn_session,
    log_audit_event,
    get_db_connection
)

# Definición de rutas base de certificados y configuración del servidor
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

CA_CERT_PATH = os.path.join(CERTS_DIR, "ca.crt")
SERVER_CERT_PATH = os.path.join(CERTS_DIR, "server.crt")
SERVER_KEY_PATH = os.path.join(CERTS_DIR, "server.key")
SERVER_LOG_PATH = os.path.join(LOGS_DIR, "server.log")

# Parámetros de red de la pasarela VPN
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8443
MAX_CONCURRENT_WORKERS = 350  # Soporte holgado para el requerimiento de 300 usuarios (RS3)

# Aseguramos el directorio de logs
os.makedirs(LOGS_DIR, exist_ok=True)

# Configuración del sistema de logging centralizado
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
    handlers=[
        logging.FileHandler(SERVER_LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("VPN_GATEWAY")

# Simulación de recursos internos de la intranet de la Universidad U-Secure
INTERNAL_SERVICES = {
    "CORREO_CORPORATIVO": {
        "name": "Buzón Institucional Webmail (U-Secure)",
        "allowed_roles": ["PDI", "PTGAS", "Investigador", "Auditor"],
        "data": "Bienvenido al correo corporativo: 4 mensajes no leídos sobre convocatorias I+D."
    },
    "CAMPUS_VIRTUAL": {
        "name": "Plataforma de Docencia Virtual y Calificaciones",
        "allowed_roles": ["PDI", "PTGAS", "Investigador", "Auditor"],
        "data": "Acceso a asignaturas activas: Criptografía y Seguridad en Redes (2026/2027)."
    },
    "SISTEMAS_ADMINISTRATIVOS": {
        "name": "Gestión de Personal, Nóminas y Presupuestos (PTGAS)",
        "allowed_roles": ["PTGAS", "Auditor"],
        "data": "Sistema ERP Central: Expediente administrativo y autorizaciones de compras autorizado."
    },
    "INVESTIGACION_DB": {
        "name": "Repositorio Científico y Clúster de Computación de Alta Capacidad",
        "allowed_roles": ["PDI", "Investigador", "Auditor"],
        "data": "Clúster HPC: Acceso concedido al repositorio de datasets confidenciales de criptoanálisis."
    }
}


def build_tls13_server_context() -> ssl.SSLContext:
    """
    Qué hace:
        Construye y configura el contexto criptográfico SSL/TLS del servidor imponiendo TLS 1.3 y mTLS.
    Cuál es su función:
        Blindar el canal de comunicaciones garantizando autenticación mutua, secreto perfecto hacia adelante (PFS)
        y cifrado autenticado de datos (AEAD), satisfaciendo los requisitos de seguridad RS1 y RS2.
    Cómo lo hace:
        1. Instancia ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).
        2. Configura minimum_version y maximum_version en ssl.TLSVersion.TLSv1_3 para vetar TLS 1.2 y anteriores.
        3. Configura verify_mode en ssl.CERT_REQUIRED para exigir certificado digital X.509 al cliente.
        4. Carga el certificado de la CA corporativa U-Secure como emisor confiable con load_verify_locations.
        5. Carga el certificado del servidor y su clave privada RSA con load_cert_chain.
    """
    logger.info("[*] Configurando contexto de seguridad TLS 1.3 con Autenticación Mutua (mTLS)...")

    # Creamos el contexto para rol de servidor TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Restringimos estrictamente la versión del protocolo a TLS 1.3 (RS2)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    # Exigimos obligatoriamente certificado de cliente válido (mTLS - RS1)
    context.verify_mode = ssl.CERT_REQUIRED

    # Cargamos el certificado raíz de la CA corporativa para validar clientes BYOD
    if not os.path.exists(CA_CERT_PATH):
        raise FileNotFoundError(f"No se encuentra el certificado de la CA: {CA_CERT_PATH}")
    context.load_verify_locations(cafile=CA_CERT_PATH)

    # Cargamos la cadena de certificados del servidor VPN y su clave privada
    if not os.path.exists(SERVER_CERT_PATH) or not os.path.exists(SERVER_KEY_PATH):
        raise FileNotFoundError("Faltan las credenciales criptográficas del servidor VPN.")
    context.load_cert_chain(certfile=SERVER_CERT_PATH, keyfile=SERVER_KEY_PATH)

    logger.info("[+] Protocolo restringido a TLSv1.3 exclusivamente. Suites AEAD y PFS activadas.")
    logger.info("[+] Modo mTLS configurado: Todo cliente BYOD debe presentar certificado firmado por U-Secure Root CA.")
    return context


def extract_client_common_name(peercert: Dict[str, Any]) -> Optional[str]:
    """
    Qué hace:
        Extrae el campo Common Name (CN) de la estructura del certificado X.509 presentado por el cliente.
    Cuál es su función:
        Identificar la identidad criptográfica del dispositivo BYOD para la verificación en dos capas (RF1, RF2).
    Cómo lo hace:
        Recorre el campo 'subject' del diccionario devuelto por sslsocket.getpeercert() buscando 'commonName'.
    """
    if not peercert or "subject" not in peercert:
        return None

    # El sujeto viene en formato tupla de tuplas de atributos RDN
    for rdn in peercert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def handle_client_connection(raw_client_sock: socket.socket, client_addr: Tuple[str, int], ssl_context: ssl.SSLContext) -> None:
    """
    Qué hace:
        Atiende el ciclo de vida completo de una conexión de cliente en un hilo independiente (RS3).
    Cuál es su función:
        Ejecutar el handshake TLS 1.3 con mTLS, verificar certificados, procesar solicitudes JSON,
        gestionar la autenticación en dos capas, dar acceso a servicios y realizar el desmontaje seguro.
    Cómo lo hace:
        1. Envuelve el socket TCP con ssl_context.wrap_socket en modo servidor.
        2. Si el handshake falla (cliente sin certificado o no confiable), registra alerta y cierra conexión.
        3. Si el handshake triunfa, entra en un bucle interactivo de tramas JSON delimitadas por salto de línea.
        4. Procesa acciones: LOGIN, ACCESS_SERVICE, PING, DISCONNECT.
        5. Libera recursos y cierra sockets de manera limpia y segura.
    """
    client_ip, client_port = client_addr
    ssl_sock = None
    session_info = None

    try:
        # Envolvemos el socket en TLS 1.3 con mTLS obligatorio
        ssl_sock = ssl_context.wrap_socket(raw_client_sock, server_side=True)

        # Inspeccionamos la suite criptográfica y la versión negociada
        tls_version = ssl_sock.version()
        tls_cipher = ssl_sock.cipher()[0]
        logger.info(f"[+] Conexión segura establecida con {client_ip}:{client_port} | Protocolo: {tls_version} | Cipher: {tls_cipher}")

        # Obtenemos y verificamos el certificado digital de cliente presentado
        peercert = ssl_sock.getpeercert()
        cert_cn = extract_client_common_name(peercert)

        if not cert_cn:
            logger.warning(f"[!] Rechazo: Cliente {client_ip} no contiene Common Name válido en su certificado X.509.")
            ssl_sock.sendall(json.dumps({"status": 403, "error": "Certificado de cliente sin CN válido."}).encode("utf-8") + b"\n")
            return

        logger.info(f"[+] Certificado digital X.509 validado para identidad BYOD: '{cert_cn}'")
        log_audit_event("MTLS_HANDSHAKE_SUCCESS", "INFO", cert_cn, client_ip,
                        f"Handshake mTLS TLS 1.3 completado. Cipher: {tls_cipher}")

        # Bucle de recepción de comandos dentro del túnel cifrado
        buffer = ""
        while True:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                # El cliente cerró la conexión TCP
                break

            buffer += chunk.decode("utf-8")
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue

                try:
                    request = json.loads(line)
                except json.JSONDecodeError:
                    ssl_sock.sendall(json.dumps({"status": 400, "error": "Formato JSON inválido"}).encode("utf-8") + b"\n")
                    continue

                action = request.get("action", "").upper()

                # -------------------------------------------------------------
                # 1. ACCIÓN: LOGIN (Autenticación en Dos Capas - RF2)
                # -------------------------------------------------------------
                if action == "LOGIN":
                    username = request.get("username", "")
                    password = request.get("password", "")

                    # Verificamos credenciales y correspondencia con el certificado digital
                    is_auth, msg, user_data = authenticate_user(username, password, cert_cn)

                    if not is_auth:
                        logger.warning(f"[!] Autenticación denegada para usuario '{username}' desde {client_ip}: {msg}")
                        response = {"status": 401, "authenticated": False, "error": msg}
                        ssl_sock.sendall(json.dumps(response).encode("utf-8") + b"\n")
                        continue

                    # Credenciales correctas: Creamos sesión VPN y asignamos IP virtual
                    session_info = create_vpn_session(username, client_ip, tls_cipher)
                    if not session_info:
                        response = {"status": 503, "error": "Pool de direcciones IP virtuales agotado."}
                        ssl_sock.sendall(json.dumps(response).encode("utf-8") + b"\n")
                        continue

                    logger.info(f"[OK] Sesión VPN iniciada: Usuario '{username}' ({user_data['role']}) -> IP Virtual: {session_info['virtual_ip']}")
                    response = {
                        "status": 200,
                        "authenticated": True,
                        "message": "Autenticación en dos capas superada. Túnel VPN TLS 1.3 activo.",
                        "session_id": session_info["session_id"],
                        "virtual_ip": session_info["virtual_ip"],
                        "role": user_data["role"],
                        "user_info": {
                            "username": user_data["username"],
                            "full_name": user_data["full_name"],
                            "email": user_data["email"],
                            "role": user_data["role"]
                        }
                    }
                    ssl_sock.sendall(json.dumps(response).encode("utf-8") + b"\n")

                # -------------------------------------------------------------
                # 2. ACCIÓN: ACCESS_SERVICE (Acceso a Recursos Internos con RBAC)
                # -------------------------------------------------------------
                elif action == "ACCESS_SERVICE":
                    if not session_info:
                        response = {"status": 401, "error": "Debe autenticarse en el túnel VPN antes de solicitar servicios."}
                        ssl_sock.sendall(json.dumps(response).encode("utf-8") + b"\n")
                        continue

                    service_key = request.get("service", "").upper()
                    if service_key not in INTERNAL_SERVICES:
                        response = {"status": 404, "error": f"Servicio '{service_key}' no encontrado en la intranet de U-Secure."}
                        ssl_sock.sendall(json.dumps(response).encode("utf-8") + b"\n")
                        continue

                    service_meta = INTERNAL_SERVICES[service_key]
                    user_role = session_info.get("role", user_data["role"])

                    # Control de acceso basado en roles (RBAC)
                    if user_role not in service_meta["allowed_roles"]:
                        logger.warning(f"[!] Acceso denegado: Usuario '{session_info['username']}' con rol '{user_role}' intentó acceder a '{service_key}'")
                        log_audit_event("RBAC_ACCESS_DENIED", "WARNING", session_info["username"], client_ip,
                                        f"Intento no autorizado al recurso {service_key}")
                        response = {
                            "status": 403,
                            "error": f"Acceso restringido: El rol '{user_role}' no tiene privilegios para acceder al servicio '{service_key}'."
                        }
                        ssl_sock.sendall(json.dumps(response).encode("utf-8") + b"\n")
                        continue

                    logger.info(f"[+] Acceso autorizado a '{service_key}' para usuario '{session_info['username']}' ({user_role})")
                    log_audit_event("RESOURCE_ACCESS", "INFO", session_info["username"], client_ip,
                                    f"Acceso concedido al servicio {service_key}")
                    response = {
                        "status": 200,
                        "service": service_meta["name"],
                        "data": service_meta["data"],
                        "timestamp": time.time()
                    }
                    ssl_sock.sendall(json.dumps(response).encode("utf-8") + b"\n")

                # -------------------------------------------------------------
                # 3. ACCIÓN: PING (Verificación de Latencia y Keepalive en Túnel)
                # -------------------------------------------------------------
                elif action == "PING":
                    response = {"status": 200, "message": "PONG", "server_time": time.time()}
                    ssl_sock.sendall(json.dumps(response).encode("utf-8") + b"\n")

                # -------------------------------------------------------------
                # 4. ACCIÓN: DISCONNECT (Cierre Seguro y Desmontaje de Túnel - RF4)
                # -------------------------------------------------------------
                elif action == "DISCONNECT":
                    if session_info:
                        destroy_vpn_session(session_info["session_id"])
                        logger.info(f"[-] Desconexión solicitada por '{session_info['username']}'. Túnel desmontado de forma segura.")
                    response = {"status": 200, "message": "Túnel VPN finalizado. Claves de sesión efímeras destruidas."}
                    ssl_sock.sendall(json.dumps(response).encode("utf-8") + b"\n")
                    break

                else:
                    response = {"status": 400, "error": f"Acción desconocida: {action}"}
                    ssl_sock.sendall(json.dumps(response).encode("utf-8") + b"\n")

    except ssl.SSLError as ssl_err:
        # Errores en la capa TLS (fallo de handshake, certificado no confiable o no suministrado)
        logger.error(f"[!] Alerta de Seguridad TLS con cliente {client_ip}:{client_port}: {ssl_err}")
        log_audit_event("TLS_HANDSHAKE_FAILURE", "CRITICAL", None, client_ip, f"Fallo TLS: {str(ssl_err)}")
    except Exception as exc:
        logger.error(f"[!] Excepción en procesamiento de cliente {client_ip}:{client_port}: {exc}")
    finally:
        # Limpieza y cierre ordenado de sockets
        if session_info:
            destroy_vpn_session(session_info["session_id"])
        if ssl_sock:
            try:
                ssl_sock.close()
            except Exception:
                pass
        try:
            raw_client_sock.close()
        except Exception:
            pass


class VpnServer:
    """
    Qué hace:
        Gestiona el socket de escucha TCP principal y el despachador de hilos de la pasarela VPN.
    Cuál es su función:
        Escuchar peticiones entrantes en el puerto 8443, aplicar la capa TLS 1.3 con mTLS y
        despachar concurrentemente hasta 300 sesiones activas mediante un ThreadPoolExecutor.
    Cómo lo hace:
        1. Inicializa el contexto TLS 1.3 mediante build_tls13_server_context().
        2. Abre socket TCP en (SERVER_HOST, SERVER_PORT) con SO_REUSEADDR.
        3. En un bucle infinito, acepta conexiones y las envía a ThreadPoolExecutor.submit.
    """

    def __init__(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        self.host = host
        self.port = port
        self.ssl_context = build_tls13_server_context()
        self.server_sock = None
        self.running = False
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_WORKERS, thread_name_prefix="VPNClientWorker")

    def start(self) -> None:
        """
        Inicia el bucle de escucha del servidor VPN en modo continuo.
        """
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(500)
        self.running = True

        logger.info(f"==========================================================================")
        logger.info(f" PASARELA ROAD WARRIOR VPN TLS 1.3 (U-SECURE) ACTIVA EN {self.host}:{self.port}")
        logger.info(f" Capacidad de Concurrencia: {MAX_CONCURRENT_WORKERS} hilos simultáneos (RS3)")
        logger.info(f"==========================================================================")

        try:
            while self.running:
                raw_client, client_addr = self.server_sock.accept()
                # Delegamos la conexión al grupo de hilos para concurrencia masiva
                self.thread_pool.submit(handle_client_connection, raw_client, client_addr, self.ssl_context)
        except KeyboardInterrupt:
            logger.info("[*] Servidor detenido por interrupción de teclado.")
        except Exception as e:
            if self.running:
                logger.error(f"[!] Error fatal en bucle de escucha: {e}")
        finally:
            self.stop()

    def stop(self) -> None:
        """
        Detiene el servidor y finaliza los hilos de trabajo.
        """
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        self.thread_pool.shutdown(wait=False)
        logger.info("[+] Servidor VPN detenido y recursos liberados.")


if __name__ == "__main__":
    # Arrancamos el servidor VPN institucional
    server = VpnServer()
    server.start()
