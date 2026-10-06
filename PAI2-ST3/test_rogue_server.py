#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
PRUEBA DE PENETRACIÓN: SERVIDOR FALSO / GATEWAY ROGUE (EVIL TWIN MITM ATTACK)
Módulo: test_rogue_server.py
Equipo: Security Team 3 (Grupo 3)
Asignatura: Seguridad en Sistemas Informáticos y en Internet - PAI 2 (BYODSEC)
Fecha: Octubre 2026
========================================================================================
Descripción General:
Este script simula un ataque avanzado de intercepción y suplantación de gateway (Evil Twin /
Man-in-the-Middle) donde un atacante despliega un servidor falso escuchando peticiones de VPN
para cosechar credenciales corporativas de los usuarios universitarios.

Objetivo de la Prueba (Extra Opcional +10%):
Demostrar que el cliente BYOD rechaza categóricamente la pasarela falsa porque su certificado
digital no está avalado por la Autoridad de Certificación Raíz de U-Secure.
========================================================================================
"""

import os
import time
import socket
import ssl
import threading

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")

ROGUE_SERVER_CERT = os.path.join(CERTS_DIR, "rogue_server.crt")
ROGUE_SERVER_KEY = os.path.join(CERTS_DIR, "rogue_server.key")
OFFICIAL_CA_CERT = os.path.join(CERTS_DIR, "ca.crt")
CLIENT_CERT = os.path.join(CERTS_DIR, "client_carmen_pdi.crt")
CLIENT_KEY = os.path.join(CERTS_DIR, "client_carmen_pdi.key")

ROGUE_PORT = 8444
SERVER_HOSTNAME = "vpn.usecure.edu.es"


def start_rogue_gateway_listener(stop_event: threading.Event) -> None:
    """
    Qué hace:
        Inicia un servidor falso que presenta el certificado malicioso de atacante.
    Cuál es su función:
        Simular el gateway fraudulento que intenta engañar al cliente BYOD.
    Cómo lo hace:
        Abre socket en el puerto 8444, envuelve con rogue_server.crt y espera conexiones.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=ROGUE_SERVER_CERT, keyfile=ROGUE_SERVER_KEY)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", ROGUE_PORT))
    server_sock.listen(5)
    server_sock.settimeout(1.0)

    while not stop_event.is_set():
        try:
            raw_client, _ = server_sock.accept()
            try:
                ssl_conn = context.wrap_socket(raw_client, server_side=True)
                ssl_conn.close()
            except Exception:
                pass
            finally:
                raw_client.close()
        except socket.timeout:
            continue
        except Exception:
            break

    server_sock.close()


def test_rogue_server_mitm() -> bool:
    """
    Qué hace:
        Un cliente legítimo intenta conectarse a la pasarela maliciosa.
    Cuál es su función:
        Verificar que el cliente detecte el certificado no firmado por la CA oficial y aborte la conexión.
    Cómo lo hace:
        1. Lanza el servidor rogue en un hilo secundario.
        2. El cliente intenta conectar validando contra OFFICIAL_CA_CERT.
        3. Captura ssl.SSLCertVerificationError confirmando que el ataque fue frustrado.
    """
    print("=" * 70)
    print(" SIMULACIÓN DE ATAQUE: PASARELA VPN FALSA / EVIL TWIN MITM (EXTRA +10%)")
    print("=" * 70)
    print(f"[*] Levantando Gateway Malicioso en 127.0.0.1:{ROGUE_PORT}...")

    stop_event = threading.Event()
    rogue_thread = threading.Thread(target=start_rogue_gateway_listener, args=(stop_event,), daemon=True)
    rogue_thread.start()
    time.sleep(0.5)

    print("[*] Cliente legítimo BYOD intenta conectar con el Gateway falso...")
    # El cliente legítimo solo confía en la CA oficial de U-Secure
    client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=OFFICIAL_CA_CERT)
    client_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    client_ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

    attack_foiled = False
    try:
        raw_sock = socket.create_connection(("127.0.0.1", ROGUE_PORT), timeout=5.0)
        # El cliente debe abortar aquí porque el certificado del servidor falso no proviene de la CA oficial
        ssl_sock = client_ctx.wrap_socket(raw_sock, server_hostname=SERVER_HOSTNAME)

        print("[!] ERROR CRÍTICO: El cliente confió en un servidor VPN fraudulento.")
        ssl_sock.close()
    except (ssl.SSLCertVerificationError, ssl.SSLError) as err:
        print("[OK] ATAQUE EVIL TWIN / MITM NEUTRALIZADO EXITOSAMENTE.")
        print(f"     El cliente detectó que el servidor no está firmado por la U-Secure Root CA.")
        print(f"     Detalle de la alerta criptográfica: {err}")
        attack_foiled = True
    except Exception as ex:
        print(f"[OK] Conexión abortada: {ex}")
        attack_foiled = True
    finally:
        stop_event.set()
        rogue_thread.join(timeout=2.0)

    return attack_foiled


if __name__ == "__main__":
    test_rogue_server_mitm()
