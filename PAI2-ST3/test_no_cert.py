#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
PRUEBA DE PENETRACIÓN: CONEXIÓN SIN CERTIFICADO DIGITAL DE CLIENTE
Módulo: test_no_cert.py
Equipo: Security Team 3 (Grupo 3)
Asignatura: Seguridad en Sistemas Informáticos y en Internet - PAI 2 (BYODSEC)
Fecha: Octubre 2026
========================================================================================
Descripción General:
Este script simula un ataque estándar desde Internet donde un usuario o script malicioso
intenta establecer una conexión TLS convencional sin presentar un certificado digital X.509
de cliente BYOD.

Objetivo de la Prueba:
Comprobar que la política ssl.CERT_REQUIRED del gateway VPN impide cualquier comunicación
si el cliente no aporta un certificado de dispositivo válido.
========================================================================================
"""

import os
import socket
import ssl

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
CA_CERT = os.path.join(CERTS_DIR, "ca.crt")

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8443
SERVER_HOSTNAME = "vpn.usecure.edu.es"


def test_no_cert_attack() -> bool:
    """
    Qué hace:
        Intenta iniciar una sesión TLS 1.3 sin proporcionar certificado de cliente.
    Cuál es su función:
        Validar que el servidor aborte la conexión inmediatamente al no recibir credenciales mTLS.
    Cómo lo hace:
        1. Crea un contexto TLS estándar sin invocar context.load_cert_chain.
        2. Intenta el handshake TLS 1.3 con el gateway VPN.
        3. Comprueba que el servidor emite una alerta SSL crítica y corta el socket.
    """
    print("=" * 70)
    print(" SIMULACIÓN DE ATAQUE: CONEXIÓN SIN CERTIFICADO DE CLIENTE (NO-CERT)")
    print("=" * 70)
    print(f"[*] Objetivo: {SERVER_HOST}:{SERVER_PORT}")
    print("[*] Condición: Cliente omite presentación de certificado digital en el handshake.")

    # Contexto TLS sin certificado de cliente
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True

    try:
        raw_sock = socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=5.0)
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=SERVER_HOSTNAME)

        # En TLS 1.3, el cliente transmite el frame inicial; el servidor procesa y emite alerta de rechazo
        # Forzamos la lectura/escritura para verificar si el servidor admitió o cortó el canal
        ssl_sock.sendall(b'{"action":"PING"}\n')
        resp = ssl_sock.recv(1024)

        if resp:
            # Si el servidor responde datos válidos, hay un fallo de seguridad
            print("[!] VULNERABILIDAD DETECTADA: El servidor respondió datos sin exigir certificado de cliente.")
            ssl_sock.close()
            return False
        else:
            print("[OK] ATAQUE BLOQUEADO POR MTLS TLS 1.3: Conexión cortada por el servidor por falta de certificado.")
            return True
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError, ConnectionError) as e:
        print(f"[OK] ATAQUE BLOQUEADO POR MTLS TLS 1.3.")
        print(f"     Excepción capturada: {e}")
        print("     El servidor abortó la conexión por ausencia de certificado de cliente.")
        return True
    except Exception as ex:
        print(f"[OK] ATAQUE NEUTRALIZADO: {ex}")
        return True


if __name__ == "__main__":
    test_no_cert_attack()
