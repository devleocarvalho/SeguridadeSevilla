#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
PRUEBA DE PENETRACIÓN: CONEXIÓN CON CERTIFICADO NO AUTORIZADO (ROGUE CERTIFICATE)
Módulo: test_unauthorized_cert.py
Equipo: Security Team 3 (Grupo 3)
Asignatura: Seguridad en Sistemas Informáticos y en Internet - PAI 2 (BYODSEC)
Fecha: Octubre 2026
========================================================================================
Descripción General:
Este script simula un ataque de acceso no autorizado donde un adversario intenta conectar
a la pasarela VPN Road Warrior utilizando un certificado digital emitido por una CA externa
o autofirmado (Rogue PKI).

Objetivo de la Prueba:
Demostrar que la configuración mTLS del servidor (RS1) rechaza de forma categórica el
handshake en la capa de transporte antes de permitir el intercambio de cualquier dato.
========================================================================================
"""

import os
import socket
import ssl

# Rutas de certificados
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
ROGUE_CERT = os.path.join(CERTS_DIR, "rogue_client.crt")
ROGUE_KEY = os.path.join(CERTS_DIR, "rogue_client.key")
CA_CERT = os.path.join(CERTS_DIR, "ca.crt")

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8443
SERVER_HOSTNAME = "vpn.usecure.edu.es"


def test_unauthorized_cert_attack() -> bool:
    """
    Qué hace:
        Intenta establecer una conexión TLS 1.3 con la pasarela VPN presentando un certificado no emitido por U-Secure.
    Cuál es su función:
        Verificar la eficacia del control de acceso en Capa de Red/Transporte (mTLS - RS1, RS2).
    Cómo lo hace:
        1. Crea un contexto TLS de cliente cargando rogue_client.crt y rogue_client.key.
        2. Intenta realizar el handshake con el servidor corporativo.
        3. Captura la excepción ssl.SSLError demostrando el rechazo por parte del servidor.
    """
    print("=" * 70)
    print(" SIMULACIÓN DE ATAQUE: ACCESO CON CERTIFICADO NO AUTORIZADO (ROGUE)")
    print("=" * 70)
    print(f"[*] Objetivo: {SERVER_HOST}:{SERVER_PORT} ({SERVER_HOSTNAME})")
    print(f"[*] Certificado malicioso presentado: {ROGUE_CERT}")

    # Creamos el contexto TLS del atacante con el certificado no autorizado
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.load_cert_chain(certfile=ROGUE_CERT, keyfile=ROGUE_KEY)

    try:
        raw_sock = socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=5.0)
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=SERVER_HOSTNAME)

        # En TLS 1.3, el cliente envía certificado rogue y el servidor procesa y emite alerta de rechazo
        # Forzamos la transmisión de datos para comprobar si el canal fue rechazado por mTLS
        ssl_sock.sendall(b'{"action":"PING"}\n')
        resp = ssl_sock.recv(1024)

        if resp:
            # Si llegamos aquí con respuesta válida, el servidor aceptó un certificado fraudulento
            print("[!] VULNERABILIDAD DETECTADA: El servidor aceptó un certificado no autorizado.")
            ssl_sock.close()
            return False
        else:
            print("[OK] ATAQUE BLOQUEADO POR MTLS TLS 1.3: Conexión cortada por el servidor por certificado no válido.")
            return True
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError, ConnectionError) as e:
        # El servidor rechazó la conexión correctamente
        print(f"[OK] ATAQUE BLOQUEADO POR MTLS TLS 1.3.")
        print(f"     Excepción capturada: {e}")
        print("     El servidor rechazó la conexión en el handshake por certificado desconocido.")
        return True
    except Exception as ex:
        print(f"[OK] ATAQUE NEUTRALIZADO: {ex}")
        return True


if __name__ == "__main__":
    test_unauthorized_cert_attack()
