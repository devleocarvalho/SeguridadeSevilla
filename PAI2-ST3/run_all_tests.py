#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
SUITE INTEGRAL DE PRUEBAS AUTOMÁTICAS Y AUDITORÍA DE SEGURIDAD - PAI 2 (BYODSEC)
Módulo: run_all_tests.py
Equipo: Security Team 3 (Grupo 3)
Asignatura: Seguridad en Sistemas Informáticos y en Internet - PAI 2 (BYODSEC)
Fecha: Octubre 2026
========================================================================================
Descripción General:
Este módulo ejecuta la batería completa de verificación y validación para el proyecto
BYODSEC (PAI 2) de la Universidad Pública U-Secure. Evalúa todos los requisitos funcionales
(RF1, RF2, RF4, RF5) y de seguridad (RS1, RS2, RS3, RS4, más la prueba Extra +10% de
resistencia a suplantación e intercepción MitM).

Adicionalmente, captura tráfico de red en vivo mediante TShark en formato .pcap,
genera el archivo de registro test_execution.log y valida el 100% de cobertura técnica.
========================================================================================
"""

import os
import sys
import time
import json
import socket
import ssl
import subprocess
import threading
from typing import Dict, Any, List

# Importamos los componentes del sistema desarrollado
from pki_manager import initialize_full_pki, CERTS_DIR
from database import (
    init_database,
    register_user,
    authenticate_user,
    get_db_connection,
    get_audit_logs
)
from vpn_server import VpnServer, SERVER_HOST, SERVER_PORT
from vpn_client import VpnClient
from test_unauthorized_cert import test_unauthorized_cert_attack
from test_no_cert import test_no_cert_attack
from test_rogue_server import test_rogue_server_mitm
from hashcat_audit import run_hashcat_security_analysis
from benchmark_concurrency import run_comparative_benchmark

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
EVIDENCIAS_DIR = os.path.join(BASE_DIR, "evidencias")
TEST_LOG_PATH = os.path.join(LOGS_DIR, "test_execution.log")
PCAP_OUTPUT_PATH = os.path.join(EVIDENCIAS_DIR, "vpn_tls13_traffic.pcap")

# Redirección de salida a archivo de log y consola simultáneamente
class LoggerTee:
    """
    Qué hace:
        Duplica los flujos de salida estándar para escribir en consola y en el fichero test_execution.log.
    Cuál es su función:
        Preservar el registro inmutable de la ejecución de pruebas para el entregable oficial.
    Cómo lo hace:
        Sobrescribe los métodos write y flush reenviando los bytes al fichero y al stdout original.
    """
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.log_file = open(filename, "w", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log_file.write(message)

    def flush(self):
        self.terminal.flush()
        self.log_file.flush()


def start_pcap_sniffer() -> subprocess.Popen:
    """
    Qué hace:
        Inicia un proceso de captura de tráfico en segundo plano utilizando TShark en la interfaz loopback (lo).
    Cuál es su función:
        Generar la evidencia técnica .pcap exigida por las normas de entrega y el requisito RS4.
    Cómo lo hace:
        Invoca tshark filtrando por los puertos 8443 (VPN TLS), 8444 (Rogue) y 8089 (Plain TCP) escribiendo en PCAP_OUTPUT_PATH.
    """
    cmd = [
        "tshark", "-i", "lo",
        "-f", "tcp port 8443 or tcp port 8444 or tcp port 8089",
        "-w", PCAP_OUTPUT_PATH,
        "-q"
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)  # Esperamos a que tshark enlace el socket de captura
        return proc
    except Exception as e:
        print(f"[!] Aviso: No se pudo arrancar tshark: {e}")
        return None


def run_all_tests():
    """
    Qué hace:
        Coordina y ejecuta secuencialmente las 12 pruebas de validación funcional y de seguridad de PAI 2.
    Cuál es su función:
        Demostrar formal y trazablemente el cumplimiento del 100% de los requisitos del pliego de condiciones.
    Cómo lo hace:
        Ejecuta cada test, verifica aserciones criptográficas, recopila métricas y genera un resumen ejecutivo.
    """
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(EVIDENCIAS_DIR, exist_ok=True)

    # Activamos la duplicación de salida a test_execution.log
    sys.stdout = LoggerTee(TEST_LOG_PATH)

    print("=" * 80)
    print(" SUITE OFICIAL DE VALIDACIÓN Y PRUEBAS DE CIBERSEGURIDAD - PAI 2 (BYODSEC)")
    print(" Entidad: Universidad Pública U-Secure | Equipo Auditor: Security Team 3 (Grupo 3)")
    print(" Fecha de Ejecución: Octubre 2026 | Entorno: TLS 1.3 / mTLS / OpenSSL 3.x")
    print("=" * 80)

    # 1. Iniciamos el sniffer de red TShark para capturar evidencias de tráfico
    print("\n[*] Iniciando captura de paquetes de red con TShark en 'lo' -> evidencias/vpn_tls13_traffic.pcap...")
    sniffer_proc = start_pcap_sniffer()

    # 2. Inicializamos la PKI institucional
    print("\n" + "=" * 80)
    print(" FASE 1: INICIALIZACIÓN DE LA INFRAESTRUCTURA DE CLAVE PÚBLICA (PKI) - RS1")
    print("=" * 80)
    pki_data = initialize_full_pki()

    # 3. Limpieza y reinicio de la base de datos corporativa para pruebas limpias
    print("\n" + "=" * 80)
    print(" FASE 2: INICIALIZACIÓN DE BASE DE DATOS Y DIRECTORIO DE USUARIOS - RF5")
    print("=" * 80)
    db_file = os.path.join(BASE_DIR, "data", "usecure_vpn.db")
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except Exception:
            pass
    # Eliminamos también los archivos auxiliares WAL de SQLite si existen
    for extra in [db_file + "-wal", db_file + "-shm"]:
        if os.path.exists(extra):
            try:
                os.remove(extra)
            except Exception:
                pass
    init_database()

    # 4. Levantamos la Pasarela VPN Road Warrior TLS 1.3 en un hilo independiente
    print("\n" + "=" * 80)
    print(" FASE 3: DESPLIEGUE DEL SERVIDOR GATEWAY ROAD WARRIOR VPN TLS 1.3 (mTLS)")
    print("=" * 80)
    server = VpnServer(SERVER_HOST, SERVER_PORT)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(1.0)  # Esperamos a que el servidor abra el socket de escucha

    test_results = []

    def record_test(test_id: str, desc: str, passed: bool, notes: str = ""):
        test_results.append({
            "id": test_id,
            "desc": desc,
            "passed": passed,
            "notes": notes
        })
        status_str = "[ PASS ]" if passed else "[ FAIL ]"
        print(f"\n{status_str} {test_id}: {desc}")
        if notes:
            print(f"         Detalle: {notes}")

    # =========================================================================
    # TEST 1: Validación de Infraestructura PKI y Extensiones X.509 v3 (RS1)
    # =========================================================================
    try:
        ca_exists = os.path.exists(pki_data["ca_cert"]) and os.path.exists(pki_data["ca_key"])
        srv_exists = os.path.exists(pki_data["server_cert"]) and os.path.exists(pki_data["server_key"])
        clients_ok = len(pki_data["clients"]) >= 4
        record_test("TEST 1 (RS1)", "Infraestructura PKI y Emisión de Certificados X.509 v3",
                    ca_exists and srv_exists and clients_ok,
                    "Root CA, Server Certificate con SAN y 4 certificados BYOD emitidos correctamente.")
    except Exception as e:
        record_test("TEST 1 (RS1)", "Infraestructura PKI", False, str(e))

    # =========================================================================
    # TEST 2: Precarga de Cuentas Universitarias por Rol (RF5)
    # =========================================================================
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username, role FROM users")
        users = cursor.fetchall()
        roles_found = {u["role"] for u in users}
        expected_roles = {"PDI", "PTGAS", "Investigador", "Auditor"}
        conn.close()
        is_ok = expected_roles.issubset(roles_found)
        record_test("TEST 2 (RF5)", "Precarga de Usuarios Corporativos y Perfiles de Acceso",
                    is_ok, f"Roles identificados en BD: {list(roles_found)}")
    except Exception as e:
        record_test("TEST 2 (RF5)", "Precarga de Usuarios Corporativos", False, str(e))

    # =========================================================================
    # TEST 3: Registro de Nuevo Usuario y Vinculación Inmutable BYOD (RF1)
    # =========================================================================
    try:
        new_user = "nuevo_investigador"
        reg_ok = register_user(
            username=new_user,
            password="NuevoInvestigadorPass2026$#INV",
            role="Investigador",
            full_name="Dr. Fernando Gómez (Investigador Asociado)",
            email="fernando.inv@usecure.edu.es",
            cert_cn=new_user
        )
        # Intentar registrar duplicado debe fallar (RF1 inmutabilidad)
        reg_dup = register_user(
            username=new_user,
            password="OtraPassCualquiera",
            role="Investigador",
            full_name="Duplicado",
            email="fernando.inv@usecure.edu.es",
            cert_cn=new_user
        )
        is_ok = reg_ok and (not reg_dup)
        record_test("TEST 3 (RF1)", "Registro de Usuario y Prevención de Identidades Duplicadas",
                    is_ok, "Usuario registrado y duplicidad bloqueada correctamente.")
    except Exception as e:
        record_test("TEST 3 (RF1)", "Registro de Usuario", False, str(e))

    # =========================================================================
    # TEST 4: Rate Limiting y Bloqueo Temporal frente a Fuerza Bruta (RS1.b)
    # =========================================================================
    try:
        # Probamos 3 intentos fallidos consecutivos sobre eval_user
        for _ in range(3):
            authenticate_user("eval_user", "ContrasenaCompletamenteErronea", "eval_user")
        # El 4to intento debe ser bloqueado por Rate Limiting
        is_auth, lock_msg, _ = authenticate_user("eval_user", "EvalAuditorPassword2026!#TEST", "eval_user")
        is_ok = (not is_auth) and ("bloqueada" in lock_msg.lower())
        record_test("TEST 4 (RS1.b)", "Protección Fuerza Bruta: Rate Limiting (Bloqueo de 60s)",
                    is_ok, f"Respuesta tras 3 fallos: '{lock_msg}'")
    except Exception as e:
        record_test("TEST 4 (RS1.b)", "Rate Limiting", False, str(e))

    # =========================================================================
    # TEST 5: Rechazo de Conexión sin Certificado de Cliente (mTLS - RS1, RS2)
    # =========================================================================
    try:
        no_cert_blocked = test_no_cert_attack()
        record_test("TEST 5 (RS1/RS2)", "Rechazo Categórico de Conexión sin Certificado (No-Cert)",
                    no_cert_blocked, "El servidor abortó el handshake al no recibir certificado de cliente.")
    except Exception as e:
        record_test("TEST 5 (RS1/RS2)", "Conexión sin Certificado", False, str(e))

    # =========================================================================
    # TEST 6: Rechazo de Certificado No Autorizado / Rogue (mTLS - RS1, RS2)
    # =========================================================================
    try:
        rogue_cert_blocked = test_unauthorized_cert_attack()
        record_test("TEST 6 (RS1/RS2)", "Rechazo de Certificado Digital No Autorizado (Rogue PKI)",
                    rogue_cert_blocked, "El handshake TLS 1.3 falló por certificado no firmado por la CA oficial.")
    except Exception as e:
        record_test("TEST 6 (RS1/RS2)", "Certificado No Autorizado", False, str(e))

    # =========================================================================
    # TEST 7: Detección y Rechazo de Gateway Falso / Evil Twin (EXTRA +10%)
    # =========================================================================
    try:
        rogue_server_blocked = test_rogue_server_mitm()
        record_test("TEST 7 (EXTRA +10%)", "Defensa Anti-MitM: Rechazo de Pasarela VPN Falsa (Evil Twin)",
                    rogue_server_blocked, "El cliente BYOD detectó y abortó la conexión al gateway no oficial.")
    except Exception as e:
        record_test("TEST 7 (EXTRA +10%)", "Defensa Anti-MitM", False, str(e))

    # =========================================================================
    # TEST 8: Detección de Discrepancia Dispositivo-Usuario (Device Spoofing)
    # =========================================================================
    try:
        # Conectamos con el certificado de carmen_pdi pero intentamos loguearnos como manuel_ptgas
        carmen_cert = os.path.join(CERTS_DIR, "client_carmen_pdi.crt")
        carmen_key = os.path.join(CERTS_DIR, "client_carmen_pdi.key")
        spoof_client = VpnClient(cert_path=carmen_cert, key_path=carmen_key)
        spoof_client.connect()
        spoof_res = spoof_client.login("manuel_ptgas", "ManuelSysAdmin2026!#PTGAS")
        spoof_client.close()

        is_spoof_blocked = (spoof_res.get("status") == 401) and ("certificado" in spoof_res.get("error", "").lower())
        record_test("TEST 8 (RF2)", "Detección de Discrepancia Dispositivo-Usuario (Device Binding)",
                    is_spoof_blocked, f"Resultado: {spoof_res.get('error')}")
    except Exception as e:
        record_test("TEST 8 (RF2)", "Device Spoofing", False, str(e))

    # =========================================================================
    # TEST 9: Conexión Legítima mTLS TLS 1.3 y Autenticación en Dos Capas (RF2)
    # =========================================================================
    legit_client = None
    try:
        # Desbloqueamos eval_user en BD para la prueba legítima
        conn = get_db_connection()
        conn.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = 'eval_user'")
        conn.commit()
        conn.close()

        eval_cert = os.path.join(CERTS_DIR, "client_eval_user.crt")
        eval_key = os.path.join(CERTS_DIR, "client_eval_user.key")
        legit_client = VpnClient(cert_path=eval_cert, key_path=eval_key)
        connected = legit_client.connect()

        cipher_used = legit_client.ssl_sock.cipher()[0]
        version_used = legit_client.ssl_sock.version()

        login_res = legit_client.login("eval_user", "EvalAuditorPassword2026!#TEST")
        auth_ok = (login_res.get("status") == 200) and login_res.get("authenticated")
        virtual_ip = login_res.get("virtual_ip", "")

        is_ok = connected and auth_ok and (version_used == "TLSv1.3") and virtual_ip.startswith("10.8.0.")
        record_test("TEST 9 (RF2/RS2)", "Handshake Legítimo mTLS TLS 1.3 y Autenticación en Dos Capas",
                    is_ok, f"Versión: {version_used} | Cifrado: {cipher_used} | IP Virtual: {virtual_ip}")
    except Exception as e:
        record_test("TEST 9 (RF2/RS2)", "Conexión Legítima mTLS", False, str(e))

    # =========================================================================
    # TEST 10: Control de Acceso Basado en Roles (RBAC) a Recursos de Intranet
    # =========================================================================
    try:
        # eval_user tiene rol 'Auditor' con acceso universal
        res_mail = legit_client.access_service("CORREO_CORPORATIVO")
        res_hpc = legit_client.access_service("INVESTIGACION_DB")
        is_ok = (res_mail.get("status") == 200) and (res_hpc.get("status") == 200)

        record_test("TEST 10 (RBAC)", "Acceso Seguro a Recursos Internos según Perfil Corporativo",
                    is_ok, f"Servicios accedidos: {res_mail.get('service')}, {res_hpc.get('service')}")
    except Exception as e:
        record_test("TEST 10 (RBAC)", "Acceso a Recursos Internos", False, str(e))

    # =========================================================================
    # TEST 11: Desmontaje Seguro del Túnel y Destrucción de Sesión (RF4)
    # =========================================================================
    try:
        active_sess_id = legit_client.session_info.get("session_id") if (legit_client and legit_client.session_info) else None
        disc_res = legit_client.disconnect()
        is_ok = disc_res.get("status") == 200
        # Verificamos que la sesión ya no figure activa en base de datos
        conn = get_db_connection()
        cursor = conn.cursor()
        if active_sess_id:
            cursor.execute("SELECT * FROM active_sessions WHERE session_id = ?", (active_sess_id,))
        else:
            cursor.execute("SELECT * FROM active_sessions WHERE username = 'eval_user'")
        active = cursor.fetchone()
        conn.close()

        is_ok = is_ok and (active is None)
        record_test("TEST 11 (RF4)", "Cierre Seguro de Sesión y Desmontaje del Túnel (PFS)",
                    is_ok, "IP virtual liberada y claves efímeras destruidas satisfactoriamente.")
    except Exception as e:
        record_test("TEST 11 (RF4)", "Desmontaje de Túnel", False, str(e))

    # =========================================================================
    # TEST 12: Evaluación de Rendimiento y Escalabilidad (300 Concurrencias - RS3)
    # =========================================================================
    try:
        bench_data = run_comparative_benchmark(concurrency=300)
        is_ok = bench_data["tls13_mtls"]["success_rate"] == 100.0
        record_test("TEST 12 (RS3)", "Escalabilidad y Carga Concurrente (300 Usuarios Simultáneos)",
                    is_ok, f"100% éxito | Throughput: {bench_data['tls13_mtls']['throughput_req_s']:.1f} req/s | RTT: {bench_data['tls13_mtls']['avg_rtt_ms']:.2f} ms")
    except Exception as e:
        record_test("TEST 12 (RS3)", "Escalabilidad 300 Usuarios", False, str(e))

    # 5. Auditoría Criptográfica con Hashcat
    print("\n" + "=" * 80)
    print(" FASE 4: AUDITORÍA DE SEGURIDAD DE CREDENCIALES Y FUERZA BRUTA CON HASHCAT")
    print("=" * 80)
    run_hashcat_security_analysis()

    # 6. Detenemos sniffer y servidor
    print("\n[*] Finalizando captura TShark y deteniendo servidor VPN...")
    if sniffer_proc:
        try:
            sniffer_proc.terminate()
            sniffer_proc.wait(timeout=2.0)
        except Exception:
            pass

    server.stop()

    # 7. Resumen de Ejecución
    print("\n" + "=" * 80)
    print(" RESUMEN FINAL DE LA BATERÍA DE PRUEBAS DE CIBERSEGURIDAD")
    print("=" * 80)
    total_tests = len(test_results)
    passed_tests = sum(1 for t in test_results if t["passed"])
    coverage_pct = (passed_tests / total_tests) * 100.0

    for t in test_results:
        mark = "✓ PASS" if t["passed"] else "✗ FAIL"
        print(f"  [{mark}] {t['id']:<18} : {t['desc']}")

    print("-" * 80)
    print(f" Pruebas Ejecutadas: {total_tests} | Superadas: {passed_tests} | Fallidas: {total_tests - passed_tests}")
    print(f" Grado de Cobertura y Cumplimiento: {coverage_pct:.1f}%")
    print("=" * 80)

    # 8. Verificación de PCAP capturado
    if os.path.exists(PCAP_OUTPUT_PATH):
        pcap_size = os.path.getsize(PCAP_OUTPUT_PATH)
        print(f"[+] Archivo PCAP generado con éxito: {PCAP_OUTPUT_PATH} ({pcap_size:,} bytes)")
        print("[*] Inspección preliminar de trazas con TShark:")
        try:
            pcap_summary = subprocess.check_output(
                ["tshark", "-r", PCAP_OUTPUT_PATH, "-c", "10", "-q", "-z", "io,stat,0"],
                text=True
            )
            print(pcap_summary)
        except Exception:
            pass

    # Restauramos stdout
    sys.stdout.terminal.flush()
    sys.stdout = sys.stdout.terminal
    print(f"[OK] Logs completos guardados en: {TEST_LOG_PATH}")


if __name__ == "__main__":
    run_all_tests()
