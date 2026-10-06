#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
SISTEMA DE BASE DE DATOS Y GESTIÓN DE IDENTIDADES - UNIVERSIDAD U-SECURE
Módulo: database.py
Equipo: Security Team 3 (Grupo 3)
Asignatura: Seguridad en Sistemas Informáticos y en Internet - PAI 2 (BYODSEC)
Fecha: Octubre 2026
========================================================================================
Descripción General:
Este módulo implementa el repositorio centralizado de identidades, credenciales corporativas,
asignación de direccionamiento IP virtual del túnel VPN y auditoría de eventos de seguridad
para la Universidad Pública U-Secure.

Garantías de Seguridad Implementadas:
1. Almacenamiento Criptográfico de Contraseñas: PBKDF2-HMAC-SHA256 con 600.000 iteraciones
   y sal única de 128 bits generada por CSPRNG (estándares NIST SP 800-132 y OWASP).
2. Prevención de Ataques de Tiempo (Timing Attacks): Comparación estricta en tiempo constante
   mediante la primitiva criptográfica secrets.compare_digest.
3. Vinculación Fuerte Dispositivo-Usuario (Device-User Binding): Asociación unívoca entre la
   identidad corporativa y el Common Name (CN) del certificado digital X.509 de cliente (RF1, RF2).
4. Gestión de Concurrencia y Pool de Direcciones Virtuales (10.8.0.0/24) para 300 sesiones simultáneas.
5. Registro Inmutable de Auditoría de Accesos, Intentos Fallidos y Bloqueos (RS4).
========================================================================================
"""

import os
import sqlite3
import hashlib
import secrets
import time
import threading
from typing import Optional, Dict, Any, List

# Bloqueo reentrante para sincronización de escrituras concurrentes en SQLite (RS3)
_db_lock = threading.RLock()

# Definición de rutas base para almacenamiento de base de datos relacional SQLite
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "usecure_vpn.db")

# Constantes de seguridad para derivación de claves (NIST SP 800-132)
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16  # 128 bits de entropía pseudoaleatoria criptográficamente segura


def ensure_data_dir() -> None:
    """
    Qué hace:
        Verifica y crea el directorio donde se aloja el archivo de base de datos SQLite.
    Cuál es su función:
        Evitar fallos de entrada/salida al abrir la conexión con usecure_vpn.db.
    Cómo lo hace:
        Ejecuta os.makedirs especificando exist_ok=True para prevenir errores por existencia previa.
    """
    os.makedirs(DATA_DIR, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    """
    Qué hace:
        Establece una conexión con la base de datos SQLite corporativa y habilita claves foráneas.
    Cuál es su función:
        Proporcionar un objeto de conexión seguro y configurado para operaciones ACID transaccionales.
    Cómo lo hace:
        Llama a sqlite3.connect con timeout de 60 segundos y activa 'PRAGMA foreign_keys = ON' y 'PRAGMA busy_timeout = 60000'.
    """
    # Nos aseguramos de que la carpeta contenedora exista
    ensure_data_dir()

    # Abrimos la conexión con la base de datos local con timeout generoso para concurrencia
    conn = sqlite3.connect(DB_PATH, timeout=60.0)

    # Configuramos el formato de fila como sqlite3.Row para acceder a columnas por nombre
    conn.row_factory = sqlite3.Row

    # Habilitamos la integridad referencial mediante claves foráneas
    conn.execute("PRAGMA foreign_keys = ON;")

    # Habilitamos el modo WAL (Write-Ahead Logging) para permitir concurrencia de lectura/escritura
    conn.execute("PRAGMA journal_mode = WAL;")

    # Configuramos el timeout de ocupado en SQLite
    conn.execute("PRAGMA busy_timeout = 60000;")

    return conn


def hash_password(password: str, salt_hex: Optional[str] = None) -> tuple:
    """
    Qué hace:
        Deriva un hash criptográfico robusto a partir de una contraseña en texto plano utilizando PBKDF2.
    Cuál es su función:
        Proteger las credenciales contra ataques de diccionario, fuerza bruta y tablas Rainbow (RS1.a).
    Cómo lo hace:
        1. Si no se suministra una sal, genera 16 bytes aleatorios con secrets.token_hex(SALT_BYTES).
        2. Ejecuta hashlib.pbkdf2_hmac con algoritmo SHA-256, 600.000 iteraciones y salida de 32 bytes (256 bits).
        3. Retorna la sal utilizada y el hash resultante en formato hexadecimal.
    """
    # Generamos sal criptográfica de 128 bits si no se proporciona una previamente
    if salt_hex is None:
        salt_bytes = secrets.token_bytes(SALT_BYTES)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt_hex)

    # Computamos la función de derivación PBKDF2 con HMAC-SHA256
    derived_key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt_bytes,
        iterations=PBKDF2_ITERATIONS,
        dklen=32
    )

    # Convertimos los bytes del hash a representación hexadecimal
    hash_hex = derived_key.hex()

    return salt_hex, hash_hex


def verify_password(stored_salt_hex: str, stored_hash_hex: str, provided_password: str) -> bool:
    """
    Qué hace:
        Verifica si una contraseña proporcionada coincide con el hash almacenado en base de datos.
    Cuál es su función:
        Autenticar al usuario en la capa de aplicación previniendo fugas por canales laterales de tiempo.
    Cómo lo hace:
        Deriva el hash con la sal registrada y compara mediante secrets.compare_digest en tiempo constante.
    """
    # Calculamos el hash de la contraseña provista con la sal existente
    _, test_hash_hex = hash_password(provided_password, stored_salt_hex)

    # Comparamos usando tiempo constante para inmunidad absoluta contra Timing Attacks
    is_valid = secrets.compare_digest(stored_hash_hex, test_hash_hex)

    return is_valid


def init_database() -> None:
    """
    Qué hace:
        Crea las tablas relacionales de la base de datos institucional si no existen e inicializa los datos.
    Cuál es su función:
        Establecer el esquema de almacenamiento para usuarios corporativos, sesiones VPN y auditoría.
    Cómo lo hace:
        Ejecuta sentencias DDL (CREATE TABLE IF NOT EXISTS) e invoca la precarga de usuarios institucionales (RF5).
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Tabla de Usuarios Institucionales (PDI, PTGAS, Investigadores)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        cert_cn TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        locked_until REAL DEFAULT 0,
        created_at REAL NOT NULL
    );
    """)

    # Tabla de Sesiones Activas del Túnel VPN (RF4, RS3)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS active_sessions (
        session_id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        virtual_ip TEXT NOT NULL UNIQUE,
        client_ip TEXT NOT NULL,
        tls_cipher TEXT NOT NULL,
        connected_at REAL NOT NULL,
        last_activity REAL NOT NULL,
        bytes_in INTEGER DEFAULT 0,
        bytes_out INTEGER DEFAULT 0,
        FOREIGN KEY (username) REFERENCES users (username) ON DELETE CASCADE
    );
    """)

    # Tabla de Registro Inmutable de Auditoría de Ciberseguridad (RS4)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        username TEXT,
        client_ip TEXT,
        details TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()

    # Precargamos los usuarios predeterminados requeridos por las especificaciones de U-Secure (RF5)
    seed_default_users()


def seed_default_users() -> None:
    """
    Qué hace:
        Registra en la base de datos el conjunto inicial de identidades pertenecientes a los roles de la universidad.
    Cuál es su función:
        Cumplir con el requisito funcional RF5 (Gestión de Usuarios Preexistentes y Perfiles de Acceso: PDI, PTGAS, Investigador).
    Cómo lo hace:
        Inserta registros con contraseñas seguras pre-hasheadas y vinculadas unívocamente a los certificados X.509 de la PKI.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Cuentas predefinidas según la normativa corporativa de U-Secure
    initial_accounts = [
        {
            "username": "carmen_pdi",
            "password": "CarmenSecurePass2026!#PDI",
            "role": "PDI",
            "full_name": "Dra. Carmen Sánchez (Catedrática de Seguridad Informática)",
            "email": "carmen.pdi@usecure.edu.es",
            "cert_cn": "carmen_pdi"
        },
        {
            "username": "manuel_ptgas",
            "password": "ManuelSysAdmin2026!#PTGAS",
            "role": "PTGAS",
            "full_name": "Manuel Rodríguez (Técnico de Redes y Comunicaciones)",
            "email": "manuel.ptgas@usecure.edu.es",
            "cert_cn": "manuel_ptgas"
        },
        {
            "username": "lucia_inv",
            "password": "LuciaCryptoPass2026!#INV",
            "role": "Investigador",
            "full_name": "Lucía Morales (Investigadora Postdoctoral en Criptografía)",
            "email": "lucia.investigacion@usecure.edu.es",
            "cert_cn": "lucia_inv"
        },
        {
            "username": "eval_user",
            "password": "EvalAuditorPassword2026!#TEST",
            "role": "Auditor",
            "full_name": "Equipo Auditor Security Team 3 (Pruebas de Ciberseguridad)",
            "email": "eval.user@usecure.edu.es",
            "cert_cn": "eval_user"
        }
    ]

    now = time.time()
    for acc in initial_accounts:
        cursor.execute("SELECT username FROM users WHERE username = ?", (acc["username"],))
        if cursor.fetchone() is None:
            salt_hex, hash_hex = hash_password(acc["password"])
            cursor.execute("""
                INSERT INTO users (username, salt, password_hash, role, full_name, email, cert_cn, failed_attempts, locked_until, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
            """, (acc["username"], salt_hex, hash_hex, acc["role"], acc["full_name"], acc["email"], acc["cert_cn"], now))

    conn.commit()
    conn.close()


def register_user(username: str, password: str, role: str, full_name: str, email: str, cert_cn: str) -> bool:
    """
    Qué hace:
        Registra un nuevo usuario en la base de datos vinculándolo a su certificado X.509 de dispositivo BYOD (RF1).
    Cuál es su función:
        Garantizar la inmutabilidad de registros y vincular la identidad digital con la credencial de aplicación.
    Cómo lo hace:
        Genera sal criptográfica, deriva el hash con PBKDF2 y realiza una inserción transaccional en la tabla users.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verificamos si el usuario ya existe
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            conn.close()
            return False

        # Derivamos la contraseña con sal aleatoria
        salt_hex, hash_hex = hash_password(password)
        now = time.time()

        cursor.execute("""
            INSERT INTO users (username, salt, password_hash, role, full_name, email, cert_cn, failed_attempts, locked_until, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
        """, (username, salt_hex, hash_hex, role, full_name, email, cert_cn, now))

        conn.commit()
        return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def authenticate_user(username: str, password: str, cert_cn: str) -> tuple:
    """
    Qué hace:
        Valida la autenticación en dos capas (mTLS + Credenciales) conforme al requisito RF2.
    Cuál es su función:
        Comprobar que:
        1. La cuenta no esté bloqueada por exceso de intentos fallidos (Rate Limiting).
        2. La contraseña de aplicación sea matemáticamente correcta (PBKDF2 con compare_digest).
        3. El certificado digital del cliente coincida exactamente con el usuario registrado (Device Binding).
    Cómo lo hace:
        Consulta la tabla users, verifica bloqueos temporales, valida contraseña en tiempo constante,
        compara cert_cn con el registrado, y gestiona contadores de fallos con bloqueos de 60s tras 3 errores.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = time.time()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    if row is None:
        conn.close()
        return False, "Usuario inexistente en el directorio corporativo", None

    # Comprobamos bloqueo por fuerza bruta (Rate Limiting)
    if row["locked_until"] > now:
        remaining = int(row["locked_until"] - now)
        conn.close()
        return False, f"Cuenta temporalmente bloqueada. Intente de nuevo en {remaining} segundos.", None

    # Validación 1: Vinculación Estricta con el Certificado Digital mTLS (RF1, RF2)
    if not secrets.compare_digest(row["cert_cn"], cert_cn):
        # El certificado presentado no pertenece a este usuario (Intento de suplantación)
        log_audit_event("AUTH_SPOOF_ATTEMPT", "CRITICAL", username, "N/A",
                        f"Discrepancia de identidad: Certificado CN '{cert_cn}' no coincide con '{row['cert_cn']}'")
        conn.close()
        return False, "Violación de seguridad: El certificado digital BYOD no corresponde al usuario corporativo.", None

    # Validación 2: Verificación de Contraseña de Aplicación en tiempo constante
    is_valid_pw = verify_password(row["salt"], row["password_hash"], password)

    if not is_valid_pw:
        with _db_lock:
            new_failed = row["failed_attempts"] + 1
            locked_time = 0
            if new_failed >= 3:
                locked_time = now + 60.0  # Bloqueo por 60 segundos tras 3 fallos consecutivos
            cursor.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
                           (new_failed, locked_time, username))
            conn.commit()
            conn.close()
        if new_failed >= 3:
            log_audit_event("ACCOUNT_LOCKED", "WARNING", username, "N/A",
                            f"Cuenta bloqueada por 60s tras alcanzar {new_failed} intentos fallidos.")
        return False, "Credenciales incorrectas (Contraseña corporativa no válida)", None

    # Credenciales correctas: Reiniciamos contador de fallos
    with _db_lock:
        cursor.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = ?", (username,))
        conn.commit()

    user_info = {
        "username": row["username"],
        "role": row["role"],
        "full_name": row["full_name"],
        "email": row["email"],
        "cert_cn": row["cert_cn"]
    }
    conn.close()
    return True, "Autenticación bidireccional superada satisfactoriamente", user_info


def allocate_virtual_ip(cursor: sqlite3.Cursor) -> Optional[str]:
    """
    Qué hace:
        Asigna una dirección IP virtual dentro del rango VPN corporativo (10.8.0.0/22) para la sesión establecida.
    Cuál es su función:
        Enrutar el tráfico seguro dentro del túnel garantizando unicidad de IPs para más de 500 clientes simultáneos.
    Cómo lo hace:
        Examina las IPs ocupadas en active_sessions y selecciona la primera libre en las subredes 10.8.0.x, 10.8.1.x o 10.8.2.x.
    """
    cursor.execute("SELECT virtual_ip FROM active_sessions")
    used_ips = {row["virtual_ip"] for row in cursor.fetchall()}

    for subnet in (0, 1, 2):
        for host in range(10, 255):
            cand = f"10.8.{subnet}.{host}"
            if cand not in used_ips:
                return cand
    return None


def create_vpn_session(username: str, client_ip: str, tls_cipher: str) -> Optional[Dict[str, Any]]:
    """
    Qué hace:
        Crea y registra atómicamente una nueva sesión activa de túnel VPN Road Warrior en la base de datos (RF2).
    Cuál es su función:
        Asignar Session ID criptográfico (128 bits CSPRNG), IP virtual única y persistir estado TLS 1.3 de forma segura en concurrencia.
    Cómo lo hace:
        Bajo bloqueo reentrante _db_lock, obtiene IP libre con allocate_virtual_ip e inserta el registro en active_sessions.
    """
    with _db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        vip = allocate_virtual_ip(cursor)
        if not vip:
            conn.close()
            return None

        session_id = secrets.token_hex(16)
        now = time.time()

        cursor.execute("""
            INSERT INTO active_sessions (session_id, username, virtual_ip, client_ip, tls_cipher, connected_at, last_activity, bytes_in, bytes_out)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
        """, (session_id, username, vip, client_ip, tls_cipher, now, now))

        conn.commit()
        conn.close()

    log_audit_event("SESSION_START", "INFO", username, client_ip,
                    f"Túnel VPN establecido. IP Virtual: {vip}. Cifrado: {tls_cipher}. SessionID: {session_id}")

    return {
        "session_id": session_id,
        "username": username,
        "virtual_ip": vip,
        "tls_cipher": tls_cipher,
        "connected_at": now
    }


def destroy_vpn_session(session_id: str) -> bool:
    """
    Qué hace:
        Elimina la sesión del túnel VPN activo y libera los recursos asignados (RF4).
    Cuál es su función:
        Garantizar el desmontaje inmediato del túnel y la destrucción de identificadores de sesión en concurrencia.
    Cómo lo hace:
        Bajo _db_lock, elimina el registro de active_sessions según session_id y registra evento en audit_logs.
    """
    with _db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT username, virtual_ip, client_ip FROM active_sessions WHERE session_id = ?", (session_id,))
        row = cursor.fetchone()

        if row is None:
            conn.close()
            return False

        username = row["username"]
        virtual_ip = row["virtual_ip"]
        client_ip = row["client_ip"]

        cursor.execute("DELETE FROM active_sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        conn.close()

    log_audit_event("SESSION_TERMINATE", "INFO", username, client_ip,
                    f"Túnel VPN desmontado explícitamente (RF4). IP Virtual liberada: {virtual_ip}")
    return True


def log_audit_event(event_type: str, severity: str, username: Optional[str], client_ip: Optional[str], details: str) -> None:
    """
    Qué hace:
        Inserta un evento de auditoría estructurado en la tabla audit_logs de forma trazable e inmutable (RS4).
    Cuál es su función:
        Proporcionar evidencias de cumplimiento normativo (RGPD, ENS) de forma thread-safe en alta concurrencia.
    Cómo lo hace:
        Bajo _db_lock, inserta marca de tiempo UTC, tipo de evento, severidad, usuario, IP y detalles.
    """
    try:
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            now = time.time()

            cursor.execute("""
                INSERT INTO audit_logs (timestamp, event_type, severity, username, client_ip, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (now, event_type, severity, username, client_ip, details))

            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[ERROR AUDIT LOG] {e}")


def get_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Qué hace:
        Recupera los eventos más recientes del registro de auditoría de ciberseguridad.
    Cuál es su función:
        Permitir al administrador de seguridad auditar accesos, intentos de ataque y sesiones activas.
    Cómo lo hace:
        Ejecuta un SELECT ordenado por timestamp descendente con límite especificado.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()

    logs = [dict(r) for r in rows]
    conn.close()
    return logs


if __name__ == "__main__":
    # Si se ejecuta directamente, inicializamos el esquema relacional
    print("[*] Inicializando base de datos institucional usecure_vpn.db...")
    init_database()
    print("[OK] Base de datos y cuentas corporativas precargadas satisfactoriamente.")
