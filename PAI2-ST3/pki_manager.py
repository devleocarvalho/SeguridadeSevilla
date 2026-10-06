#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
SISTEMA DE GESTIÓN DE INFRAESTRUCTURA DE CLAVE PÚBLICA (PKI) - UNIVERSIDAD U-SECURE
Módulo: pki_manager.py
Equipo: Security Team 3 (Grupo 3)
Asignatura: Seguridad en Sistemas Informáticos y en Internet - PAI 2 (BYODSEC)
Fecha: Octubre 2026
========================================================================================
Descripción General:
Este módulo implementa la Autoridad de Certificación (CA) Corporativa interna de la
Universidad Pública U-Secure, gestionando el ciclo de vida completo de certificados
digitales conforme al estándar ITU-T X.509 versión 3 y el estándar RFC 5280.

Funcionalidades Principales:
1. Generación de Claves Criptográficas Asimétricas RSA mediante CSPRNG de alta entropía.
2. Emisión y firma digital de la Autoridad de Certificación Raíz (U-Secure Root CA v1.3).
3. Emisión de Certificados de Servidor (Gateway VPN) con extensiones SAN (Subject Alternative Names).
4. Emisión de Certificados de Cliente BYOD con autenticación mutua (mTLS) y perfilado por roles (PDI, PTGAS, Investigador).
5. Generación de certificados no autorizados (Rogue/Attacker PKI) para pruebas de penetración y denegación de acceso.
6. Generación masiva de credenciales y certificados para pruebas de estrés y concurrencia (300 usuarios).
========================================================================================
"""

import os
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Definición de rutas base para almacenamiento seguro de certificados y claves privadas
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")


def ensure_certs_dir() -> None:
    """
    Qué hace:
        Verifica la existencia del directorio de certificados y lo crea si no existe.
    Cuál es su función:
        Garantizar que el sistema de archivos disponga de la ruta adecuada con permisos
        restringidos antes de almacenar claves criptográficas privadas y certificados.
    Cómo lo hace:
        Invoca os.makedirs con exist_ok=True para evitar condiciones de carrera en el sistema de ficheros.
    """
    # Creamos el directorio si no existe previamente en disco
    os.makedirs(CERTS_DIR, exist_ok=True)


def generate_rsa_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Qué hace:
        Genera una clave privada asimétrica RSA utilizando el generador seguro del sistema operativo.
    Cuál es su función:
        Proporcionar la base matemática para las operaciones de firma digital y descifrado asimétrico
        requeridas en la infraestructura PKI y en el protocolo mTLS (Mutual TLS).
    Cómo lo hace:
        Invoca rsa.generate_private_key especificando un exponente público estándar 65537 (F4 de Fermat)
        y una longitud de clave de 2048 bits (recomendación NIST SP 800-57 para operaciones seguras).
    """
    # Generamos la clave asimétrica RSA con exponente seguro 65537
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    # Retornamos la instancia de clave privada generada en memoria
    return private_key


def save_private_key_pem(key: rsa.RSAPrivateKey, filepath: str, password: str = None) -> None:
    """
    Qué hace:
        Serializa y almacena en disco una clave privada RSA en formato estándar PEM (PKCS#8).
    Cuál es su función:
        Persistir la clave privada de forma protegida para que pueda ser cargada por los sockets TLS.
    Cómo lo hace:
        Utiliza serialization.PrivateFormat.PKCS8 con cifrado BestAvailableEncryption si se suministra
        contraseña, o NoEncryption si se gestiona en memoria o entorno de laboratorio controlado.
    """
    # Determinamos el algoritmo de cifrado para la clave privada en disco
    if password:
        # Ciframos con contraseña mediante PBKDF2/AES a través del estándar OpenSSL
        encryption_algo = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        # Almacenamos sin cifrado de clave privada para automatización de pruebas
        encryption_algo = serialization.NoEncryption()

    # Convertimos la clave al formato de bytes PEM
    pem_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    )

    # Escribimos los bytes resultantes en el fichero de destino
    with open(filepath, "wb") as f:
        f.write(pem_bytes)

    # Establecemos permisos restrictivos (solo lectura/escritura para el propietario: 0600)
    os.chmod(filepath, 0o600)


def save_certificate_pem(cert: x509.Certificate, filepath: str) -> None:
    """
    Qué hace:
        Serializa y guarda en disco un certificado digital X.509 en formato PEM.
    Cuál es su función:
        Distribuir la clave pública, identidad institucional y extensiones firmadas a los participantes.
    Cómo lo hace:
        Invoca cert.public_bytes con Encoding.PEM y escribe el contenido con permisos legibles estándar (0644).
    """
    # Convertimos la estructura de datos ASN.1 del certificado a texto estructurado PEM
    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)

    # Escribimos en el archivo especificado
    with open(filepath, "wb") as f:
        f.write(pem_bytes)

    # Establecemos permisos de lectura pública (0644)
    os.chmod(filepath, 0o644)


def create_root_ca(common_name: str = "U-Secure Root CA v1.3", days_valid: int = 365) -> tuple:
    """
    Qué hace:
        Crea la Autoridad de Certificación Raíz (Root CA) autofirmada para la Universidad U-Secure.
    Cuál es su función:
        Actuar como el ancla de confianza (Trust Anchor) de toda la arquitectura de seguridad BYOD,
        firmando los certificados tanto del servidor VPN Gateway como de los dispositivos autorizados.
    Cómo lo hace:
        1. Genera un par de claves RSA de 2048 bits.
        2. Construye el sujeto (Subject) e emisor (Issuer) idénticos (autofirmado).
        3. Añade la extensión crítica BasicConstraints(ca=True) indicando capacidad de firma de certificados.
        4. Añade KeyUsage con key_cert_sign y crl_sign habilitados.
        5. Firma el certificado utilizando el algoritmo SHA-256 y la clave privada de la propia CA.
    """
    # Aseguramos el directorio de destino
    ensure_certs_dir()

    # Generamos la clave privada de la CA Raíz
    ca_key = generate_rsa_private_key(key_size=2048)

    # Definimos la identidad institucional de la CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sevilla"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Sevilla"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad Publica U-Secure"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Servicio de Ciberseguridad e Infraestructura"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Definimos la ventana temporal de validez (UTC)
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now - datetime.timedelta(minutes=5)
    valid_to = now + datetime.timedelta(days=days_valid)

    # Construimos el certificado X.509 v3
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        # Extensión crítica indicando que es una CA válida
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        # Extensión de usos de clave: firmar otros certificados y listas de revocación
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        # Identificador de clave del sujeto (Subject Key Identifier - RFC 5280)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False
        )
        # Firma criptográfica con RSA y hash SHA-256
        .sign(ca_key, hashes.SHA256())
    )

    # Guardamos clave privada y certificado en disco
    ca_key_path = os.path.join(CERTS_DIR, "ca.key")
    ca_cert_path = os.path.join(CERTS_DIR, "ca.crt")
    save_private_key_pem(ca_key, ca_key_path)
    save_certificate_pem(ca_cert, ca_cert_path)

    # Retornamos los objetos y rutas para su uso
    return ca_key, ca_cert, ca_key_path, ca_cert_path


def issue_server_certificate(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    common_name: str = "vpn.usecure.edu.es",
    san_list: list = None,
    days_valid: int = 180
) -> tuple:
    """
    Qué hace:
        Emite y firma el certificado digital X.509 v3 para la pasarela VPN Road Warrior de U-Secure.
    Cuál es su función:
        Permitir que los clientes remotos BYOD verifiquen la autenticidad del servidor institucional
        y establezcan una conexión cifrada TLS 1.3 inmune a ataques Man-in-the-Middle y suplantación de servidor.
    Cómo lo hace:
        1. Genera una clave privada RSA de 2048 bits específica para el servidor.
        2. Configura los nombres alternativos del sujeto (SAN: Subject Alternative Names) incluyendo IP y DNS.
        3. Configura la extensión ExtendedKeyUsage con serverAuth (autenticación de servidor web/VPN).
        4. Firma el certificado utilizando la clave privada de la CA Raíz de U-Secure.
    """
    # Generamos la clave privada del servidor VPN
    server_key = generate_rsa_private_key(key_size=2048)

    # Definimos el sujeto del certificado
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sevilla"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Sevilla"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad Publica U-Secure"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Infraestructura de Comunicaciones Seguras"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Definimos la ventana temporal de validez
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now - datetime.timedelta(minutes=5)
    valid_to = now + datetime.timedelta(days=days_valid)

    # Preparamos las alternativas de nombre de sujeto (SAN) para validación estricta de nombres
    if san_list is None:
        san_list = ["localhost", "127.0.0.1", "vpn.usecure.edu.es"]

    san_names = []
    for item in san_list:
        try:
            # Si es una dirección IP válida, la agregamos como IPAddress
            ip_obj = ipaddress.ip_address(item)
            san_names.append(x509.IPAddress(ip_obj))
        except ValueError:
            # Si no es IP, la tratamos como nombre de dominio DNS
            san_names.append(x509.DNSName(item))

    # Construimos y firmamos el certificado del servidor
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        # Restricción básica: no es una CA
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        # Usos de clave: firma digital e intercambio/cifrado de claves
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        # Uso extendido: autenticación de servidor TLS (serverAuth)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )
        # Nombres alternativos del sujeto (SAN) para evitar alertas de mismatch de hostname
        .add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False
        )
        # Identificador de clave de autoridad vinculada a la CA
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False
        )
        # Firma realizada con la clave privada de la CA Raíz
        .sign(ca_key, hashes.SHA256())
    )

    # Guardamos los archivos resultantes
    server_key_path = os.path.join(CERTS_DIR, "server.key")
    server_cert_path = os.path.join(CERTS_DIR, "server.crt")
    save_private_key_pem(server_key, server_key_path)
    save_certificate_pem(server_cert, server_cert_path)

    return server_key, server_cert, server_key_path, server_cert_path


def issue_client_certificate(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    username: str,
    role: str,
    email: str,
    days_valid: int = 90
) -> tuple:
    """
    Qué hace:
        Emite y firma un certificado digital de cliente X.509 v3 para un dispositivo BYOD autorizado.
    Cuál es su función:
        Materializar el primer factor de autenticación (Capa de Transporte mTLS): vincular criptográficamente
        un dispositivo personal y un usuario específico con la clave privada alojada en el equipo BYOD.
    Cómo lo hace:
        1. Genera una clave RSA de 2048 bits para el dispositivo cliente.
        2. Configura los metadatos institucionales incluyendo nombre de usuario, rol corporativo y email.
        3. Configura la extensión ExtendedKeyUsage con clientAuth (autenticación de cliente TLS).
        4. Firma el certificado con la clave privada de la CA Raíz de U-Secure.
    """
    # Generamos la clave privada del dispositivo BYOD
    client_key = generate_rsa_private_key(key_size=2048)

    # Definimos la identidad institucional del usuario y su rol
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sevilla"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Sevilla"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad Publica U-Secure"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Rol-{role}"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    # Definimos la ventana temporal de validez
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now - datetime.timedelta(minutes=5)
    valid_to = now + datetime.timedelta(days=days_valid)

    # Construimos y firmamos el certificado del cliente BYOD
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        # Restricción básica: no es una CA
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        # Usos de clave: firma digital para la prueba CertificateVerify en el handshake TLS 1.3
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        # Uso extendido: autenticación de cliente TLS (clientAuth)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
        # Nombre alternativo del sujeto con correo RFC822
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False
        )
        # Identificador de clave de autoridad firmado por la CA
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False
        )
        # Firma criptográfica con la clave de la CA
        .sign(ca_key, hashes.SHA256())
    )

    # Guardamos los ficheros en el almacén de certificados
    safe_name = username.replace("@", "_").replace(".", "_")
    client_key_path = os.path.join(CERTS_DIR, f"client_{safe_name}.key")
    client_cert_path = os.path.join(CERTS_DIR, f"client_{safe_name}.crt")

    save_private_key_pem(client_key, client_key_path)
    save_certificate_pem(client_cert, client_cert_path)

    return client_key, client_cert, client_key_path, client_cert_path


def create_rogue_attacker_pki() -> tuple:
    """
    Qué hace:
        Genera una infraestructura de clave pública falsa/maliciosa (Rogue CA y Rogue Client/Server).
    Cuál es su función:
        Servir como vector de ataque simulado para demostrar en laboratorio que tanto el servidor VPN
        como los clientes BYOD rechazan categóricamente certificados no emitidos por la CA oficial.
    Cómo lo hace:
        1. Crea una CA ficticia ("Hacker Evil CA").
        2. Emite certificados de cliente y servidor firmados por dicha CA maliciosa.
        3. Permite verificar que el handshake TLS 1.3 lanza alertas críticas de fallo de validación de certificado.
    """
    ensure_certs_dir()

    # Generamos clave y certificado autofirmado del atacante
    rogue_ca_key = generate_rsa_private_key(key_size=2048)
    rogue_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted Rogue Attacker Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Untrusted CA"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    rogue_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_subject)
        .issuer_name(rogue_subject)
        .public_key(rogue_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(rogue_ca_key, hashes.SHA256())
    )

    # Emitimos un certificado de cliente malicioso firmado por la Rogue CA
    rogue_client_key = generate_rsa_private_key(key_size=2048)
    rogue_client_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted Rogue Attacker Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "rogue_attacker_device"),
    ])

    rogue_client_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_client_subject)
        .issuer_name(rogue_ca_cert.subject)
        .public_key(rogue_client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(rogue_ca_key, hashes.SHA256())
    )

    # Emitimos un certificado de servidor malicioso (Rogue Server / Evil Twin)
    rogue_server_key = generate_rsa_private_key(key_size=2048)
    rogue_server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted Rogue Gateway"),
        x509.NameAttribute(NameOID.COMMON_NAME, "vpn.usecure.edu.es"),
    ])

    rogue_server_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_server_subject)
        .issuer_name(rogue_ca_cert.subject)
        .public_key(rogue_server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("vpn.usecure.edu.es"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=False)
        .sign(rogue_ca_key, hashes.SHA256())
    )

    # Guardamos los archivos maliciosos para pruebas de penetración
    save_certificate_pem(rogue_ca_cert, os.path.join(CERTS_DIR, "rogue_ca.crt"))
    save_private_key_pem(rogue_ca_key, os.path.join(CERTS_DIR, "rogue_ca.key"))

    save_certificate_pem(rogue_client_cert, os.path.join(CERTS_DIR, "rogue_client.crt"))
    save_private_key_pem(rogue_client_key, os.path.join(CERTS_DIR, "rogue_client.key"))

    save_certificate_pem(rogue_server_cert, os.path.join(CERTS_DIR, "rogue_server.crt"))
    save_private_key_pem(rogue_server_key, os.path.join(CERTS_DIR, "rogue_server.key"))

    return (
        os.path.join(CERTS_DIR, "rogue_ca.crt"),
        os.path.join(CERTS_DIR, "rogue_client.crt"),
        os.path.join(CERTS_DIR, "rogue_client.key"),
        os.path.join(CERTS_DIR, "rogue_server.crt"),
        os.path.join(CERTS_DIR, "rogue_server.key")
    )


def initialize_full_pki() -> dict:
    """
    Qué hace:
        Ejecuta la inicialización completa de la infraestructura PKI institucional de U-Secure.
    Cuál es su función:
        Automatizar el aprovisionamiento de la Root CA, el servidor VPN, los usuarios oficiales
        precargados (PDI, PTGAS, Investigador, Estudiante) y el entorno de pruebas maliciosas.
    Cómo lo hace:
        Coordina las llamadas a create_root_ca, issue_server_certificate, issue_client_certificate
        y create_rogue_attacker_pki, retornando un diccionario con todas las rutas generadas.
    """
    print("[*] Inicializando Infraestructura PKI Corporativa de U-Secure...")

    # 1. Creamos la CA Raíz
    ca_key, ca_cert, ca_k_path, ca_c_path = create_root_ca()
    print(f"    [+] U-Secure Root CA generada: {ca_c_path}")

    # 2. Emitimos el certificado del servidor VPN
    srv_key, srv_cert, srv_k_path, srv_c_path = issue_server_certificate(ca_key, ca_cert)
    print(f"    [+] Servidor VPN Certificate generado: {srv_c_path}")

    # 3. Emitimos certificados para los roles universitarios precargados (RF5)
    roles = [
        {"user": "carmen_pdi", "role": "PDI", "email": "carmen.pdi@usecure.edu.es"},
        {"user": "manuel_ptgas", "role": "PTGAS", "email": "manuel.ptgas@usecure.edu.es"},
        {"user": "lucia_inv", "role": "Investigador", "email": "lucia.investigacion@usecure.edu.es"},
        {"user": "eval_user", "role": "Auditor", "email": "eval.user@usecure.edu.es"},
    ]

    client_certs = {}
    for r in roles:
        ck, cc, ck_path, cc_path = issue_client_certificate(
            ca_key, ca_cert, r["user"], r["role"], r["email"]
        )
        client_certs[r["user"]] = {"cert": cc_path, "key": ck_path, "role": r["role"]}
        print(f"    [+] Certificado BYOD emitido para [{r['role']}] {r['user']}: {cc_path}")

    # 4. Generamos infraestructura maliciosa (Rogue) para pruebas de pentesting
    rogue_paths = create_rogue_attacker_pki()
    print(f"    [+] Infraestructura Rogue (Pentest) generada: {rogue_paths[1]}")

    print("[OK] Infraestructura de Clave Pública desplegada con éxito.")
    return {
        "ca_cert": ca_c_path,
        "ca_key": ca_k_path,
        "server_cert": srv_c_path,
        "server_key": srv_k_path,
        "clients": client_certs,
        "rogue": rogue_paths
    }


if __name__ == "__main__":
    # Si se ejecuta directamente, inicializamos la PKI de pruebas
    initialize_full_pki()
