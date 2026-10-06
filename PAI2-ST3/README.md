# PROYECTO BYODSEC (PAI 2) - UNIVERSIDAD PÚBLICA U-SECURE
## Road Warrior VPN SSL/TLS 1.3 con Autenticación Mutua (mTLS)
### E.T.S. Ingeniería Informática — Universidad de Sevilla
**Equipo:** Security Team 3 (Grupo 3)  
**Analistas de Seguridad:** Kleber Leonardo de Carvalho, Paula Benítez, Luigui Juan, Guillermo Ramos.  
**Convocatoria:** Curso Académico 2026 / 2027  
**Fecha de Entrega Oficial:** 27 de octubre de 2026 (23:59 h)

---

## 1. Descripción del Repositorio
Este entregable contiene la implementación completa, suite de pruebas automatizadas, auditoría criptográfica con Hashcat y capturas de tráfico PCAP para la pasarela **Road Warrior VPN SSL/TLS 1.3** de la Universidad Pública U-Secure.

El sistema garantiza confidencialidad, integridad, autenticación mutua y secreto perfecto hacia adelante (PFS) mediante **TLS 1.3 estricto** y **mTLS obligatorio** para dispositivos personales (BYOD) del personal docente (PDI), administración (PTGAS) e investigadores.

---

## 2. Estructura de Ficheros

```
PAI2-ST3/
├── pki_manager.py           # Autoridad de Certificación (CA), emisión de certificados X.509 v3 y PKI Rogue
├── database.py              # Base de datos SQLite, PBKDF2 (600.000 iteraciones), pool virtual y auditoría
├── vpn_server.py            # Servidor Gateway VPN Road Warrior en TLS 1.3 mTLS (Puerto 8443) con RBAC
├── vpn_client.py            # Cliente BYOD interactivo y programático con autenticación en dos capas (RF2)
├── test_unauthorized_cert.py# PoC Ataque 1: Rechazo de certificado no autorizado / Rogue CA
├── test_no_cert.py          # PoC Ataque 2: Rechazo de conexión sin certificado de cliente
├── test_rogue_server.py     # PoC Ataque 3: Detección y rechazo de gateway falso / Evil Twin (+10% Extra)
├── hashcat_audit.py         # Auditoría criptográfica con Hashcat (Modos 10900/1450) y justificación de mTLS
├── benchmark_concurrency.py # Estudio experimental comparativo de 300 sesiones concurrentes (RS3)
├── run_all_tests.py         # Suite integral de validación automatizada (12 tests, 100% cobertura)
├── certs/                   # Almacén de certificados X.509 v3 y claves privadas RSA
│   ├── ca.crt / ca.key
│   ├── server.crt / server.key
│   ├── client_carmen_pdi.crt / client_carmen_pdi.key
│   ├── client_manuel_ptgas.crt / client_manuel_ptgas.key
│   ├── client_lucia_inv.crt / client_lucia_inv.key
│   ├── client_eval_user.crt / client_eval_user.key
│   └── rogue_*.crt / rogue_*.key
├── data/                    # Directorio de datos (base de datos usecure_vpn.db y targets Hashcat)
├── evidencias/              # Trazas de tráfico de red en formato .pcap (Wireshark / TShark)
│   └── vpn_tls13_traffic.pcap
└── logs/                    # Archivos de registro y auditoría
    ├── server.log           # Log continuo de eventos del gateway VPN
    └── test_execution.log   # Salida completa de la batería de pruebas (100% superadas)
```

---

## 3. Guía de Despliegue Rápido

### Requisitos Previos:
- Sistema operativo GNU/Linux.
- Python 3.10 o superior (con librería estándar `ssl`, `socket`, `sqlite3`, `secrets` y paquete `cryptography`).
- `tshark` / `wireshark` (para captura e inspección de tráfico de red).
- `hashcat` (para auditoría de credenciales).

### 1. Inicializar la PKI Corporativa:
```bash
python3 pki_manager.py
```

### 2. Inicializar la Base de Datos y Precarga de Usuarios (RF5):
```bash
python3 database.py
```

### 3. Iniciar el Servidor VPN Road Warrior:
```bash
python3 vpn_server.py
```

### 4. Conectar un Cliente BYOD (Menú Interactivo):
```bash
python3 vpn_client.py
```

### 5. Ejecutar la Suite Completa de Seguridad y Tests:
```bash
python3 run_all_tests.py
```

### 6. Ejecutar el Benchmark de Concurrencia (300 Usuarios - RS3):
```bash
python3 benchmark_concurrency.py
```

### 7. Ejecutar la Auditoría Criptográfica con Hashcat:
```bash
python3 hashcat_audit.py
```
