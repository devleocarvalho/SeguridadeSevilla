"""
Mede o tempo das respostas do servidor a assinaturas HMAC inválidas.

Como executar no Kali:
1. Em um terminal, inicie o servidor: python3 Servidor.py
2. Em outro terminal, na pasta do projeto, rode:
   export SECBANK_SERVER_PORT=8081
   python3 4-benchmark_timing.py
   (Use a porta 8081 se o servidor também estiver configurado nessa porta.)
3. O teste faz dez medições com erro no início e dez com erro no final
   da assinatura. Todas as requisições devem receber HTTP 403.
4. Para observar o tráfego no Wireshark, capture na interface de loopback
   e use o filtro: tcp.port == 8081

Os tempos variam com a carga e o sistema operacional. A medição é uma
demonstração simples, não prova sozinha a existência de uma fuga de segredo.
"""

import json
import os
import statistics
import time
import urllib.error
import urllib.request
import uuid

import hasher


SERVER_URL = (
    f"http://127.0.0.1:"
    f"{os.environ.get('SECBANK_SERVER_PORT', os.environ.get('SECBANK_PORT', '8080'))}"
    "/signin"
)
ITERACIONES = 10


def medir_respuesta(posicion_error: str) -> float:
    # Cambia un solo carácter de una firma válida para medir la respuesta real.
    datos = json.dumps(
        {"usuario": "prueba_timing", "password": "no_se_guarda"}
    ).encode("utf-8")
    nonce = str(uuid.uuid4())
    timestamp = str(time.time())
    mensaje = datos + nonce.encode("utf-8") + timestamp.encode("utf-8")
    firma = hasher.crear_hash_signature(mensaje)

    indice = 0 if posicion_error == "inicio" else len(firma) - 1
    caracter = "0" if firma[indice] != "0" else "1"
    firma_alterada = firma[:indice] + caracter + firma[indice + 1 :]

    request = urllib.request.Request(
        SERVER_URL,
        data=datos,
        headers={
            "Content-Type": "application/json",
            "X-Signature": firma_alterada,
            "X-Nonce": nonce,
            "X-Timestamp": timestamp,
        },
        method="POST",
    )
    inicio = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=5) as respuesta:
            codigo = respuesta.status
            respuesta.read()
    except urllib.error.HTTPError as error:
        codigo = error.code
        error.read()
    duracion = time.perf_counter() - inicio

    if codigo != 403:
        raise RuntimeError(
            f"Se esperaba HTTP 403 para una firma incorrecta; llegó HTTP {codigo}."
        )
    return duracion


def main() -> None:
    tiempos_inicio = []
    tiempos_final = []
    print("Prueba de tiempo real contra el servidor local.")
    print("Cada petición lleva una firma incorrecta y debe recibir HTTP 403.")
    print("Las peticiones aparecerán en Wireshark como tráfico HTTP.")

    for _ in range(ITERACIONES):
        tiempos_inicio.append(medir_respuesta("inicio"))
        tiempos_final.append(medir_respuesta("final"))

    mediana_inicio = statistics.median(tiempos_inicio)
    mediana_final = statistics.median(tiempos_final)
    print(f"\nPeticiones por caso: {ITERACIONES}")
    print(f"Error al inicio de la firma: mediana {mediana_inicio * 1000:.3f} ms")
    print(f"Error al final de la firma:  mediana {mediana_final * 1000:.3f} ms")
    print(
        "\nLa red y el sistema operativo afectan los tiempos. "
        "Esta medición no demuestra que se haya descubierto un secreto; "
        "solo permite observar la respuesta del servidor."
    )


if __name__ == "__main__":
    main()
