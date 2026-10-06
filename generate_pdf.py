#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
GENERADOR DE INFORME PDF OFICIAL - PAI 2 (BYODSEC)
Módulo: generate_pdf.py
Equipo: Security Team 3 (Grupo 3)
Asignatura: Seguridad en Sistemas Informáticos y en Internet - PAI 2 (BYODSEC)
Fecha: Octubre 2026
========================================================================================
Descripción General:
Este script automatiza la conversión del informe técnico en Markdown (INFORME-PAI2-ST3.md)
a formato PDF institucional (INFORME-PAI2-ST3.pdf) cumpliendo con el límite estricto de
15 páginas fijado por las normas de entrega de la asignatura mediante Brave/Chromium headless.
========================================================================================
"""

import os
import sys
import re
import subprocess
import markdown

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MD_PATH = os.path.join(BASE_DIR, "INFORME-PAI2-ST3.md")
PDF_PATH = os.path.join(BASE_DIR, "INFORME-PAI2-ST3.pdf")
HTML_TEMP = os.path.join(BASE_DIR, "informe_temp.html")


def convert_markdown_to_pdf():
    """
    Convierte INFORME-PAI2-ST3.md a INFORME-PAI2-ST3.pdf con estilos profesionales.
    """
    if not os.path.exists(MD_PATH):
        print(f"[!] Error: No se encontró el archivo Markdown en {MD_PATH}")
        sys.exit(1)

    with open(MD_PATH, "r", encoding="utf-8") as f:
        text = f.read()

    # Sustitución de callouts de GitHub por bloques visuales con clase CSS
    text = re.sub(
        r'> \[!IMPORTANT\]\n((?:> .*\n?)+)',
        lambda m: '<div class="callout callout-important"><strong>AVISO DE SEGURIDAD CRÍTICO:</strong><br/>' + m.group(1).replace('> ', '') + '</div>\n',
        text
    )
    text = re.sub(
        r'> \[!NOTE\]\n((?:> .*\n?)+)',
        lambda m: '<div class="callout callout-note"><strong>NOTA TÉCNICA:</strong><br/>' + m.group(1).replace('> ', '') + '</div>\n',
        text
    )
    text = re.sub(
        r'> \[!WARNING\]\n((?:> .*\n?)+)',
        lambda m: '<div class="callout callout-warning"><strong>ADVERTENCIA:</strong><br/>' + m.group(1).replace('> ', '') + '</div>\n',
        text
    )

    body_html = markdown.markdown(text, extensions=["tables", "fenced_code", "extra", "sane_lists"])

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>INFORME-PAI2-ST3 - Auditoría de Ciberseguridad U-Secure</title>
<style>
  @page {{
    size: A4;
    margin: 16mm 14mm 16mm 14mm;
    @bottom-right {{
      content: "Página " counter(page) " de " counter(pages);
      font-size: 8pt;
      color: #64748b;
    }}
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    color: #1e293b;
    line-height: 1.45;
    font-size: 9.2pt;
  }}
  h1 {{
    font-size: 15.5pt;
    color: #0f172a;
    border-bottom: 2px solid #0284c7;
    padding-bottom: 4px;
    margin-top: 14px;
    margin-bottom: 6px;
    page-break-after: avoid;
  }}
  h2 {{
    font-size: 12.5pt;
    color: #0369a1;
    border-bottom: 1px solid #cbd5e1;
    padding-bottom: 3px;
    margin-top: 12px;
    margin-bottom: 5px;
    page-break-after: avoid;
  }}
  h3 {{
    font-size: 10.5pt;
    color: #0284c7;
    margin-top: 10px;
    margin-bottom: 4px;
    page-break-after: avoid;
  }}
  h4 {{
    font-size: 9.8pt;
    color: #334155;
    margin-top: 8px;
    margin-bottom: 2px;
    page-break-after: avoid;
  }}
  p, ul, ol {{
    margin-top: 3px;
    margin-bottom: 4px;
  }}
  li {{
    margin-bottom: 2px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 6px 0;
    font-size: 8.2pt;
    page-break-inside: avoid;
  }}
  th, td {{
    border: 1px solid #cbd5e1;
    padding: 3.5px 5.5px;
    text-align: left;
    vertical-align: top;
  }}
  th {{
    background-color: #f1f5f9;
    color: #0f172a;
    font-weight: 600;
  }}
  tr:nth-child(even) td {{
    background-color: #f8fafc;
  }}
  code {{
    font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
    font-size: 8.2pt;
    background-color: #f1f5f9;
    padding: 1px 3px;
    border-radius: 3px;
    color: #094067;
  }}
  pre {{
    background-color: #f8fafc;
    border: 1px solid #e2e8f0;
    border-left: 3px solid #0284c7;
    padding: 6px 8px;
    border-radius: 4px;
    font-size: 7.8pt;
    line-height: 1.25;
    overflow-x: auto;
    margin: 5px 0;
    page-break-inside: avoid;
    white-space: pre-wrap;
    word-break: break-all;
  }}
  pre code {{
    background: none;
    padding: 0;
    color: #1e293b;
    font-size: 7.8pt;
  }}
  .callout {{
    padding: 7px 10px;
    margin: 6px 0;
    border-radius: 4px;
    font-size: 8.5pt;
    page-break-inside: avoid;
  }}
  .callout-important {{
    background-color: #eff6ff;
    border-left: 4px solid #3b82f6;
    color: #1e3a8a;
  }}
  .callout-note {{
    background-color: #f0fdf4;
    border-left: 4px solid #22c55e;
    color: #14532d;
  }}
  .callout-warning {{
    background-color: #fffbeb;
    border-left: 4px solid #f59e0b;
    color: #78350f;
  }}
  blockquote {{
    border-left: 3px solid #94a3b8;
    margin: 5px 0;
    padding-left: 8px;
    color: #475569;
    font-style: italic;
  }}
  hr {{
    border: 0;
    border-top: 1px solid #e2e8f0;
    margin: 8px 0;
  }}
</style>
</head>
<body>
{body_html}
</body>
</html>"""

    with open(HTML_TEMP, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[*] Compilando PDF mediante Brave headless...")
    cmd = [
        "brave",
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        f"--print-to-pdf={PDF_PATH}",
        HTML_TEMP
    ]
    subprocess.run(cmd, check=True)

    # Limpiamos archivo temporal
    if os.path.exists(HTML_TEMP):
        os.remove(HTML_TEMP)

    if os.path.exists(PDF_PATH):
        pdfinfo = subprocess.check_output(["pdfinfo", PDF_PATH], text=True)
        pages_match = re.search(r"Pages:\s+(\d+)", pdfinfo)
        pages = pages_match.group(1) if pages_match else "?"
        size_kb = os.path.getsize(PDF_PATH) / 1024
        print(f"[OK] Documento PDF generado exitosamente: {PDF_PATH}")
        print(f"     Páginas: {pages} (Límite normativo: máx. 15 páginas) | Tamaño: {size_kb:.1f} KB")


if __name__ == "__main__":
    convert_markdown_to_pdf()
