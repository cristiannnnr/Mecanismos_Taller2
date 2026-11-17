# Taller 2 — Mecanismos de seguridad para redes IEEE 802.3 con servidores TCP/IP

Universidad Distrital Francisco José de Caldas · Ingeniería de Sistemas
Docente: Octavio José Salcedo Parra

Laboratorio académico. No se generó tráfico de ataque contra ningún sistema: las
capturas son sintéticas, los escenarios simulados están señalados en el informe
y la evidencia real proviene del equipo propio.

## Entregables

| Entregable de la guía | Dónde está |
|---|---|
| Informe técnico con resumen ejecutivo y alcance | `PDF_Informe_Taller2_Seguridad_v2.pdf` (fuente: `Informe_Taller2_Seguridad_v2.md`) |
| Diez fichas de caso, reglas de detección y conclusiones | Dentro del informe, Parte I |
| Capturas, figuras y PCAP sintéticas | `evidencias/` |
| Hashes SHA-256 de las evidencias | `evidencias/00_INDICE_HASHES_v2.txt` |
| Script reproducible del Caso 4 (IA/ML) | `caso4_ml/` |
| Parte II: sistema de rastreo por consentimiento | `parte2/` (backend, frontend y bot de Telegram) |

## Reproducir el análisis de la Parte I

`analizar_pcaps.py` solo usa la biblioteca estándar de Python.

```
python analizar_pcaps.py            # todos los casos con PCAP (1, 2, 5, 7 y 8)
python analizar_pcaps.py caso1      # un caso
python analizar_pcaps.py hashes     # SHA-256 de todas las evidencias
```

Caso 4 (requiere `pip install -r caso4_ml/requirements.txt`):

```
python caso4_ml/anomaly_detector.py
python caso4_ml/comparar_linea_base.py
```

Las PCAP se generaron con `generar_evidencias.py` (requiere Scapy y matplotlib).

## Ejecutar la Parte II

```
cd parte2/backend
pip install -r requirements.txt
uvicorn main:app --port 8000
```

Luego abrir `parte2/frontend/index.html` en el navegador. Para el bot, copiar
`parte2/telegram_bot/.env.example` a `.env`, poner el token de BotFather y
ejecutar `python bot.py`.

El sistema solo registra la ubicación que el titular del número envía
voluntariamente tras aceptar el consentimiento. Es un prototipo: la revisión de
seguridad del informe lista los puntos pendientes antes de cualquier uso real,
por lo que debe usarse únicamente con números de prueba.
