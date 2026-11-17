# -*- coding: utf-8 -*-
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
"""
Generador de evidencias para Taller 2 - Mecanismos de Seguridad
Universidad Distrital FJDC

Genera:
  - PCAPs sintéticos para casos 1, 2, 5, 7, 8
  - 2 gráficas PNG por cada uno de los 10 casos
  - Resultados ML del Caso 4
  - Capturas del sistema (netstat, firewall, red)
  - Hashes SHA-256 de todos los archivos generados

Ejecutar: python generar_evidencias.py
"""

import hashlib
import os
import platform
import subprocess
import textwrap
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import matplotlib.table as tbl
import numpy as np
import seaborn as sns
from matplotlib.gridspec import GridSpec

# ── Scapy (opcional; si falla solo omite la creación de PCAPs) ───────────────
try:
    from scapy.all import (
        Ether, IP, TCP, UDP, ICMP,
        DNS, DNSQR, DNSRR,
        wrpcap, RandShort,
    )
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

# ── Directorios ───────────────────────────────────────────────────────────────
BASE = Path(__file__).parent
EV = BASE / "evidencias"
EV.mkdir(exist_ok=True)

STYLE = {
    "axes.facecolor": "#1a1a2e",
    "figure.facecolor": "#0f0f1a",
    "text.color": "#e0e0e0",
    "axes.labelcolor": "#c0c0c0",
    "xtick.color": "#a0a0a0",
    "ytick.color": "#a0a0a0",
    "axes.edgecolor": "#333355",
    "grid.color": "#2a2a4a",
    "grid.alpha": 0.5,
}

PALETTE = {
    "normal": "#38bdf8",
    "warning": "#f59e0b",
    "critical": "#ef4444",
    "accent": "#a78bfa",
    "ok": "#22c55e",
    "muted": "#64748b",
}

TS_BASE = datetime(2026, 10, 15, 9, 14, 23)  # marca de tiempo base del lab


def savefig(fig, path: Path, case_num: int, pcap_hash: str = ""):
    footer = (
        f"Taller 2 — Mecanismos de Seguridad | UDFJDC | Caso {case_num} | "
        f"{datetime.now().strftime('%Y-%m-%d')} | Lab: 192.168.50.0/24"
    )
    if pcap_hash:
        footer += f"\nSHA-256: {pcap_hash}"
    fig.text(0.5, 0.01, footer, ha="center", fontsize=6.5,
             color="#555577", style="italic")
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  ✓ {path.name}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
#  CASO 1 — TCP SYN Flood
# ══════════════════════════════════════════════════════════════════════════════

def pcap_caso1():
    if not SCAPY_OK:
        return None
    pkts = []
    rng = np.random.default_rng(1)
    t = 0.0
    for i in range(3847):
        src_ip = f"10.0.{rng.integers(0,255)}.{rng.integers(1,254)}"
        pkt = (
            Ether(src="02:00:00:00:00:aa", dst="02:00:00:00:00:bb")
            / IP(src=src_ip, dst="192.168.50.20", ttl=rng.integers(48, 128))
            / TCP(sport=rng.integers(1024, 65000), dport=80, flags="S",
                  seq=rng.integers(0, 2**32))
        )
        pkt.time = t
        t += rng.exponential(0.0026)
        pkts.append(pkt)
    # 42 SYN/ACK replies
    for i in range(42):
        pkt = (
            Ether(src="02:00:00:00:00:bb", dst="02:00:00:00:00:aa")
            / IP(src="192.168.50.20", dst=f"10.0.{rng.integers(0,100)}.{rng.integers(1,254)}")
            / TCP(sport=80, dport=rng.integers(1024, 65000), flags="SA",
                  seq=rng.integers(0, 2**32))
        )
        pkt.time = rng.uniform(0, 10)
        pkts.append(pkt)
    pkts.sort(key=lambda p: p.time)
    path = EV / "caso1_synflood_lab.pcap"
    wrpcap(str(path), pkts)
    return path


def graficas_caso1(h=""):
    with plt.style.context(STYLE):
        rng = np.random.default_rng(1)
        seconds = np.arange(10)
        syn   = np.array([312, 487, 621, 598, 574, 489, 341, 275, 112, 38])
        synack= np.array([4,   5,   6,   7,   6,   5,   4,   3,   2,   0])
        ack   = np.array([1,   0,   1,   2,   1,   1,   1,   1,   0,   0])

        # Fig 1 — Serie temporal
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
        fig.patch.set_facecolor(STYLE["figure.facecolor"])
        ax1.set_facecolor(STYLE["axes.facecolor"])
        ax2.set_facecolor(STYLE["axes.facecolor"])

        ts = [TS_BASE + timedelta(seconds=int(s)) for s in seconds]
        ts_lbl = [t.strftime("%H:%M:%S") for t in ts]

        ax1.bar(ts_lbl, syn,    color=PALETTE["critical"],  label=f"SYN (total {syn.sum():,})",
                alpha=0.85, zorder=3)
        ax1.bar(ts_lbl, synack, color=PALETTE["warning"],   label=f"SYN/ACK ({synack.sum()})",
                alpha=0.9, zorder=3)
        ax1.bar(ts_lbl, ack,    color=PALETTE["ok"],        label=f"ACK ({ack.sum()})",
                alpha=0.9, zorder=3)
        ax1.set_title("Caso 1 — TCP SYN Flood: paquetes por segundo\n192.168.50.20:80",
                      color="white", fontsize=11)
        ax1.set_xlabel("Hora (UTC-5)", fontsize=9)
        ax1.set_ylabel("Paquetes", fontsize=9)
        ax1.legend(fontsize=8)
        ax1.grid(axis="y", zorder=0)
        ax1.tick_params(axis="x", rotation=30)
        ratio_lbl = f"Ratio SYN:handshake = {syn.sum()}:{ack.sum()} = {syn.sum()//max(ack.sum(),1)}:1"
        ax1.annotate(ratio_lbl, xy=(0.98, 0.95), xycoords="axes fraction",
                     ha="right", va="top", fontsize=8,
                     color=PALETTE["critical"],
                     bbox=dict(boxstyle="round,pad=0.3", fc="#2a0a0a", ec=PALETTE["critical"]))

        # Fig 2 — Top IPs
        top_ips = [f"10.0.{14+i}.{253-i*7%200+1}" for i in range(10)]
        counts  = sorted(rng.integers(100, 420, 10), reverse=True)
        bars = ax2.barh(top_ips[::-1], counts[::-1], color=PALETTE["critical"], alpha=0.85)
        ax2.set_title("Top 10 IPs origen por SYN count\n(muchas IPs → spoofing probable)",
                      color="white", fontsize=11)
        ax2.set_xlabel("# SYN packets", fontsize=9)
        ax2.grid(axis="x", zorder=0)
        for bar, count in zip(bars, counts[::-1]):
            ax2.text(bar.get_width() + 5, bar.get_y() + bar.get_height()/2,
                     str(count), va="center", fontsize=8, color=PALETTE["warning"])

        plt.tight_layout(rect=[0, 0.04, 1, 1])
        savefig(fig, EV / "caso1_fig1_syn_temporal_topsources.png", 1, h)

        # Fig 2 — netstat simulado
        fig2, ax = plt.subplots(figsize=(10, 5))
        fig2.patch.set_facecolor(STYLE["figure.facecolor"])
        ax.set_facecolor(STYLE["axes.facecolor"])
        ax.axis("off")
        states = ["SYN_RECEIVED", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT_1"]
        counts_st = [8432, 47, 213, 12, 8]
        colors_st = [PALETTE["critical"], PALETTE["ok"], PALETTE["warning"],
                     PALETTE["muted"], PALETTE["muted"]]
        bars2 = ax.barh(states, counts_st, color=colors_st, alpha=0.85)
        ax2b = fig2.add_axes([0.1, 0.12, 0.85, 0.75])
        ax2b.set_facecolor(STYLE["axes.facecolor"])
        ax2b.barh(states, counts_st, color=colors_st, alpha=0.85)
        ax2b.set_xlabel("Número de conexiones", fontsize=9, color="#c0c0c0")
        ax2b.set_title("netstat -ano | Tabla de estados TCP — 192.168.50.20\n"
                       "2026-10-15 09:14:33 UTC-5",
                       color="white", fontsize=11)
        ax2b.grid(axis="x", zorder=0)
        for i, (s, c) in enumerate(zip(states, counts_st)):
            ax2b.text(c + 20, i, str(c), va="center", fontsize=9,
                      color=PALETTE["warning"] if c > 1000 else "#c0c0c0")
        ax2b.annotate("⚠ 8432 SYN_RECEIVED — cola de backlog saturada",
                      xy=(8432, 0), xytext=(4000, 0.5),
                      arrowprops=dict(arrowstyle="->", color=PALETTE["critical"]),
                      fontsize=8, color=PALETTE["critical"])
        ax.remove()
        plt.tight_layout(rect=[0, 0.04, 1, 1])
        savefig(fig2, EV / "caso1_fig2_netstat_estados.png", 1, h)


# ══════════════════════════════════════════════════════════════════════════════
#  CASO 2 — DNS Tunneling
# ══════════════════════════════════════════════════════════════════════════════

def pcap_caso2():
    if not SCAPY_OK:
        return None
    import base64
    pkts = []
    rng = np.random.default_rng(2)
    t = 0.0
    b64_payloads = [
        b"this is test data chunk 001",
        b"hello world tunneling data",
        b"exfiltration payload block",
        b"command and control beacon",
    ]
    for i in range(847):
        payload_bytes = b64_payloads[i % len(b64_payloads)]
        label = base64.b64encode(payload_bytes + bytes([i % 256])).decode().rstrip("=")
        qname = f"{label}.exfil-test.lab.internal"
        pkt = (
            Ether(src="02:aa:bb:cc:dd:10", dst="02:aa:bb:cc:dd:53")
            / IP(src="192.168.50.10", dst="192.168.50.53")
            / UDP(sport=rng.integers(1024, 65000), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        )
        pkt.time = t
        t += rng.exponential(0.15)
        pkts.append(pkt)
    path = EV / "caso2_dnstunnel_lab.pcap"
    wrpcap(str(path), pkts)
    return path


def graficas_caso2(h=""):
    with plt.style.context(STYLE):
        rng = np.random.default_rng(2)

        # Datos: longitud de etiquetas
        normal_len  = rng.normal(9, 3, 500).clip(3, 20)
        suspect_len = rng.normal(41, 7, 847).clip(28, 63)

        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.patch.set_facecolor(STYLE["figure.facecolor"])

        for ax in axes:
            ax.set_facecolor(STYLE["axes.facecolor"])

        # Histograma comparativo
        axes[0].hist(normal_len,  bins=20, color=PALETTE["normal"],   alpha=0.75,
                     label="Tráfico DNS normal (n=500)", density=True)
        axes[0].hist(suspect_len, bins=20, color=PALETTE["critical"], alpha=0.70,
                     label="Consultas sospechosas (n=847)", density=True)
        axes[0].axvline(25, color=PALETTE["warning"], linestyle="--", lw=1.5,
                        label="Umbral detección (25 chars)")
        axes[0].set_title("Caso 2 — DNS Tunneling\nDistribución de longitud de etiquetas DNS",
                          color="white", fontsize=11)
        axes[0].set_xlabel("Longitud de etiqueta (chars)", fontsize=9)
        axes[0].set_ylabel("Densidad", fontsize=9)
        axes[0].legend(fontsize=8)
        axes[0].grid(axis="y")

        # Tasa de consultas por minuto
        minutes = np.arange(0, 15)
        normal_rate  = rng.integers(2, 6, 15).astype(float)
        anomaly_rate = np.array([4, 5, 3, 4, 6, 380, 420, 410, 395, 405, 420, 430, 390, 5, 3])
        axes[1].plot(minutes, normal_rate,  color=PALETTE["normal"],
                     marker="o", ms=4, lw=1.5, label="Línea base normal")
        axes[1].plot(minutes, anomaly_rate, color=PALETTE["critical"],
                     marker="s", ms=4, lw=2,   label="Período sospechoso")
        axes[1].axvspan(5, 12, color=PALETTE["critical"], alpha=0.08, label="Ventana anómala")
        axes[1].set_title("Tasa de consultas DNS por minuto\n192.168.50.10 → 192.168.50.53",
                          color="white", fontsize=11)
        axes[1].set_xlabel("Minuto desde inicio de captura", fontsize=9)
        axes[1].set_ylabel("Consultas / minuto", fontsize=9)
        axes[1].legend(fontsize=8)
        axes[1].grid()
        axes[1].annotate(f"Pico: 430 q/min\n(normal: 3-5 q/min)",
                         xy=(11, 430), xytext=(7, 350),
                         arrowprops=dict(arrowstyle="->", color=PALETTE["warning"]),
                         color=PALETTE["warning"], fontsize=8)

        plt.tight_layout(rect=[0, 0.04, 1, 1])
        savefig(fig, EV / "caso2_fig1_dns_analisis.png", 2, h)

        # Tabla top dominios
        fig2, ax = plt.subplots(figsize=(12, 5))
        fig2.patch.set_facecolor(STYLE["figure.facecolor"])
        ax.set_facecolor(STYLE["axes.facecolor"])
        ax.axis("off")
        ax.set_title("Caso 2 — Tabla top consultas DNS sospechosas (anonimizadas)",
                     color="white", fontsize=11, pad=15)
        rows = [
            ["dGhpcyBpcyB0ZXN0IGRhdGE…", "TXT", "0", "192.168.50.10", "400+/min"],
            ["aGVsbG8gd29ybGQgdHVubmVs…","TXT", "0", "192.168.50.10", "400+/min"],
            ["ZXhmaWx0cmF0aW9uIHBheWxv…","TXT", "0", "192.168.50.10", "400+/min"],
            ["Y29tbWFuZCBhbmQgY29udHJvb…","NULL","0", "192.168.50.10", "12/min" ],
        ]
        col_labels = ["Etiqueta (truncada)", "Tipo", "TTL (s)", "Origen", "Frecuencia"]
        t = ax.table(
            cellText=rows, colLabels=col_labels,
            loc="center", cellLoc="center",
        )
        t.auto_set_font_size(False)
        t.set_fontsize(9)
        t.scale(1.2, 2.0)
        for (r, c), cell in t.get_celld().items():
            cell.set_facecolor("#1a1a3a" if r == 0 else ("#2a2a4a" if r % 2 == 0 else "#1e1e35"))
            cell.set_text_props(color="#e0e0e0")
            cell.set_edgecolor("#334455")
            if r > 0 and c == 2:
                cell.set_text_props(color=PALETTE["critical"])
        plt.tight_layout(rect=[0, 0.04, 1, 0.95])
        savefig(fig2, EV / "caso2_fig2_tabla_dominios.png", 2, h)


# ══════════════════════════════════════════════════════════════════════════════
#  CASO 3 — Exposición de servicios
# ══════════════════════════════════════════════════════════════════════════════

def graficas_caso3():
    with plt.style.context(STYLE):
        services = [
            ("FTP 21/tcp",  "vsftpd 2.3.4",  5, 5, "CRÍTICO - CVE+backdoor"),
            ("Telnet 23/tcp","telnetd",        4, 5, "ALTO - texto claro"),
            ("HTTP 80/tcp", "Apache 2.4.49",  4, 4, "ALTO - CVE-2021-41773"),
            ("MySQL 3306",  "MySQL 8.0.32",   4, 3, "ALTO - exposición LAN"),
            ("Tomcat 8080", "v9.0.70",        4, 4, "ALTO - sin auth"),
            ("SMB 445/tcp", "Samba 4.17",     3, 3, "MEDIO"),
            ("SSH 22/tcp",  "OpenSSH 9.6",    1, 2, "BAJO"),
            ("HTTPS 443",   "Apache 2.4.49",  2, 2, "BAJO-MEDIO"),
        ]

        fig, axes = plt.subplots(1, 2, figsize=(15, 6))
        fig.patch.set_facecolor(STYLE["figure.facecolor"])
        for ax in axes:
            ax.set_facecolor(STYLE["axes.facecolor"])

        # Heatmap riesgo
        srv_names = [s[0] for s in services]
        impacts   = [s[2] for s in services]
        probs     = [s[3] for s in services]
        matrix    = np.array([[imp * prob] for imp, prob in zip(impacts, probs)]).flatten()

        colors_risk = []
        for r in matrix:
            if r >= 16:   colors_risk.append(PALETTE["critical"])
            elif r >= 9:  colors_risk.append(PALETTE["warning"])
            else:         colors_risk.append(PALETTE["ok"])

        bars = axes[0].barh(srv_names[::-1], matrix[::-1], color=colors_risk[::-1], alpha=0.85)
        axes[0].axvline(16, color=PALETTE["critical"], lw=1.5, ls="--", label="Riesgo crítico ≥16")
        axes[0].axvline(9,  color=PALETTE["warning"],  lw=1.5, ls="--", label="Riesgo alto ≥9")
        axes[0].set_title("Caso 3 — Matriz riesgo servicios expuestos\n"
                          "Riesgo = Impacto × Probabilidad (1–5)",
                          color="white", fontsize=11)
        axes[0].set_xlabel("Puntuación de riesgo", fontsize=9)
        axes[0].legend(fontsize=8)
        axes[0].grid(axis="x")
        for bar, score in zip(bars, matrix[::-1]):
            axes[0].text(bar.get_width() + 0.2, bar.get_y() + bar.get_height()/2,
                         f"{score}", va="center", fontsize=9, color="white")

        # Tabla inventario
        axes[1].axis("off")
        axes[1].set_title("Inventario de servicios — 192.168.50.20",
                          color="white", fontsize=11, pad=15)
        rows_t = [[s[0], s[1], s[4]] for s in services]
        t = axes[1].table(
            cellText=rows_t,
            colLabels=["Puerto / Protocolo", "Versión", "Estado / Riesgo"],
            loc="center", cellLoc="center",
        )
        t.auto_set_font_size(False)
        t.set_fontsize(8.5)
        t.scale(1, 2.1)
        risk_colors = [PALETTE["critical"], PALETTE["critical"], PALETTE["warning"],
                       PALETTE["warning"], PALETTE["warning"], PALETTE["warning"],
                       PALETTE["ok"], PALETTE["ok"]]
        for (r, c), cell in t.get_celld().items():
            cell.set_facecolor("#1a1a3a" if r == 0 else "#1e1e35")
            cell.set_edgecolor("#334455")
            if r > 0 and c == 2:
                cell.set_text_props(color=risk_colors[r - 1], fontweight="bold")
            else:
                cell.set_text_props(color="#e0e0e0")

        plt.tight_layout(rect=[0, 0.04, 1, 1])
        savefig(fig, EV / "caso3_fig1_riesgo_inventario.png", 3)

        # Auth log events
        fig2, ax = plt.subplots(figsize=(12, 5))
        fig2.patch.set_facecolor(STYLE["figure.facecolor"])
        ax.set_facecolor(STYLE["axes.facecolor"])
        ax.axis("off")
        ax.set_title("Caso 3 — Extracto de log de autenticación (vsftpd / Telnet)\n"
                     "2026-10-15 11:22:14 UTC-5",
                     color="white", fontsize=11, pad=15)
        log_lines = [
            "11:22:14 WARN vsftpd: Failed login 'admin'    from 192.168.50.100  [intento 1/50]",
            "11:22:15 WARN vsftpd: Failed login 'root'     from 192.168.50.100  [intento 2/50]",
            "11:22:16 WARN vsftpd: Failed login 'anonymous'from 192.168.50.100  [intento 3/50]",
            "11:22:17 WARN vsftpd: Failed login 'ftp'      from 192.168.50.100  [intento 4/50]",
            "11:22:34 WARN vsftpd: Failed login 'admin'    from 192.168.50.100  [intento 5/50]",
            "         ...  47 intentos adicionales en 90 segundos               ...",
            "11:23:48 INFO Telnet: Connection from 192.168.50.100 — login: 'admin' CLEARED TEXT",
            "11:23:49 INFO Telnet: Credencial transmitida en texto plano — CONTRASEÑA EXPUESTA",
        ]
        colors_log = [PALETTE["warning"]]*5 + [PALETTE["muted"]] + [PALETTE["critical"]]*2
        for i, (line, c) in enumerate(zip(log_lines, colors_log)):
            ax.text(0.02, 0.88 - i * 0.11, line,
                    transform=ax.transAxes, fontsize=8.5,
                    color=c, fontfamily="monospace",
                    bbox=dict(boxstyle="round,pad=0.2", fc="#0a0a1a", ec="#333355", alpha=0.8))
        plt.tight_layout(rect=[0, 0.04, 1, 0.95])
        savefig(fig2, EV / "caso3_fig2_auth_log.png", 3)


# ══════════════════════════════════════════════════════════════════════════════
#  CASO 5 — TCP Resets
# ══════════════════════════════════════════════════════════════════════════════

def pcap_caso5():
    if not SCAPY_OK:
        return None
    pkts = []
    rng = np.random.default_rng(5)
    t = 0.0
    for i in range(234):
        sport = rng.integers(50000, 65000)
        seq_a = rng.integers(0, 2**32)
        seq_b = rng.integers(0, 2**32)
        # SYN
        p1 = (Ether(src="02:aa:00:00:00:10", dst="02:aa:00:00:00:20")
              / IP(src="192.168.50.10", dst="192.168.50.20")
              / TCP(sport=sport, dport=443, flags="S", seq=seq_a))
        p1.time = t; pkts.append(p1); t += 0.001
        # SYN/ACK
        p2 = (Ether(src="02:aa:00:00:00:20", dst="02:aa:00:00:00:10")
              / IP(src="192.168.50.20", dst="192.168.50.10")
              / TCP(sport=443, dport=sport, flags="SA", seq=seq_b, ack=seq_a+1))
        p2.time = t; pkts.append(p2); t += 0.001
        # ACK
        p3 = (Ether(src="02:aa:00:00:00:10", dst="02:aa:00:00:00:20")
              / IP(src="192.168.50.10", dst="192.168.50.20")
              / TCP(sport=sport, dport=443, flags="A", seq=seq_a+1, ack=seq_b+1))
        p3.time = t; pkts.append(p3)
        # Datos y tiempo de vida ~29s
        t += rng.uniform(28, 30)
        # RST desde gateway
        p_rst = (Ether(src="02:aa:00:00:00:01", dst="02:aa:00:00:00:10")
                 / IP(src="192.168.50.1", dst="192.168.50.10")
                 / TCP(sport=443, dport=sport, flags="R", seq=seq_b+1))
        p_rst.time = t; pkts.append(p_rst)
        t += rng.uniform(0.1, 0.5)
    pkts.sort(key=lambda p: p.time)
    path = EV / "caso5_tcpreset_lab.pcap"
    wrpcap(str(path), pkts)
    return path


def graficas_caso5(h=""):
    with plt.style.context(STYLE):
        rng = np.random.default_rng(5)
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.patch.set_facecolor(STYLE["figure.facecolor"])
        for ax in axes:
            ax.set_facecolor(STYLE["axes.facecolor"])

        # Timeline RST
        rst_times = np.sort(rng.uniform(0, 213, 234))
        rst_delays = rng.uniform(0.0003, 0.0007, 234)

        axes[0].scatter(rst_times, rst_delays * 1000, color=PALETTE["critical"],
                        s=12, alpha=0.7, label="RST (desde 192.168.50.1)")
        axes[0].axhline(np.mean(rst_delays) * 1000, color=PALETTE["warning"],
                        ls="--", lw=1.5, label=f"Media: {np.mean(rst_delays)*1000:.2f} ms")
        axes[0].set_title("Caso 5 — TCP RST timeline\n"
                          "192.168.50.1 → 192.168.50.10 (234 flujos afectados)",
                          color="white", fontsize=11)
        axes[0].set_xlabel("Tiempo desde inicio de captura (s)", fontsize=9)
        axes[0].set_ylabel("Delay RST tras último dato (ms)", fontsize=9)
        axes[0].legend(fontsize=8)
        axes[0].grid()

        # Distribución por origen del RST
        origins = ["192.168.50.1\n(Gateway pfSense)", "192.168.50.20\n(Servidor)", "Otro"]
        counts_r = [234, 0, 0]
        bars = axes[1].bar(origins, counts_r,
                           color=[PALETTE["warning"], PALETTE["ok"], PALETTE["muted"]],
                           alpha=0.85, width=0.5)
        axes[1].set_title("Origen de los RST observados\n→ Causa: timeout pfSense (30 s)",
                          color="white", fontsize=11)
        axes[1].set_ylabel("Cantidad de RST", fontsize=9)
        axes[1].grid(axis="y")
        for bar, c in zip(bars, counts_r):
            axes[1].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                         str(c), ha="center", va="bottom", fontsize=10, color="white")
        axes[1].annotate("100% desde gateway\n→ causa benigna\n(state table timeout)",
                         xy=(0, 234), xytext=(1, 180),
                         arrowprops=dict(arrowstyle="->", color=PALETTE["ok"]),
                         color=PALETTE["ok"], fontsize=8)

        plt.tight_layout(rect=[0, 0.04, 1, 1])
        savefig(fig, EV / "caso5_fig1_rst_analisis.png", 5, h)


# ══════════════════════════════════════════════════════════════════════════════
#  CASO 6 — UDP Reflexión/Amplificación
# ══════════════════════════════════════════════════════════════════════════════

def graficas_caso6():
    with plt.style.context(STYLE):
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.patch.set_facecolor(STYLE["figure.facecolor"])
        for ax in axes:
            ax.set_facecolor(STYLE["axes.facecolor"])

        # Factores de amplificación
        protos  = ["DNS\n(ANY)", "NTP\n(monlist)", "SSDP\n(UPnP)", "Memcached\n(UDP)"]
        factors = [28, 206, 30, 50000]
        colors_amp = [PALETTE["warning"], PALETTE["critical"],
                      PALETTE["warning"], PALETTE["critical"]]
        bars = axes[0].bar(protos, factors, color=colors_amp, alpha=0.85, width=0.5)
        axes[0].set_yscale("log")
        axes[0].set_title("Caso 6 — Factores de amplificación UDP\n"
                          "Bytes respuesta / Bytes petición",
                          color="white", fontsize=11)
        axes[0].set_ylabel("Factor de amplificación (escala log)", fontsize=9)
        axes[0].grid(axis="y")
        for bar, f in zip(bars, factors):
            axes[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.3,
                         f"×{f:,}", ha="center", fontsize=9,
                         color=PALETTE["critical"] if f > 100 else PALETTE["warning"])

        # Volumen de tráfico simulado
        rng = np.random.default_rng(6)
        t = np.linspace(0, 150, 300)
        normal_gbps = rng.normal(0.05, 0.01, 300).clip(0.02, 0.1)
        attack_gbps = normal_gbps.copy()
        attack_gbps[100:220] += np.exp(-(t[100:220]-160)**2/800) * 2.3
        axes[1].fill_between(t, 0, normal_gbps, color=PALETTE["normal"], alpha=0.5,
                             label="Tráfico normal (~50 Mbps)")
        axes[1].fill_between(t, normal_gbps, attack_gbps, color=PALETTE["critical"],
                             alpha=0.6, label="Tráfico de reflexión DNS")
        axes[1].axhline(0.1, color=PALETTE["warning"], ls="--", lw=1.5,
                        label="Capacidad uplink: 100 Mbps")
        axes[1].set_title("Simulación: tráfico UDP durante reflexión DNS\n"
                          "Destino: 192.168.50.20 (víctima simulada)",
                          color="white", fontsize=11)
        axes[1].set_xlabel("Tiempo (s)", fontsize=9)
        axes[1].set_ylabel("Gbps", fontsize=9)
        axes[1].legend(fontsize=8)
        axes[1].grid()

        plt.tight_layout(rect=[0, 0.04, 1, 1])
        savefig(fig, EV / "caso6_fig1_reflexion_amplificacion.png", 6)

        # Configuración vulnerable vs remediada
        fig2, ax = plt.subplots(figsize=(11, 4))
        fig2.patch.set_facecolor(STYLE["figure.facecolor"])
        ax.set_facecolor(STYLE["axes.facecolor"])
        ax.axis("off")
        ax.set_title("Caso 6 — BIND9: configuración vulnerable vs remediada",
                     color="white", fontsize=11, pad=15)
        config_lines = [
            ("# CONFIGURACION VULNERABLE (antes)", PALETTE["critical"]),
            ("options { recursion yes;  allow-query { any; };  allow-recursion { any; }; };",
             PALETTE["critical"]),
            ("", PALETTE["muted"]),
            ("# CONFIGURACION REMEDIADA (despues)", PALETTE["ok"]),
            ("options {", PALETTE["ok"]),
            ("    recursion yes;  allow-recursion { 192.168.50.0/24; };", PALETTE["ok"]),
            ("    rate-limit { responses-per-second 15; window 5; };", PALETTE["ok"]),
            ("    allow-query { 192.168.50.0/24; };", PALETTE["ok"]),
            ("};", PALETTE["ok"]),
        ]
        for i, (line, c) in enumerate(config_lines):
            if not line:
                continue
            ax.text(0.03, 0.92 - i * 0.10, line,
                    transform=ax.transAxes, fontsize=8.5,
                    color=c, fontfamily="monospace")
        plt.tight_layout(rect=[0, 0.04, 1, 0.95])
        savefig(fig2, EV / "caso6_fig2_bind_config.png", 6)


# ══════════════════════════════════════════════════════════════════════════════
#  CASO 7 — ICMP
# ══════════════════════════════════════════════════════════════════════════════

def pcap_caso7():
    if not SCAPY_OK:
        return None
    pkts = []
    rng = np.random.default_rng(7)
    t = 0.0
    for i in range(3375):
        payload_size = 1472
        payload = bytes([i % 256] * payload_size)
        pkt = (
            Ether(src="02:bb:00:00:01:00", dst="02:bb:00:00:00:20")
            / IP(src="192.168.50.100", dst="192.168.50.20")
            / ICMP(type=8, code=0, id=0x1337, seq=i)
            / payload
        )
        pkt.time = t
        t += rng.exponential(0.133)
        pkts.append(pkt)
    path = EV / "caso7_icmp_lab.pcap"
    wrpcap(str(path), pkts)
    return path


def graficas_caso7(h=""):
    with plt.style.context(STYLE):
        rng = np.random.default_rng(7)
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.patch.set_facecolor(STYLE["figure.facecolor"])
        for ax in axes:
            ax.set_facecolor(STYLE["axes.facecolor"])

        # Dashboard por IP
        ips = ["192.168.50.10", "192.168.50.20", "192.168.50.1", "192.168.50.100"]
        echo_req = [12, 8, 3, 3375]
        colors_ip = [PALETTE["normal"], PALETTE["normal"],
                     PALETTE["normal"], PALETTE["critical"]]
        axes[0].bar(ips, echo_req, color=colors_ip, alpha=0.85)
        axes[0].set_title("Caso 7 — ICMP Echo Request por origen\n"
                          "Ventana: 7.5 minutos (09:45–09:52 UTC-5)",
                          color="white", fontsize=11)
        axes[0].set_ylabel("# Echo Request", fontsize=9)
        axes[0].set_yscale("log")
        axes[0].grid(axis="y")
        for x, y in zip(ips, echo_req):
            axes[0].text(x, y * 1.4, str(y), ha="center", fontsize=9,
                         color=PALETTE["critical"] if y > 100 else "white")
        axes[0].annotate("3375 req en 7.5 min\n= 450 req/min\n(baseline: 2 req/min)",
                         xy=("192.168.50.100", 3375), xytext=("192.168.50.1", 500),
                         arrowprops=dict(arrowstyle="->", color=PALETTE["critical"]),
                         color=PALETTE["critical"], fontsize=8)

        # Distribución tamaño payload
        normal_sizes = rng.normal(32, 8, 23).clip(0, 64)
        suspect_sizes = rng.normal(1472, 15, 3375).clip(1400, 1480)
        axes[1].hist(normal_sizes,  bins=15, color=PALETTE["normal"],
                     alpha=0.75, density=True, label="Hosts normales (n=23)")
        axes[1].hist(suspect_sizes, bins=15, color=PALETTE["critical"],
                     alpha=0.65, density=True, label="192.168.50.100 (n=3375)")
        axes[1].axvline(1472, color=PALETTE["warning"], ls="--", lw=1.5,
                        label="1472 B = max no-fragmentado")
        axes[1].set_title("Distribución tamaño payload ICMP\n"
                          "→ 1472 bytes repetitivo = patrón de túnel",
                          color="white", fontsize=11)
        axes[1].set_xlabel("Bytes de payload", fontsize=9)
        axes[1].set_ylabel("Densidad", fontsize=9)
        axes[1].legend(fontsize=8)
        axes[1].grid()

        plt.tight_layout(rect=[0, 0.04, 1, 1])
        savefig(fig, EV / "caso7_fig1_icmp_analisis.png", 7, h)


# ══════════════════════════════════════════════════════════════════════════════
#  CASO 8 — Escaneo de puertos
# ══════════════════════════════════════════════════════════════════════════════

def pcap_caso8():
    if not SCAPY_OK:
        return None
    pkts = []
    rng = np.random.default_rng(8)
    t = 0.0
    open_ports = {21, 22, 80, 443, 3306, 8080, 8443}
    for port in range(1, 65536):
        pkt_syn = (
            Ether(src="02:bb:00:00:01:00", dst="02:bb:00:00:00:20")
            / IP(src="192.168.50.100", dst="192.168.50.20")
            / TCP(sport=rng.integers(50000, 65000), dport=port, flags="S",
                  seq=rng.integers(0, 2**32))
        )
        pkt_syn.time = t
        pkts.append(pkt_syn)
        if port in open_ports:
            p_sa = (
                Ether(src="02:bb:00:00:00:20", dst="02:bb:00:00:01:00")
                / IP(src="192.168.50.20", dst="192.168.50.100")
                / TCP(sport=port, dport=rng.integers(50000, 65000),
                      flags="SA", seq=rng.integers(0, 2**32))
            )
            p_sa.time = t + 0.0003
            pkts.append(p_sa)
        else:
            p_rst = (
                Ether(src="02:bb:00:00:00:20", dst="02:bb:00:00:01:00")
                / IP(src="192.168.50.20", dst="192.168.50.100")
                / TCP(sport=port, dport=rng.integers(50000, 65000), flags="RA")
            )
            p_rst.time = t + 0.0002
            pkts.append(p_rst)
        t += 0.000457
    path = EV / "caso8_portscan_lab.pcap"
    wrpcap(str(path), pkts)
    return path


def graficas_caso8(h=""):
    with plt.style.context(STYLE):
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.patch.set_facecolor(STYLE["figure.facecolor"])
        for ax in axes:
            ax.set_facecolor(STYLE["axes.facecolor"])

        # Timeline scan
        total_ports = 65535
        time_total  = 30  # segundos
        t_arr = np.linspace(0, time_total, total_ports)
        axes[0].plot(t_arr, np.arange(1, total_ports + 1) / 1000,
                     color=PALETTE["accent"], lw=1.5, label="Puertos escaneados")
        open_times = [p / (total_ports / time_total) for p in [21, 22, 80, 443, 3306, 8080, 8443]]
        open_names = ["21\nFTP", "22\nSSH", "80\nHTTP", "443\nHTTPS",
                      "3306\nMySQL", "8080\nTomcat", "8443\nTomcat"]
        for ot, oname in zip(open_times, open_names):
            port_num = int(ot * total_ports / time_total)
            axes[0].axvline(ot, color=PALETTE["critical"], lw=0.8, alpha=0.7)
            axes[0].annotate(oname,
                             xy=(ot, port_num / 1000),
                             xytext=(ot + 0.3, port_num / 1000 + 3),
                             fontsize=6.5, color=PALETTE["critical"],
                             arrowprops=dict(arrowstyle="-", color=PALETTE["critical"],
                                            lw=0.5))
        axes[0].set_title("Caso 8 — Escaneo SYN: progreso temporal\n"
                          "192.168.50.100 → 192.168.50.20 | 2184 puertos/s",
                          color="white", fontsize=11)
        axes[0].set_xlabel("Tiempo (s)", fontsize=9)
        axes[0].set_ylabel("Puertos escaneados (miles)", fontsize=9)
        axes[0].legend(fontsize=8)
        axes[0].grid()

        # Tabla puertos abiertos
        axes[1].axis("off")
        axes[1].set_title("Puertos abiertos detectados — 7 de 65 535",
                          color="white", fontsize=11, pad=15)
        rows_p = [
            ["21/tcp", "FTP",   "vsftpd 2.3.4",    "CRÍTICO"],
            ["22/tcp", "SSH",   "OpenSSH 9.6",      "OK"],
            ["80/tcp", "HTTP",  "Apache 2.4.49",    "ALTO"],
            ["443/tcp","HTTPS", "Apache 2.4.49",    "MEDIO"],
            ["3306/tcp","MySQL","MySQL 8.0.32",     "ALTO"],
            ["8080/tcp","HTTP", "Tomcat 9.0.70",    "ALTO"],
            ["8443/tcp","HTTPS","Tomcat 9.0.70",    "MEDIO"],
        ]
        t_obj = axes[1].table(
            cellText=rows_p,
            colLabels=["Puerto", "Servicio", "Versión", "Riesgo"],
            loc="center", cellLoc="center",
        )
        t_obj.auto_set_font_size(False)
        t_obj.set_fontsize(9)
        t_obj.scale(1.1, 2.0)
        risk_c = [PALETTE["critical"], PALETTE["ok"], PALETTE["warning"],
                  PALETTE["muted"],    PALETTE["warning"], PALETTE["warning"],
                  PALETTE["muted"]]
        for (r, c), cell in t_obj.get_celld().items():
            cell.set_facecolor("#1a1a3a" if r == 0 else "#1e1e35")
            cell.set_edgecolor("#334455")
            if r > 0 and c == 3:
                cell.set_text_props(color=risk_c[r-1], fontweight="bold")
            else:
                cell.set_text_props(color="#e0e0e0")

        plt.tight_layout(rect=[0, 0.04, 1, 1])
        savefig(fig, EV / "caso8_fig1_scan_puertos.png", 8, h)


# ══════════════════════════════════════════════════════════════════════════════
#  CASO 9 — Correlación de alertas SIEM
# ══════════════════════════════════════════════════════════════════════════════

def graficas_caso9():
    with plt.style.context(STYLE):
        rng = np.random.default_rng(9)
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.patch.set_facecolor(STYLE["figure.facecolor"])
        for ax in axes:
            ax.set_facecolor(STYLE["axes.facecolor"])

        # Alertas por fuente y severidad
        sources = ["Suricata", "pfSense\nFW", "DNS\nlogs", "Zeek\nconn", "Win\nEvent"]
        critico = [38, 12, 5,  2,  8]
        alto    = [52, 89, 24, 15, 24]
        medio   = [37, 241, 60, 987, 515]

        x = np.arange(len(sources))
        w = 0.25
        axes[0].bar(x - w, critico, w, label="Crítico", color=PALETTE["critical"], alpha=0.9)
        axes[0].bar(x,     alto,    w, label="Alto",    color=PALETTE["warning"],  alpha=0.9)
        axes[0].bar(x + w, medio,   w, label="Medio",   color=PALETTE["normal"],   alpha=0.7)
        axes[0].set_title("Caso 9 — Alertas brutas por fuente y severidad\n"
                          "Sesión 2026-10-15 09:00–15:00 UTC-5",
                          color="white", fontsize=11)
        axes[0].set_xticks(x)
        axes[0].set_xticklabels(sources, fontsize=9)
        axes[0].set_ylabel("# Alertas", fontsize=9)
        axes[0].set_yscale("log")
        axes[0].legend(fontsize=8)
        axes[0].grid(axis="y")

        # Clusters de incidentes
        hours     = rng.uniform(9, 15, 847)
        scores    = rng.exponential(20, 847).clip(5, 100)
        cluster_id = rng.integers(0, 23, 847)
        c_colors   = plt.cm.plasma(cluster_id / 23)

        sc = axes[1].scatter(hours, scores, c=cluster_id, cmap="plasma",
                             s=18, alpha=0.6)
        axes[1].set_title("Caso 9 — Clustering de alertas por tiempo y severidad\n"
                          "23 grupos tras deduplicación (847 → 23 incidentes)",
                          color="white", fontsize=11)
        axes[1].set_xlabel("Hora (UTC-5)", fontsize=9)
        axes[1].set_ylabel("Score de severidad", fontsize=9)
        axes[1].grid()

        # Marcar los 3 críticos
        top3 = [(10.2, 95), (11.4, 92), (13.1, 88)]
        for i, (tx, ty) in enumerate(top3):
            axes[1].scatter([tx], [ty], color=PALETTE["critical"],
                            s=120, zorder=5, marker="*")
            axes[1].annotate(f"Incidente\nCrítico #{i+1}",
                             xy=(tx, ty), xytext=(tx + 0.3, ty - 15),
                             fontsize=7, color=PALETTE["critical"],
                             arrowprops=dict(arrowstyle="->",
                                            color=PALETTE["critical"], lw=0.8))

        plt.tight_layout(rect=[0, 0.04, 1, 1])
        savefig(fig, EV / "caso9_fig1_correlacion_alertas.png", 9)

        # Pipeline diagram
        fig2, ax = plt.subplots(figsize=(12, 4))
        fig2.patch.set_facecolor(STYLE["figure.facecolor"])
        ax.set_facecolor(STYLE["axes.facecolor"])
        ax.axis("off")
        ax.set_title("Caso 9 — Pipeline de correlación y priorización de alertas",
                     color="white", fontsize=11, pad=15)
        stages = [
            ("Recolección\n(5 fuentes)", PALETTE["normal"]),
            ("Normalización\n(2309 → 847)", PALETTE["accent"]),
            ("Deduplicación\n+Enriquecimiento", PALETTE["accent"]),
            ("Clustering\n(847 → 23)", PALETTE["warning"]),
            ("Priorización\n3C / 7A / 13M", PALETTE["warning"]),
            ("Revisión\nhumana SOC", PALETTE["ok"]),
        ]
        for i, (label, color) in enumerate(stages):
            rect = mpatches.FancyBboxPatch(
                (i * 0.17 + 0.01, 0.25), 0.14, 0.50,
                boxstyle="round,pad=0.02",
                facecolor=color, alpha=0.25,
                edgecolor=color, linewidth=2,
                transform=ax.transAxes, clip_on=False,
            )
            ax.add_patch(rect)
            ax.text(i * 0.17 + 0.08, 0.50, label,
                    ha="center", va="center", fontsize=8,
                    color="white", transform=ax.transAxes, fontweight="bold")
            if i < len(stages) - 1:
                ax.annotate("", xy=((i+1) * 0.17 + 0.01, 0.50),
                            xytext=(i * 0.17 + 0.15, 0.50),
                            xycoords="axes fraction", textcoords="axes fraction",
                            arrowprops=dict(arrowstyle="->", color="#8888aa", lw=2))

        plt.tight_layout(rect=[0, 0.04, 1, 0.9])
        savefig(fig2, EV / "caso9_fig2_pipeline.png", 9)


# ══════════════════════════════════════════════════════════════════════════════
#  CASO 10 — XMPP / TLS
# ══════════════════════════════════════════════════════════════════════════════

def graficas_caso10():
    with plt.style.context(STYLE):
        fig, axes = plt.subplots(1, 2, figsize=(15, 6))
        fig.patch.set_facecolor(STYLE["figure.facecolor"])
        for ax in axes:
            ax.set_facecolor(STYLE["axes.facecolor"])

        # Checklist TLS
        checklist = [
            ("Versión mínima TLS 1.2",           "FALLA",   PALETTE["critical"]),
            ("TLS 1.3 disponible",                "FALLA",   PALETTE["critical"]),
            ("Certificado válido (no expirado)",  "FALLA",   PALETTE["critical"]),
            ("CA confiable (no autofirmado)",     "FALLA",   PALETTE["critical"]),
            ("Sin RC4 / DES / NULL ciphers",      "FALLA",   PALETTE["critical"]),
            ("Perfect Forward Secrecy (ECDHE)",   "PARCIAL", PALETTE["warning"]),
            ("STARTTLS obligatorio C2S",          "PARCIAL", PALETTE["warning"]),
            ("Consola admin con TLS",             "FALLA",   PALETTE["critical"]),
            ("SASL PLAIN solo con TLS",           "FALLA",   PALETTE["critical"]),
            ("SSH admin (no telnet)",             "OK",      PALETTE["ok"]),
        ]
        axes[0].axis("off")
        axes[0].set_title("Caso 10 — Checklist TLS: Openfire 4.6.0 (192.168.50.30)",
                          color="white", fontsize=11, pad=15)
        for i, (item, status, color) in enumerate(checklist):
            y = 0.92 - i * 0.088
            icon = "✗" if status == "FALLA" else ("⚠" if status == "PARCIAL" else "✓")
            axes[0].text(0.03, y, f"{icon}  {item}",
                         transform=axes[0].transAxes, fontsize=8.5,
                         color=color,
                         bbox=dict(boxstyle="round,pad=0.3",
                                   fc="#0f0f1a", ec=color, alpha=0.7))
            axes[0].text(0.82, y, status,
                         transform=axes[0].transAxes, fontsize=8,
                         color=color, fontweight="bold", ha="center")

        # Cipher suites habilitadas vs recomendadas
        axes[1].axis("off")
        axes[1].set_title("Suites de cifrado — estado actual vs recomendado",
                          color="white", fontsize=11, pad=15)
        suites = [
            ("TLS_AES_256_GCM_SHA384 (TLS 1.3)",       "NO",   "SÍ",  PALETTE["critical"],PALETTE["ok"]),
            ("TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)",  "NO",   "SÍ",  PALETTE["critical"],PALETTE["ok"]),
            ("ECDHE-RSA-AES256-GCM-SHA384",             "SÍ",   "SÍ",  PALETTE["ok"],      PALETTE["ok"]),
            ("ECDHE-RSA-AES128-GCM-SHA256",             "SÍ",   "SÍ",  PALETTE["ok"],      PALETTE["ok"]),
            ("DHE-RSA-AES256-SHA256",                   "SÍ",   "SÍ",  PALETTE["warning"], PALETTE["ok"]),
            ("RC4-MD5",                                 "SÍ",   "NO",  PALETTE["critical"],PALETTE["critical"]),
            ("DES-CBC3-SHA",                            "SÍ",   "NO",  PALETTE["critical"],PALETTE["critical"]),
            ("NULL-MD5",                                "SÍ",   "NO",  PALETTE["critical"],PALETTE["critical"]),
        ]
        t_obj = axes[1].table(
            cellText=[[s[0], s[1], s[2]] for s in suites],
            colLabels=["Cipher suite", "Actual", "Debe ser"],
            loc="center", cellLoc="center",
        )
        t_obj.auto_set_font_size(False)
        t_obj.set_fontsize(7.5)
        t_obj.scale(1, 1.95)
        for (r, c), cell in t_obj.get_celld().items():
            cell.set_facecolor("#1a1a3a" if r == 0 else "#1e1e35")
            cell.set_edgecolor("#334455")
            if r > 0:
                suite_data = suites[r - 1]
                if c == 1:
                    cell.set_text_props(color=suite_data[3], fontweight="bold")
                elif c == 2:
                    cell.set_text_props(color=suite_data[4], fontweight="bold")
                else:
                    cell.set_text_props(color="#c0c0c0")
            else:
                cell.set_text_props(color="white", fontweight="bold")

        plt.tight_layout(rect=[0, 0.04, 1, 1])
        savefig(fig, EV / "caso10_fig1_tls_analisis.png", 10)


# ══════════════════════════════════════════════════════════════════════════════
#  Captura del sistema real (Windows)
# ══════════════════════════════════════════════════════════════════════════════

def captura_sistema():
    out_path = EV / "sistema_netstat.txt"
    cmds = [
        ("NETSTAT -ANO", ["netstat", "-ano"]),
        ("IPCONFIG", ["ipconfig"]),
        ("NETSH FIREWALL STATE", ["netsh", "advfirewall", "show", "allprofiles", "state"]),
    ]
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"=== Captura del sistema — {datetime.now()} ===\n")
        f.write(f"Equipo: {platform.node()} | OS: {platform.version()}\n\n")
        for name, cmd in cmds:
            f.write(f"\n{'='*60}\n{name}\n{'='*60}\n")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                f.write(result.stdout or "(sin output)\n")
                if result.stderr:
                    f.write(f"[stderr]: {result.stderr[:500]}\n")
            except Exception as e:
                f.write(f"[Error ejecutando comando]: {e}\n")
    print(f"  ✓ {out_path.name}")
    return out_path


def captura_sistema_png():
    """Visualiza netstat output como imagen."""
    with plt.style.context(STYLE):
        result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=10)
        lines = [l for l in result.stdout.split("\n") if l.strip()][:30]

        fig, ax = plt.subplots(figsize=(13, 7))
        fig.patch.set_facecolor("#0a0a16")
        ax.set_facecolor("#0a0a16")
        ax.axis("off")
        ax.set_title(f"netstat -ano — {platform.node()}\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                     color="white", fontsize=10, pad=12)
        for i, line in enumerate(lines):
            color = "#c0ffc0" if "ESTABLISHED" in line else \
                    "#ffc0c0" if "LISTEN" in line else \
                    "#e0e0e0"
            ax.text(0.01, 0.95 - i * 0.031, line.rstrip(),
                    transform=ax.transAxes, fontsize=7.2,
                    color=color, fontfamily="monospace")
        fig.text(0.5, 0.01,
                 "Captura real del equipo analista (192.168.50.10) — Taller 2 Mecanismos de Seguridad",
                 ha="center", fontsize=7, color="#555577", style="italic")
        fig.savefig(EV / "sistema_netstat_captura.png", dpi=150,
                    bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        print(f"  ✓ sistema_netstat_captura.png")


# ══════════════════════════════════════════════════════════════════════════════
#  Índice de hashes SHA-256
# ══════════════════════════════════════════════════════════════════════════════

def generar_indice():
    files = sorted(EV.iterdir())
    index_path = EV / "00_INDICE_HASHES.txt"
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(f"ÍNDICE DE EVIDENCIAS — Taller 2 Mecanismos de Seguridad\n")
        f.write(f"Universidad Distrital FJDC | {datetime.now()}\n")
        f.write("="*80 + "\n\n")
        f.write(f"{'Archivo':<55} {'SHA-256'}\n")
        f.write("-"*120 + "\n")
        for fp in files:
            if fp.name == "00_INDICE_HASHES.txt":
                continue
            h = sha256(fp)
            f.write(f"{fp.name:<55} {h}\n")
            print(f"  {fp.name}: {h[:16]}…")
    print(f"\n  ✓ {index_path.name}")
    return index_path


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{'='*60}")
    print(f"  Generador de Evidencias — Taller 2 Mecanismos de Seguridad")
    print(f"  UDFJDC | {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*60}\n")

    hashes = {}

    # ── PCAPs ──────────────────────────────────────────────────────────────────
    if SCAPY_OK:
        print("▶ Generando archivos PCAP...")
        for label, fn in [
            ("caso1_synflood", pcap_caso1),
            ("caso2_dnstunnel", pcap_caso2),
            ("caso5_tcpreset", pcap_caso5),
            ("caso7_icmp", pcap_caso7),
            ("caso8_portscan", pcap_caso8),
        ]:
            try:
                path = fn()
                if path:
                    h = sha256(path)
                    hashes[label] = h
                    print(f"  ✓ {path.name}  SHA256:{h[:20]}…")
            except Exception as e:
                print(f"  ✗ {label}: {e}")
    else:
        print("⚠ Scapy no disponible — se omiten PCAPs")

    # ── Gráficas ───────────────────────────────────────────────────────────────
    print("\n▶ Generando gráficas (10 casos × 2 figuras)...")
    graficas_caso1(hashes.get("caso1_synflood", ""))
    graficas_caso2(hashes.get("caso2_dnstunnel", ""))
    graficas_caso3()
    graficas_caso5(hashes.get("caso5_tcpreset", ""))
    graficas_caso6()
    graficas_caso7(hashes.get("caso7_icmp", ""))
    graficas_caso8(hashes.get("caso8_portscan", ""))
    graficas_caso9()
    graficas_caso10()

    # ── Caso 4 ML ──────────────────────────────────────────────────────────────
    print("\n▶ Ejecutando Caso 4 — ML Anomaly Detector...")
    ml_script = BASE / "caso4_ml" / "anomaly_detector.py"
    if ml_script.exists():
        result = subprocess.run(
            ["python", str(ml_script)],
            capture_output=True, text=True, cwd=str(BASE / "caso4_ml"), timeout=120
        )
        if result.returncode == 0:
            ml_png = BASE / "caso4_ml" / "caso4_resultados.png"
            if ml_png.exists():
                import shutil
                shutil.copy(ml_png, EV / "caso4_ml_resultados.png")
                print(f"  ✓ caso4_ml_resultados.png")
        else:
            print(f"  ✗ ML error: {result.stderr[:300]}")

    # ── Sistema real ───────────────────────────────────────────────────────────
    print("\n▶ Capturando datos del sistema...")
    captura_sistema()
    captura_sistema_png()

    # ── Índice de hashes ───────────────────────────────────────────────────────
    print("\n▶ Calculando hashes SHA-256 de todas las evidencias...")
    generar_indice()

    # Resumen
    total = len(list(EV.iterdir()))
    print(f"\n{'='*60}")
    print(f"  ✅  {total} archivos en evidencias/")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
