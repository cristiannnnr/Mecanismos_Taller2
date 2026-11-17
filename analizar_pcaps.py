# -*- coding: utf-8 -*-
"""
analizar_pcaps.py - Taller 2 Mecanismos de Seguridad (UDFJDC)

Analiza las PCAP sinteticas de la carpeta evidencias/ y muestra, para cada caso,
las metricas que sustentan el informe. Solo usa la biblioteca estandar de Python
(no requiere scapy ni tshark), de modo que cualquier persona puede reproducir
los resultados:

    python analizar_pcaps.py            # todos los casos
    python analizar_pcaps.py caso1      # un caso (caso1, caso2, caso5, caso7, caso8)
    python analizar_pcaps.py hashes     # verificacion SHA-256 de todas las evidencias

Los tiempos son relativos al primer paquete de cada captura (t = 0 s).
"""
import base64
import collections
import hashlib
import math
import socket
import statistics as st
import struct
import sys
from pathlib import Path

EV = Path(__file__).resolve().parent / "evidencias"
if not EV.is_dir():
    EV = Path(__file__).resolve().parent


# ---------------------------------------------------------------- lectura PCAP
def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = struct.unpack("<I", gh[:4])[0]
        en = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        div = 1e9 if magic == 0xA1B23C4D else 1e6
        n = 0
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            ts, us, incl, _orig = struct.unpack(en + "IIII", h)
            n += 1
            yield n, ts + us / div, f.read(incl)


def parse(d):
    p = {"len": len(d), "dmac": d[0:6].hex(":"), "smac": d[6:12].hex(":")}
    off = 14
    ihl = (d[off] & 0xF) * 4
    p["ttl"], p["proto"] = d[off + 8], d[off + 9]
    iplen = struct.unpack("!H", d[off + 2:off + 4])[0]
    p["src"] = socket.inet_ntoa(d[off + 12:off + 16])
    p["dst"] = socket.inet_ntoa(d[off + 16:off + 20])
    t = off + ihl
    if p["proto"] == 6:
        p["sport"], p["dport"], p["seq"], p["ack"] = struct.unpack("!HHII", d[t:t + 12])
        doff = (d[t + 12] >> 4) * 4
        p["flags"], p["win"] = d[t + 13], struct.unpack("!H", d[t + 14:t + 16])[0]
        p["optlen"] = doff - 20
        p["payload"] = d[t + doff:off + iplen]
    elif p["proto"] == 17:
        p["sport"], p["dport"], ul = struct.unpack("!HHH", d[t:t + 6])
        p["payload"] = d[t + 8:t + ul]
    elif p["proto"] == 1:
        p["itype"], p["icode"] = d[t], d[t + 1]
        p["icmpid"], p["icmpseq"] = struct.unpack("!HH", d[t + 4:t + 8])
        p["payload"] = d[t + 8:off + iplen]
    return p


def flagstr(f):
    names = [(0x02, "SYN"), (0x04, "RST"), (0x01, "FIN"), (0x08, "PSH"), (0x10, "ACK")]
    return ", ".join(n for b, n in names if f & b)


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(name):
    path = EV / name
    pk = [(n, ts, parse(d)) for n, ts, d in read_pcap(path)]
    t0 = pk[0][1]
    pk = [(n, ts - t0, p) for n, ts, p in pk]
    print(f"Archivo   : {name}")
    print(f"Tamano    : {path.stat().st_size:,} bytes".replace(",", " "))
    print(f"SHA-256   : {sha256(path)}")
    print(f"Paquetes  : {len(pk)}    Duracion: {pk[-1][1]:.3f} s    Enlace: Ethernet")
    return pk


def title(s):
    print("=" * 92)
    print(s)
    print("=" * 92)


def sub(s):
    print(f"\n--- {s} " + "-" * max(0, 86 - len(s)))


def tcp_row(n, ts, p):
    info = f"{p['sport']} > {p['dport']} [{flagstr(p['flags'])}] Seq={p['seq']} Win={p['win']} Len={len(p['payload'])}"
    return f"{n:>6} {ts:>10.6f}  {p['src']:<15} {p['dst']:<15} TCP  {p['len']:>4}  {info}"


HDR = f"{'No.':>6} {'Tiempo(s)':>10}  {'Origen':<15} {'Destino':<15} Prot {'Long':>4}  Info"


# ------------------------------------------------------------------- CASO 1
def caso1():
    title("CASO 1 - TCP SYN Flood  |  filtro: tcp.flags.syn == 1 && tcp.flags.ack == 0")
    pk = load("caso1_synflood_lab.pcap")
    syn = [x for x in pk if x[2]["flags"] == 0x02]
    sa = [x for x in pk if x[2]["flags"] == 0x12]
    ack = [x for x in pk if x[2]["flags"] == 0x10]
    sub("Conteo por tipo de segmento")
    print(f"SYN (sin ACK)            : {len(syn)}")
    print(f"SYN/ACK del servidor     : {len(sa)}")
    print(f"ACK final (3er paso)     : {len(ack)}   -> handshakes completados en la captura: {len(ack)}")
    print(f"Relacion SYN : SYN/ACK   : {len(syn) / len(sa):.1f} : 1")
    sub("Ventanas de 1 s (SYN / SYN-ACK / ACK)")
    for s in range(int(pk[-1][1]) + 1):
        a = sum(1 for _, t, _p in syn if int(t) == s)
        b = sum(1 for _, t, _p in sa if int(t) == s)
        c = sum(1 for _, t, _p in ack if int(t) == s)
        print(f"  t={s:>2}-{s + 1:<2} s   SYN={a:>4}   SYN/ACK={b:>2}   ACK={c}   {'#' * (a // 10)}")
    srcs = collections.Counter(p["src"] for _, _, p in syn)
    rep = collections.Counter(srcs.values())
    sub("Origenes")
    print(f"IP origen distintas      : {len(srcs)}  (rango 10.0.0.0/16, destino unico 192.168.50.20:80)")
    print(f"IP con 1 solo SYN        : {rep[1]}  ({rep[1] / len(srcs) * 100:.1f} %)   con 2: {rep[2]}   con 3: {rep[3]}")
    ttls = [p["ttl"] for _, _, p in syn]
    print(f"TTL observados           : {min(ttls)}-{max(ttls)}  ({len(set(ttls))} valores distintos)")
    print(f"Opciones TCP en los SYN  : {sum(p['optlen'] for _, _, p in syn)} bytes (ninguna; sin MSS)   Ventana: {set(p['win'] for _, _, p in syn)}")
    print(f"Tasa media               : {len(syn) / pk[-1][1]:.0f} SYN/s durante {pk[-1][1]:.1f} s")
    sub("Primeros paquetes que cumplen el filtro")
    print(HDR)
    for n, ts, p in syn[:7]:
        print(tcp_row(n, ts, p))


# ------------------------------------------------------------------- CASO 2
def dns_query(pl):
    i, labels = 12, []
    while pl[i]:
        ln = pl[i]
        labels.append(pl[i + 1:i + 1 + ln].decode("ascii", "replace"))
        i += 1 + ln
    qtype = struct.unpack("!H", pl[i + 1:i + 3])[0]
    is_resp = bool(pl[2] & 0x80)
    return labels, qtype, is_resp


QT = {1: "A", 5: "CNAME", 10: "NULL", 15: "MX", 16: "TXT", 28: "AAAA"}


def caso2():
    title("CASO 2 - DNS tunneling  |  filtro: udp.port == 53 && dns")
    pk = load("caso2_dnstunnel_lab.pcap")
    qs = [(n, ts, p, *dns_query(p["payload"])) for n, ts, p in pk]
    cons = [q for q in qs if not q[5]]
    sub("Volumen")
    dur = pk[-1][1]
    print(f"Consultas DNS            : {len(cons)}   Respuestas en la captura: {len(qs) - len(cons)}")
    print(f"Cliente -> resolver      : {set(q[2]['src'] for q in qs)} -> {set(q[2]['dst'] for q in qs)} (UDP/53)")
    print(f"Tasa                     : {len(cons) / dur:.2f} consultas/s = {len(cons) / dur * 60:.0f} consultas/min")
    print(f"Tipos de registro        : " + ", ".join(f"{QT.get(k, k)}={v}" for k, v in collections.Counter(q[4] for q in cons).items()))
    print(f"Dominios base            : {dict(collections.Counter('.'.join(q[3][1:]) for q in cons))}")
    first = [q[3][0] for q in cons]
    sub("Primera etiqueta (subdominio)")
    ll = [len(x) for x in first]
    hh = [entropy(x.encode()) for x in first]
    print(f"Longitud (caracteres)    : min={min(ll)}  media={st.mean(ll):.1f}  max={max(ll)}")
    print(f"Entropia de Shannon      : min={min(hh):.2f}  media={st.mean(hh):.2f}  max={max(hh):.2f} bits/caracter")
    print(f"Etiquetas distintas      : {len(set(first))} de {len(first)}")
    ref = ["www", "mail", "intranet", "servidor-web", "dns1"]
    print(f"Referencia (nombres comunes {ref}): longitud media "
          f"{st.mean(len(x) for x in ref):.1f}, entropia media {st.mean(entropy(x.encode()) for x in ref):.2f}")
    sub("Muestra de consultas y decodificacion Base64 de la primera etiqueta")
    print(f"{'No.':>5} {'Tiempo(s)':>9}  {'Tipo':<4} {'Consulta':<64} Decodificado")
    for n, ts, p, labels, qt, _r in cons[:8]:
        s = labels[0]
        try:
            dec = base64.b64decode(s + "=" * (-len(s) % 4))
            dec = "".join(chr(c) if 32 <= c < 127 else f"\\x{c:02x}" for c in dec)
        except Exception:
            dec = "(no es Base64)"
        print(f"{n:>5} {ts:>9.3f}  {QT.get(qt, qt):<4} {'.'.join(labels):<64} {dec}")


# ------------------------------------------------------------------- CASO 5
def caso5():
    title("CASO 5 - TCP RST inesperados  |  filtro: tcp.flags.reset == 1")
    pk = load("caso5_tcpreset_lab.pcap")
    fl = collections.Counter(flagstr(p["flags"]) for _, _, p in pk)
    sub("Conteo por flags")
    print("   ".join(f"[{k}]={v}" for k, v in fl.items()) + f"   [FIN]={sum(1 for _, _, p in pk if p['flags'] & 1)}")
    sub("Quien emite cada tipo de segmento (IP origen / MAC origen / TTL)")
    c = collections.Counter((flagstr(p["flags"]), p["src"], p["smac"], p["ttl"]) for _, _, p in pk)
    for (f, src, mac, ttl), v in c.items():
        print(f"  [{f:<8}] {src:<15} {mac}  TTL={ttl}  x{v}")
    sub("Sesiones: tiempo entre el ACK del handshake y el RST")
    pend, delays, seq_ok, data = {}, [], 0, 0
    rows = []
    for n, ts, p in pk:
        data += len(p["payload"])
        if p["flags"] == 0x12:
            pend[p["dport"]] = {"isn_srv": p["seq"]}
        elif p["flags"] == 0x10 and p["sport"] in pend:
            pend[p["sport"]]["t_ack"] = ts
        elif p["flags"] & 0x04 and p["dport"] in pend and "t_ack" in pend[p["dport"]]:
            s = pend.pop(p["dport"])
            delays.append(ts - s["t_ack"])
            ok = p["seq"] == (s["isn_srv"] + 1) & 0xFFFFFFFF
            seq_ok += ok
            rows.append((p["dport"], s["t_ack"], ts, ts - s["t_ack"], p["src"], ok))
    print(f"Sesiones con handshake completo y RST : {len(delays)}")
    print(f"Bytes de datos de aplicacion          : {data}  (las sesiones estan inactivas tras el handshake)")
    print(f"Tiempo handshake -> RST               : min={min(delays):.2f} s  media={st.mean(delays):.2f} s  max={max(delays):.2f} s")
    print(f"RST con Seq = ISN_servidor + 1        : {seq_ok} de {len(delays)}  (numero de secuencia valido)")
    print(f"Cierres ordenados con FIN             : {sum(1 for _, _, p in pk if p['flags'] & 1)}")
    sub("Tabla de flujos afectados (primeros 6)")
    print(f"{'Flujo cliente':<26} {'t ACK (s)':>10} {'t RST (s)':>10} {'Inactivo':>9}  {'RST desde':<13} Seq valido")
    for dport, ta, tr, dl, src, ok in rows[:6]:
        print(f"{'192.168.50.10:' + str(dport) + ' > .20:443':<26} {ta:>10.3f} {tr:>10.3f} {dl:>8.2f}s  {src:<13} {'si' if ok else 'no'}")
    sub("Una sesion completa")
    print(HDR)
    for n, ts, p in pk[:4]:
        print(tcp_row(n, ts, p))


# ------------------------------------------------------------------- CASO 7
def caso7():
    title("CASO 7 - ICMP atipico  |  filtro: icmp.type == 8 && data.len > 100")
    pk = load("caso7_icmp_lab.pcap")
    req = [x for x in pk if x[2]["itype"] == 8]
    rep = [x for x in pk if x[2]["itype"] == 0]
    dur = pk[-1][1]
    sub("Volumen")
    print(f"Echo Request (tipo 8)    : {len(req)}     Echo Reply (tipo 0): {len(rep)}")
    print(f"Origen -> destino        : {set(p['src'] for _, _, p in pk)} -> {set(p['dst'] for _, _, p in pk)}")
    print(f"Tasa media               : {len(req) / dur * 60:.0f} Echo Request/min durante {dur / 60:.1f} min")
    print("Referencia ping Windows  : 4 Echo Request de 32 bytes por ejecucion (1 por segundo)")
    sub("Paquetes por minuto")
    m = collections.Counter(int(t // 60) for _, t, _p in req)
    for k in sorted(m):
        print(f"  minuto {k}: {m[k]:>4}  {'#' * (m[k] // 10)}")
    sub("Carga util (payload)")
    sizes = collections.Counter(len(p["payload"]) for _, _, p in req)
    print(f"Tamano de payload        : {dict(sizes)} bytes  -> trama IP de 1500 bytes (MTU completa, sin fragmentar)")
    hp = [entropy(p["payload"]) for _, _, p in req]
    print(f"Entropia por paquete     : media={st.mean(hp):.2f} bits/byte (cada paquete repite un unico byte)")
    print(f"Entropia del conjunto    : {entropy(b''.join(p['payload'][:16] for _, _, p in req)):.2f} bits/byte (el byte cambia de un paquete a otro)")
    okpat = sum(1 for _, _, p in req if set(p["payload"]) == {p["icmpseq"] % 256})
    print(f"Patron byte = seq mod 256: {okpat} de {len(req)} paquetes")
    ia = [b[1] - a[1] for a, b in zip(req, req[1:])]
    print(f"Intervalo entre paquetes : media={st.mean(ia) * 1000:.0f} ms  desv.={st.pstdev(ia) * 1000:.0f} ms (irregular, no periodico)")
    sub("Muestra de paquetes")
    print(f"{'No.':>5} {'Tiempo(s)':>9}  {'Origen':<15} {'Destino':<14} {'Tipo':<12} {'id':>6} {'seq':>5} {'Datos':>5}  Primeros bytes")
    for n, ts, p in req[:4] + req[255:258]:
        print(f"{n:>5} {ts:>9.3f}  {p['src']:<15} {p['dst']:<14} Echo request {p['icmpid']:>#6x} {p['icmpseq']:>5} {len(p['payload']):>5}  {p['payload'][:8].hex(' ')}")


# ------------------------------------------------------------------- CASO 8
def caso8():
    title("CASO 8 - Escaneo de puertos  |  filtro: tcp.flags.syn == 1 && tcp.flags.ack == 0")
    pk = load("caso8_portscan_lab.pcap")
    syn = [x for x in pk if x[2]["flags"] == 0x02]
    sa = [x for x in pk if x[2]["flags"] == 0x12]
    rst = [x for x in pk if x[2]["flags"] & 0x04]
    ports = [p["dport"] for _, _, p in syn]
    dur = syn[-1][1] - syn[0][1]
    sub("Sondeo")
    print(f"Origen -> destino        : {set(p['src'] for _, _, p in syn)} -> {set(p['dst'] for _, _, p in syn)}")
    print(f"SYN enviados             : {len(syn)}   puertos destino distintos: {len(set(ports))} ({min(ports)}-{max(ports)})")
    print(f"Orden de los puertos     : {'secuencial ascendente' if ports == sorted(ports) else 'no secuencial'}")
    ia = [b[1] - a[1] for a, b in zip(syn, syn[1:])]
    print(f"Intervalo entre SYN      : media={st.mean(ia) * 1e6:.0f} us  desv.={st.pstdev(ia) * 1e6:.3f} us  -> {len(syn) / dur:.0f} puertos/s en {dur:.2f} s")
    print(f"Opciones TCP en los SYN  : {sum(p['optlen'] for _, _, p in syn)} bytes   ACK final tras SYN/ACK: {sum(1 for _, _, p in pk if p['flags'] == 0x10)}")
    sub("Respuestas del servidor")
    print(f"RST/ACK (puerto cerrado) : {len(rst)}")
    print(f"SYN/ACK (puerto abierto) : {len(sa)}")
    print(f"Sin respuesta (filtrado) : {len(syn) - len(rst) - len(sa)}")
    sub("Puertos que respondieron SYN/ACK (filtro: tcp.flags.syn == 1 && tcp.flags.ack == 1)")
    names = {21: "ftp", 22: "ssh", 80: "http", 443: "https", 3306: "mysql", 8080: "http-alt", 8443: "https-alt"}
    print(f"{'No.':>7} {'Tiempo(s)':>10}  {'Origen':<15} {'Puerto':>6}  {'Servicio IANA':<13} Flags")
    for n, ts, p in sa:
        print(f"{n:>7} {ts:>10.6f}  {p['src']:<15} {p['sport']:>6}  {names.get(p['sport'], '?'):<13} [{flagstr(p['flags'])}]")
    sub("Primeros paquetes de la captura")
    print(HDR)
    for n, ts, p in pk[:6]:
        print(tcp_row(n, ts, p))


# ------------------------------------------------------------------- HASHES
def hashes():
    title("Verificacion de integridad - SHA-256 de las evidencias")
    print(f"{'Archivo':<44} {'Bytes':>9}  SHA-256")
    for f in sorted(EV.iterdir()):
        if f.is_file() and f.suffix.lower() in (".pcap", ".png", ".txt") and not f.name.startswith("00_"):
            print(f"{f.name:<44} {f.stat().st_size:>9}  {sha256(f)}")


CASOS = {"caso1": caso1, "caso2": caso2, "caso5": caso5, "caso7": caso7, "caso8": caso8, "hashes": hashes}

if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sel = sys.argv[1:] or list(CASOS)
    for i, k in enumerate(sel):
        if k not in CASOS:
            sys.exit(f"Caso desconocido: {k}. Opciones: {', '.join(CASOS)}")
        if i:
            print()
        CASOS[k]()
