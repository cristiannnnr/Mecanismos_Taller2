# -*- coding: utf-8 -*-
"""Genera el Informe Taller 2 con el formato (plantilla LaTeX) del Technical Report.
Formato: tomado de Technical_Report (CS_report.sty, portada, estructura de capitulos).
Contenido: tomado del Informe Taller 2 (markdown) y sus adyacentes (guia, README).
"""
import os, re, glob
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "Informe_Taller_Formato_TechReport")
CH = os.path.join(BUILD, "chapters")
FIG = os.path.join(BUILD, "figures")
os.makedirs(CH, exist_ok=True)

REPORT = open(os.path.join(ROOT, "Informe_Taller2_Seguridad_v2.md"), encoding="utf-8").read()
GUIDE = open(os.path.join(ROOT, "SEGUNDO TALLER MECANISMOS DE SEGURIDAD OCTUBRE 26_2026_VERSION FIAL_V2.md"), encoding="utf-8").read()

# ---------- image sizes ----------
IMGSIZE = {}
for p in glob.glob(os.path.join(FIG, "*.png")):
    try:
        IMGSIZE[os.path.basename(p)] = Image.open(p).size
    except Exception:
        pass

# ---------- escaping ----------
SPECIAL = {
    '\\': r'\textbackslash{}', '{': r'\{', '}': r'\}', '$': r'\$', '&': r'\&',
    '#': r'\#', '%': r'\%', '_': r'\_', '^': r'\textasciicircum{}', '~': r'\textasciitilde{}',
    '\u2011': '-', '\u2013': '--', '\u2014': '---', '\u2026': r'\ldots{}',
    '\u2192': r'$\rightarrow$', '\u2194': r'$\leftrightarrow$', '\u2212': r'$-$',
    '\u00d7': r'$\times$', '\u00b5': r'$\mu$', '\u00b7': r'$\cdot$',
    '\u00ab': r'\guillemotleft{}', '\u00bb': r'\guillemotright{}', '\u2022': r'\textbullet{}',
}

def esc(s):
    return ''.join(SPECIAL.get(c, c) for c in s)

def seqwrap(x):
    return r'\seqsplit{%s}' % x

def urlesc(u):
    return u.replace('%', r'\%').replace('#', r'\#')

COLOR = {'real': 'tagrealc', 'pcap': 'tagpcapc', 'sim': 'tagsimc'}

def evtag(cls, txt):
    return r'\tagbox{%s}{%s}' % (COLOR.get(cls, 'tagsimc'), esc(txt))

def inline(s, cell=False):
    toks = []
    def put(x):
        toks.append(x)
        return '\x00%d\x00' % (len(toks) - 1)
    s = re.sub(r'<span class="tag (\w+)">(.*?)</span>',
               lambda m: put(evtag(m.group(1), m.group(2))), s)
    s = re.sub(r'<span class="hash">(.*?)</span>',
               lambda m: put(r'{\scriptsize\ttfamily\seqsplit{%s}}' % esc(m.group(1))), s)
    def code(m):
        raw = m.group(1)
        body = esc(raw)
        maxtok = max((len(t) for t in raw.split()), default=0)
        if (cell and maxtok > 16) or ((not cell) and maxtok > 30):
            body = seqwrap(body)
        return put(r'\texttt{%s}' % body)
    s = re.sub(r'`([^`]+)`', code, s)
    s = re.sub(r'\[([^\]]+)\]\(([^)]+)\)',
               lambda m: put(r'\href{%s}{%s}' % (urlesc(m.group(2)), esc(m.group(1)))), s)
    s = re.sub(r'\*\*(.+?)\*\*', lambda m: put(r'\textbf{%s}' % esc(m.group(1))), s)
    s = re.sub(r'(?<![\*\w])\*([^*]+?)\*(?!\w)', lambda m: put(r'\emph{%s}' % esc(m.group(1))), s)
    s = esc(s)
    for _ in range(6):
        if '\x00' not in s:
            break
        s = re.sub(r'\x00(\d+)\x00', lambda m: toks[int(m.group(1))], s)
    return s

def clean_heading(t):
    t = t.strip()
    t = re.sub(r'\*\*', '', t)
    t = re.sub(r'^_+|_+$', '', t).strip()
    t = re.sub(r'^\d+(\.\d+)*\.?\s+', '', t)  # drop leading numbering like "3.1 "
    return t.strip()

# ---------- figures ----------
def fig_width(base):
    w, h = IMGSIZE.get(base, (1000, 700))
    r = h / w
    if r <= 0.40:
        return r'\linewidth'
    if r <= 0.75:
        return r'0.92\linewidth'
    if r <= 1.05:
        return r'0.70\linewidth'
    return r'0.52\linewidth'

def short_cap(txt, n=70):
    t = re.sub(r'\s+', ' ', txt).strip()
    return t if len(t) <= n else t[:n].rsplit(' ', 1)[0] + '\u2026'

def render_figure(cap, path):
    base = os.path.basename(path)
    full = inline(cap)
    short = inline(short_cap(cap))
    return ("\\begin{figure}[htbp]\n  \\centering\n"
            "  \\includegraphics[width=%s,height=0.82\\textheight,keepaspectratio]{figures/%s}\n"
            "  \\caption[%s]{%s}\n\\end{figure}" % (fig_width(base), base, short, full))

# ---------- listings ----------
def render_listing(buf):
    body = '\n'.join(buf)
    return "\\begin{lstlisting}\n%s\n\\end{lstlisting}" % body

# ---------- tables ----------
def cellsplit(r):
    r = r.strip()
    if r.startswith('|'):
        r = r[1:]
    if r.endswith('|'):
        r = r[:-1]
    return [c.strip() for c in r.split('|')]

def cell_latex(txt):
    parts = re.split(r'<br\s*/?>', txt)
    s = r' \newline '.join(inline(p, cell=True) for p in parts)
    s = s.replace('/', r'/\allowbreak{}')
    return s

TCTX = {'title': 'Registro', 'short': 'Registro', 'k': 0}

def render_table(tbl):
    header = cellsplit(tbl[0])
    data = [cellsplit(r) for r in tbl[2:] if r.strip()]
    n = len(header)
    if n < 1:
        return ''
    font = r'\small'
    if n >= 7:
        font = r'\scriptsize'
    elif n >= 5:
        font = r'\footnotesize'
    # column spec
    if n == 2:
        colspec = r'>{\raggedright\arraybackslash}p{0.27\linewidth} >{\raggedright\arraybackslash}X'
    else:
        colspec = ' '.join([r'>{\raggedright\arraybackslash}X'] * n)
    head = ' & '.join(r'\textbf{%s}' % inline(h.replace('**', ''), cell=True) for h in header)
    body_rows = []
    for row in data:
        row = (row + [''] * n)[:n]
        body_rows.append(' & '.join(cell_latex(c) for c in row) + r' \\')
    TCTX['k'] += 1
    cap = TCTX['title']
    scap = '%s (tabla %d)' % (TCTX['short'], TCTX['k'])
    if len(data) > 22:
        out = [r'{%s' % font,
               r'\begin{xltabular}{\linewidth}{%s}' % colspec,
               r'\caption[%s]{%s}\\' % (inline(scap), inline(cap)),
               r'\toprule', head + r' \\', r'\midrule', r'\endfirsthead',
               r'\toprule', head + r' \\', r'\midrule', r'\endhead',
               r'\bottomrule', r'\endfoot']
        out += body_rows
        out += [r'\end{xltabular}}']
        return '\n'.join(out)
    out = [r'\begin{table}[H]', r'\centering', font,
           r'\caption[%s]{%s}' % (inline(scap), inline(cap)),
           r'\begin{tabularx}{\linewidth}{%s}' % colspec,
           r'\toprule', head + r' \\', r'\midrule']
    out += body_rows
    out += [r'\bottomrule', r'\end{tabularx}', r'\end{table}']
    return '\n'.join(out)

# ---------- lists ----------
def render_itemize(items):
    out = [r'\begin{itemize}']
    out += [r'  \item %s' % inline(it) for it in items]
    out += [r'\end{itemize}']
    return '\n'.join(out)

def render_enumerate(items):
    out = [r'\begin{enumerate}']
    out += [r'  \item %s' % inline(it) for it in items]
    out += [r'\end{enumerate}']
    return '\n'.join(out)

# ---------- block parser ----------
SEC = {2: 'section', 3: 'subsection', 4: 'subsubsection', 5: 'paragraph', 6: 'paragraph'}

def body_to_latex(md, ctx=None):
    if ctx:
        TCTX['title'] = ctx
        TCTX['short'] = short_cap(ctx, 60)
        TCTX['k'] = 0
    lines = md.split('\n')
    i, out = 0, []
    n = len(lines)
    while i < n:
        s = lines[i].rstrip()
        if not s.strip():
            i += 1
            continue
        m = re.match(r'(#{1,6})\s+(.*)', s)
        if m:
            lvl = len(m.group(1))
            title = clean_heading(m.group(2))
            cmd = SEC.get(lvl, 'paragraph')
            out.append('\\%s{%s}' % (cmd, inline(title)))
            TCTX['title'] = title
            TCTX['short'] = short_cap(title, 60)
            TCTX['k'] = 0
            i += 1
            continue
        if s.lstrip().startswith('```'):
            lang = s.lstrip()[3:].strip()
            j = i + 1
            buf = []
            while j < n and not lines[j].lstrip().startswith('```'):
                buf.append(lines[j])
                j += 1
            out.append(render_listing(buf))
            i = j + 1
            continue
        mi = re.match(r'!\[(.*)\]\((.*)\)\s*$', s)
        if mi:
            out.append(render_figure(mi.group(1), mi.group(2)))
            i += 1
            continue
        if s.lstrip().startswith('|'):
            tbl = []
            while i < n and lines[i].lstrip().startswith('|'):
                tbl.append(lines[i])
                i += 1
            out.append(render_table(tbl))
            continue
        if re.match(r'\s*[-*]\s+', s):
            items = []
            while i < n:
                t = lines[i]
                if re.match(r'\s*[-*]\s+', t):
                    items.append(re.sub(r'\s*[-*]\s+', '', t, count=1).rstrip())
                    i += 1
                elif not t.strip():
                    k = i + 1
                    while k < n and not lines[k].strip():
                        k += 1
                    if k < n and re.match(r'\s*[-*]\s+', lines[k]):
                        i = k
                    else:
                        break
                else:
                    break
            out.append(render_itemize(items))
            continue
        if re.match(r'\s*\d+\.\s+', s):
            items = []
            while i < n:
                t = lines[i]
                if re.match(r'\s*\d+\.\s+', t):
                    items.append(re.sub(r'\s*\d+\.\s+', '', t, count=1).rstrip())
                    i += 1
                elif not t.strip():
                    k = i + 1
                    while k < n and not lines[k].strip():
                        k += 1
                    if k < n and re.match(r'\s*\d+\.\s+', lines[k]):
                        i = k
                    else:
                        break
                else:
                    break
            out.append(render_enumerate(items))
            continue
        para = [s]
        i += 1
        while i < n:
            t = lines[i].rstrip()
            if (not t.strip() or re.match(r'#{1,6}\s', t) or t.lstrip().startswith('|')
                    or t.lstrip().startswith('```') or re.match(r'!\[', t)
                    or re.match(r'\s*[-*]\s+', t) or re.match(r'\s*\d+\.\s+', t)):
                break
            para.append(t)
            i += 1
        out.append(inline(' '.join(para)))
    return '\n\n'.join(out)

# ---------- heading navigation ----------
def headings(md):
    lines = md.split('\n')
    fence = False
    hs = []
    for idx, ln in enumerate(lines):
        if ln.lstrip().startswith('```'):
            fence = not fence
            continue
        if fence:
            continue
        m = re.match(r'(#{1,6})\s+(.*)', ln)
        if m:
            hs.append((idx, len(m.group(1)), m.group(2).strip()))
    return lines, hs

def body_of(md, pattern, level=None):
    lines, hs = headings(md)
    for hi, (idx, lvl, title) in enumerate(hs):
        if re.search(pattern, title) and (level is None or lvl == level):
            start = idx + 1
            end = len(lines)
            for (idx2, lvl2, t2) in hs[hi + 1:]:
                if lvl2 <= lvl:
                    end = idx2
                    break
            return '\n'.join(lines[start:end]).strip()
    raise KeyError(pattern)

def case_slices(md):
    lines, hs = headings(md)
    res = []
    for hi, (idx, lvl, title) in enumerate(hs):
        if lvl == 2 and re.match(r'Caso \d+', title):
            end = len(lines)
            for (idx2, lvl2, t2) in hs[hi + 1:]:
                if lvl2 <= 2:
                    end = idx2
                    break
            res.append('\n'.join(lines[idx:end]).strip())
    return res

# ======================================================================
# Build chapter files
# ======================================================================
def wsec_md(title, md, ctx=None):
    return '\\section{%s}\n%s\n' % (title, body_to_latex(md, ctx=ctx or title))

def wsec_tex(title, tex):
    return '\\section{%s}\n%s\n' % (title, tex)

# ---- 00 Abstract ----
abstract = r"""\chapter*{\centering \Large Resumen}
\addcontentsline{toc}{chapter}{Resumen}
Este informe desarrolla la Gu\'ia--Taller No.~2 de mecanismos de seguridad para redes IEEE~802.3 con servicios TCP/IP. La Parte~I analiza diez casos cr\'iticos de seguridad (inundaci\'on TCP SYN, t\'unel DNS, exposici\'on de servicios heredados, detecci\'on de anomal\'ias con aprendizaje autom\'atico, resets TCP, reflexi\'on y amplificaci\'on UDP, ICMP at\'ipico, escaneo de puertos, correlaci\'on de alertas con SIEM e IA, y seguridad de mensajer\'ia XMPP sobre TLS). La Parte~II implementa un sistema de rastreo de ubicaci\'on basado en consentimiento. Conforme a las reglas del laboratorio, no se gener\'o tr\'afico de ataque contra ning\'un sistema: la evidencia se clasifica siempre como real (salidas de comandos y programas ejecutados), PCAP sint\'etica (capturas generadas con Scapy sobre direcciones privadas y medidas con un analizador propio) o escenario simulado (telemetr\'ia did\'actica). El m\'etodo prioriza la reproducibilidad: cada captura se conserva con su hash SHA-256 y todas las cifras del informe se recalculan con un script de an\'alisis. Los resultados muestran que un indicador aislado no confirma un ataque, que medir sobre la evidencia corrige suposiciones, que los controles b\'asicos son los que m\'as riesgo reducen y que el aprendizaje autom\'atico sirve para priorizar la revisi\'on humana, no para decidir bloqueos.
~\\[1cm]
\noindent
\textbf{Palabras clave:} Seguridad de redes, IEEE 802.3, TCP/IP, Wireshark, an\'alisis de PCAP, detecci\'on de anomal\'ias, aprendizaje autom\'atico, SIEM, TLS, privacidad, consentimiento.
\vfill
\noindent
\textbf{Laboratorio:} acad\'emico, aislado y autorizado. \quad \textbf{Repositorio:} \url{https://github.com/cristiannnnr/Mecanismos_Taller2}
"""
open(os.path.join(CH, '00_abstract.tex'), 'w', encoding='utf-8').write(abstract)

# ---- 01 Introduccion ----
c1 = []
c1.append(r'\chapter{Introducci\'on}')
c1.append(r'\label{ch:intro}')
c1.append(wsec_md('Resumen ejecutivo', body_of(REPORT, r'Resumen ejecutivo', level=1)))
c1.append(wsec_md(r'Presentaci\'on y alcance', body_of(GUIDE, r'Presentaci\u00f3n y alcance'), ctx='Presentación y alcance'))
c1.append(wsec_md('Objetivos', body_of(GUIDE, r'2\.\s*Objetivos')))
c1.append(wsec_md('Resultados de aprendizaje', body_of(GUIDE, r'Resultados de aprendizaje')))
c1.append(wsec_tex('Estructura del informe', (
    'El informe sigue la estructura de un reporte t\\\'ecnico. El Cap\\\'itulo~\\ref{ch:marco} '
    'resume los conceptos de red, amenazas y controles en los que se apoya el an\\\'alisis. '
    'El Cap\\\'itulo~\\ref{ch:metodo} describe la topolog\\\'ia de referencia, las herramientas, '
    'el m\\\'etodo de reproducibilidad y el formato de registro por hallazgo. El '
    'Cap\\\'itulo~\\ref{ch:parte1} presenta los diez casos cr\\\'iticos de la Parte~I con su '
    'evidencia, reglas de detecci\\\'on propuestas y medidas de defensa. El '
    'Cap\\\'itulo~\\ref{ch:parte2} documenta el sistema de rastreo por consentimiento de la '
    'Parte~II. Los Cap\\\'itulos~\\ref{ch:discusion} y~\\ref{ch:conclusiones} discuten los '
    'resultados y presentan las conclusiones y el trabajo futuro. El ap\\\'endice re\\\'une el '
    '\\\'indice de evidencias con sus hashes de integridad.')))
open(os.path.join(CH, '01_introduccion.tex'), 'w', encoding='utf-8').write('\n'.join(c1))

# ---- 02 Marco de referencia ----
c2 = r"""\chapter{Marco de referencia y trabajo relacionado}
\label{ch:marco}
Este cap\'itulo re\'une los conceptos y referencias normativas que sustentan el an\'alisis de los casos, sin anticipar los hallazgos.

\section{Red IEEE 802.3 y pila TCP/IP}
El laboratorio opera sobre una LAN Ethernet IEEE~802.3 que transporta IPv4/IPv6 y servicios TCP/IP. El protocolo TCP establece conexiones mediante un acuerdo de tres v\'ias y mantiene estado por cada conexi\'on, lo que lo hace sensible al agotamiento de recursos; su especificaci\'on vigente es el RFC~9293~\cite{rfc9293} y las mitigaciones cl\'asicas de inundaci\'on SYN se describen en el RFC~4987~\cite{rfc4987}. El sistema de nombres de dominio usa principalmente UDP/53 y se define en el RFC~1035~\cite{rfc1035}. El protocolo ICMP, usado para diagn\'ostico y notificaci\'on de errores, se define en el RFC~792~\cite{rfc792}.

\section{Amenazas y anomal\'ias de red}
Los casos abordan amenazas a la disponibilidad, la confidencialidad y la integridad: inundaci\'on TCP SYN, posible exfiltraci\'on por t\'unel DNS, reflexi\'on y amplificaci\'on UDP, escaneo de puertos, ICMP at\'ipico e inyecci\'on de resets TCP. Los ataques de amplificaci\'on basados en UDP y sus factores de referencia est\'an documentados por CISA en la alerta TA14-017A~\cite{cisa}. El an\'alisis distingue en todo momento entre s\'intoma, indicador, hip\'otesis y evidencia confirmada, y considera explicaciones benignas antes de concluir.

\section{Controles preventivos y detectivos}
Frente a estas amenazas se evaluan controles de firewall, segmentaci\'on, endurecimiento de servicios, limitaci\'on de tasa, cifrado TLS y detecci\'on con IDS/SIEM. El filtrado de direcciones de origen en el borde (BCP~38 / RFC~2827)~\cite{bcp38} es el control que impide la falsificaci\'on empleada en reflexi\'on y amplificaci\'on. Las reglas de detecci\'on se expresan para Suricata y Zeek, y los filtros de visualizaci\'on para Wireshark~\cite{tools}.

\section{Aprendizaje autom\'atico para detecci\'on de anomal\'ias}
La detecci\'on no supervisada de anomal\'ias se apoya en Isolation Forest~\cite{iforest}, que a\'isla observaciones poco frecuentes sin necesidad de etiquetas. El informe usa este modelo \'unicamente para priorizar la revisi\'on humana y contrasta su desempe\~no con una l\'inea base estad\'istica, atendiendo al desbalance de clases y a la deriva del modelo.

\section{Seguridad de la mensajer\'ia y cifrado}
La mensajer\'ia XMPP se define en el RFC~6120~\cite{rfc6120}. La protecci\'on de transporte exige TLS en versiones vigentes: el RFC~8996~\cite{rfc8996} declara obsoletas TLS~1.0 y 1.1 y el RFC~7465~\cite{rfc7465} proh\'ibe las suites RC4. El cifrado de extremo a extremo en XMPP se especifica en XEP-0384 (OMEMO)~\cite{omemo}.

\section{Privacidad y marco legal}
La Parte~II trata datos de ubicaci\'on, que en Colombia son datos personales protegidos por la Ley~1581 de 2012~\cite{ley1581}. Su tratamiento exige autorizaci\'on previa, expresa e informada, con finalidad definida y posibilidad de revocaci\'on, principio que gu\'ia el dise\~no basado en consentimiento del sistema.
"""
open(os.path.join(CH, '02_marco.tex'), 'w', encoding='utf-8').write(c2)

# ---- 03 Metodologia ----
c3 = []
c3.append(r'\chapter{Metodolog\'ia}')
c3.append(r'\label{ch:metodo}')
c3.append(wsec_md(r'Topolog\'ia de referencia', body_of(REPORT, r'Topolog\u00eda de referencia'), ctx='Topología de referencia'))
c3.append(wsec_md('Herramientas', body_of(REPORT, r'^Herramientas')))
c3.append(wsec_md(r'M\'etodo y reproducibilidad', body_of(REPORT, r'M\u00e9todo y reproducibilidad'), ctx='Método y reproducibilidad'))
c3.append(wsec_md(r'Formato m\'inimo de registro por hallazgo', body_of(GUIDE, r'Formato m\u00ednimo de registro'), ctx='Formato mínimo de registro por hallazgo'))
open(os.path.join(CH, '03_metodologia.tex'), 'w', encoding='utf-8').write('\n'.join(c3))

# ---- 04 Parte I ----
c4 = []
c4.append(r'\chapter[Parte I --- Casos cr\'iticos]{Parte I --- An\'alisis de casos cr\'iticos}')
c4.append(r'\label{ch:parte1}')
c4.append('Cada caso se documenta con su ficha de registro, el procedimiento y la evidencia '
          'analizada, las reglas de detecci\\\'on propuestas, las medidas de mitigaci\\\'on y las '
          'preguntas de an\\\'alisis. Las etiquetas indican el tipo de evidencia de cada caso.\n')
for sl in case_slices(REPORT):
    c4.append(body_to_latex(sl))
open(os.path.join(CH, '04_parte1.tex'), 'w', encoding='utf-8').write('\n\n'.join(c4))

# ---- 05 Parte II ----
c5 = []
c5.append(r'\chapter[Parte II --- Sistema de rastreo]{Parte II --- Sistema de rastreo de ubicaci\'on por consentimiento}')
c5.append(r'\label{ch:parte2}')
c5.append(body_to_latex(body_of(REPORT, r'Parte II', level=1), ctx='Sistema de rastreo por consentimiento'))
open(os.path.join(CH, '05_parte2.tex'), 'w', encoding='utf-8').write('\n'.join(c5))

# ---- 06 Discusion + 07 Conclusiones (split Conclusiones de la Parte I) ----
concl = body_of(REPORT, r'Conclusiones de la Parte I')
m = re.search(r'\*\*Oportunidades de mejora', concl)
disc_part = concl[:m.start()].strip() if m else concl
future_part = concl[m.start():].strip() if m else ''

c6 = []
c6.append(r'\chapter{Discusi\'on y an\'alisis}')
c6.append(r'\label{ch:discusion}')
c6.append('La discusi\\\'on sintetiza lo que la evidencia de los diez casos permite afirmar y '
          'lo que deja fuera de alcance.\n')
c6.append(wsec_md(r'Interpretaci\'on de los resultados', disc_part, ctx='Interpretación de los resultados'))
open(os.path.join(CH, '06_discusion.tex'), 'w', encoding='utf-8').write('\n'.join(c6))

c7 = []
c7.append(r'\chapter{Conclusiones y trabajo futuro}')
c7.append(r'\label{ch:conclusiones}')
c7.append(wsec_tex('Conclusiones', (
    'El trabajo cumple los objetivos de la gu\\\'ia: reconoce indicadores de compromiso en '
    'tr\\\'afico TCP, UDP, ICMP, DNS, HTTP/HTTPS y mensajer\\\'ia; correlaciona eventos con '
    'capturas y registros; eval\\\'ua controles preventivos y detectivos; propone un uso '
    'responsable del aprendizaje autom\\\'atico para priorizar alertas; y documenta resultados '
    'reproducibles mediante capturas, filtros, hashes y recomendaciones verificables. La Parte~II '
    'demuestra que el rastreo de ubicaci\\\'on leg\\\'itimo solo es posible con el consentimiento '
    'del titular, y la revisi\\\'on de seguridad del propio prototipo deja expl\\\'icitos los '
    'puntos pendientes antes de cualquier uso real.')))
c7.append(wsec_md('Trabajo futuro', future_part, ctx='Trabajo futuro'))
c7.append(wsec_md('Recomendaciones',
    '- Montar la topolog\u00eda en m\u00e1quinas virtuales aisladas y capturar tr\u00e1fico propio para '
    'validar las reglas de detecci\u00f3n en un IDS real.\n'
    '- Verificar las mitigaciones con medici\u00f3n antes y despu\u00e9s sobre un servicio autorizado.\n'
    '- Priorizar los controles b\u00e1sicos: cerrar servicios sin responsable, ligar a loopback lo '
    'que es local, cifrar y actualizar.\n'
    '- Corregir el hallazgo 1 de la revisi\u00f3n de seguridad de la Parte II (autorizaci\u00f3n por '
    'titular) antes de usar el sistema fuera del laboratorio.'))
open(os.path.join(CH, '07_conclusiones.tex'), 'w', encoding='utf-8').write('\n'.join(c7))

# ---- references ----
refs = r"""\begin{thebibliography}{99}
\bibitem{rfc9293} Eddy, W. (2022) \emph{RFC 9293: Transmission Control Protocol (TCP)}. Internet Engineering Task Force (IETF).
\bibitem{rfc4987} Eddy, W. (2007) \emph{RFC 4987: TCP SYN Flooding Attacks and Common Mitigations}. IETF.
\bibitem{rfc1035} Mockapetris, P. (1987) \emph{RFC 1035: Domain Names --- Implementation and Specification}. IETF.
\bibitem{rfc792} Postel, J. (1981) \emph{RFC 792: Internet Control Message Protocol}. IETF.
\bibitem{rfc6120} Saint-Andre, P. (2011) \emph{RFC 6120: Extensible Messaging and Presence Protocol (XMPP): Core}. IETF.
\bibitem{rfc8996} Moriarty, K. y Farrell, S. (2021) \emph{RFC 8996: Deprecating TLS 1.0 and TLS 1.1}. IETF.
\bibitem{rfc7465} Popov, A. (2015) \emph{RFC 7465: Prohibiting RC4 Cipher Suites}. IETF.
\bibitem{bcp38} Ferguson, P. y Senie, D. (2000) \emph{BCP 38 / RFC 2827: Network Ingress Filtering}. IETF.
\bibitem{cisa} CISA / US-CERT (2014) \emph{Alert TA14-017A: UDP-Based Amplification Attacks}.
\bibitem{omemo} XMPP Standards Foundation (2016) \emph{XEP-0384: OMEMO Encryption}.
\bibitem{iforest} Liu, F.T., Ting, K.M. y Zhou, Z.-H. (2008) `Isolation Forest', en \emph{IEEE International Conference on Data Mining (ICDM)}.
\bibitem{tools} Documentaci\'on de Suricata (reglas y \texttt{threshold}), Zeek (framework de avisos) y Wireshark (filtros de visualizaci\'on).
\bibitem{ley1581} Congreso de Colombia (2012) \emph{Ley 1581 de 2012: protecci\'on de datos personales}.
\end{thebibliography}
"""
open(os.path.join(CH, 'references.tex'), 'w', encoding='utf-8').write(refs)

# ---- appendix ----
ap = []
ap.append(r'\chapter{\'Indice de evidencias e integridad}')
ap.append(r'\label{app:evidencias}')
ap.append(body_to_latex(body_of(REPORT, r'\u00cdndice de evidencias e integridad', level=1), ctx='\u00cdndice de evidencias e integridad'))
open(os.path.join(CH, 'appendix_evidencias.tex'), 'w', encoding='utf-8').write('\n'.join(ap))

print("chapters written:", sorted(os.listdir(CH)))
