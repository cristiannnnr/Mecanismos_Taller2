# -*- coding: utf-8 -*-
"""
Caso 4 - Comparacion: linea base estadistica vs Isolation Forest
Taller 2 - Mecanismos de Seguridad - Universidad Distrital FJDC

Complementa anomaly_detector.py con lo que pide la guia:
  1. Separacion entrenamiento/evaluacion por ORDEN TEMPORAL (sin barajar): el
     primer 80 % de los flujos entrena y el ultimo 20 % evalua.
  2. Linea base estadistica: z-score robusto (mediana / MAD) por caracteristica;
     un flujo es anomalo si alguna caracteristica supera |z| > 3.5.
  3. Detector de anomalias: Isolation Forest (mismos hiperparametros del script
     principal).
Datos 100 % sinteticos (mismo generador y semilla que anomaly_detector.py).
Ejecutar:  python comparar_linea_base.py
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (confusion_matrix, precision_recall_fscore_support,
                             roc_auc_score, roc_curve)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Reutiliza el generador del script principal (solo la parte de definicion).
src = (Path(__file__).parent / "anomaly_detector.py").read_text(encoding="utf-8")
ns = {}
exec(src.split("# ── 2.")[0].split('"""', 2)[2], ns)
df = ns["generate_dataset"]().reset_index(drop=True)

FEATURES = ["syn_ratio", "dur_seg", "bytes_pkt", "unique_dsts", "fin_ratio", "dns_label_len", "icmp_ratio"]
cut = int(len(df) * 0.8)
train, test = df.iloc[:cut], df.iloc[cut:]
Xtr, Xte, yte = train[FEATURES].values, test[FEATURES].values, test["label"].values
print(f"Flujos: {len(df)}  |  entrenamiento (primer 80 %): {len(train)}  |  evaluacion (ultimo 20 %): {len(test)}")
print(f"Anomalos en evaluacion: {int(yte.sum())} ({yte.mean() * 100:.1f} %)\n")

# 1) Linea base: z-score robusto
med = np.median(Xtr, axis=0)
mad = np.median(np.abs(Xtr - med), axis=0) * 1.4826
z = np.abs((Xte - med) / mad)
score_base = z.max(axis=1)
pred_base = (score_base > 3.5).astype(int)

# 2) Isolation Forest
sc = StandardScaler().fit(Xtr)
clf = IsolationForest(n_estimators=200, contamination=0.15, random_state=42, n_jobs=-1).fit(sc.transform(Xtr))
score_if = -clf.score_samples(sc.transform(Xte))
pred_if = (clf.predict(sc.transform(Xte)) == -1).astype(int)

rows = []
for name, pred, score in [("Linea base z-score robusto", pred_base, score_base),
                          ("Isolation Forest", pred_if, score_if)]:
    tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
    p, r, f1, _ = precision_recall_fscore_support(yte, pred, average="binary")
    rows.append((name, tp, fp, fn, tn, p, r, f1, roc_auc_score(yte, score), fp / (fp + tn) * 100))
print(f"{'Detector':<28} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>5} {'Precision':>9} {'Recall':>7} {'F1':>6} {'AUC':>6} {'FP %':>6}")
for r in rows:
    print(f"{r[0]:<28} {r[1]:>4} {r[2]:>4} {r[3]:>4} {r[4]:>5} {r[5]:>9.3f} {r[6]:>7.3f} {r[7]:>6.3f} {r[8]:>6.3f} {r[9]:>6.2f}")

print("\nRecall por subtipo de anomalia (evaluacion):")
sub = np.where(test["syn_ratio"] > 0.75, np.where(test["unique_dsts"] >= 40, "Escaneo de puertos", "SYN flood"),
               np.where(test["icmp_ratio"] >= 0.3, "ICMP flood/tunel",
                        np.where(test["dns_label_len"] >= 28, "DNS tunneling", "otro")))
print(f"{'Subtipo':<20} {'n':>4} {'Linea base':>11} {'IForest':>8}")
for s in ["SYN flood", "Escaneo de puertos", "DNS tunneling", "ICMP flood/tunel"]:
    m = (sub == s) & (yte == 1)
    print(f"{s:<20} {m.sum():>4} {pred_base[m].mean():>11.3f} {pred_if[m].mean():>8.3f}")

BLUE, ORANGE, INK, MUTED, GRID = "#2a78d6", "#eb6834", "#0b0b0b", "#898781", "#e1e0d9"
fig, ax = plt.subplots(1, 2, figsize=(11, 4.2), facecolor="#fcfcfb")
for a in ax:
    a.set_facecolor("#fcfcfb"); a.grid(color=GRID, lw=0.8); a.set_axisbelow(True)
    for s in ("top", "right"): a.spines[s].set_visible(False)
    for s in ("left", "bottom"): a.spines[s].set_color("#c3c2b7")
    a.tick_params(colors=MUTED)
for (name, pred, score), col in zip([("Línea base (z-score robusto)", pred_base, score_base),
                                     ("Isolation Forest", pred_if, score_if)], [BLUE, ORANGE]):
    fpr, tpr, _ = roc_curve(yte, score)
    ax[0].plot(fpr, tpr, color=col, lw=2, label=f"{name} · AUC {roc_auc_score(yte, score):.3f}")
ax[0].plot([0, 1], [0, 1], color=MUTED, lw=1, ls="--")
ax[0].set_xlim(-0.01, 0.3); ax[0].set_ylim(0.6, 1.005)
ax[0].set_xlabel("Tasa de falsos positivos", color=INK); ax[0].set_ylabel("Recall (tasa de verdaderos positivos)", color=INK)
ax[0].set_title("Curva ROC (zona de interés)", loc="left", color=INK, fontsize=11); ax[0].legend(frameon=False, loc="lower right")
x = np.arange(3); w = 0.36
for i, (r, col, lab) in enumerate(zip(rows, [BLUE, ORANGE], ["Línea base", "Isolation Forest"])):
    b = ax[1].bar(x + (i - 0.5) * (w + 0.03), [r[5], r[6], r[7]], w, color=col, label=lab)
    for rect, v in zip(b, [r[5], r[6], r[7]]):
        ax[1].text(rect.get_x() + rect.get_width() / 2, v + 0.012, f"{v:.2f}", ha="center", color=INK, fontsize=9)
ax[1].set_xticks(x); ax[1].set_xticklabels(["Precisión", "Recall", "F1"], color=INK); ax[1].set_ylim(0, 1.25)
ax[1].set_title("Métricas sobre el 20 % final (evaluación)", loc="left", color=INK, fontsize=11); ax[1].legend(frameon=False, ncol=2, loc="upper left")
ax[1].grid(axis="x", visible=False)
plt.tight_layout()
out = Path(__file__).parent / "caso4_comparacion_linea_base.png"
plt.savefig(out, dpi=150, facecolor=fig.get_facecolor())
print(f"\nGrafica guardada en {out.name}")
