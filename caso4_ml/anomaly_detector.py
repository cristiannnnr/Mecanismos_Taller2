"""
Caso 4 — Detector de anomalías en tráfico TCP/IP con Isolation Forest
Taller 2 - Mecanismos de Seguridad — Universidad Distrital FJDC

Uso académico. Datos sintéticos generados con NumPy; no contiene tráfico real.
Ejecutar: python anomaly_detector.py
Requiere: pip install -r requirements.txt
"""
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    RocCurveDisplay,
)

rng = np.random.default_rng(42)

# ── 1. Generación de datos sintéticos ────────────────────────────────────────
def generate_dataset(n_normal: int = 8500, n_anomalous: int = 1500) -> pd.DataFrame:
    """
    Genera un dataset con 7 características de flujo de red.
    Normal: tráfico web/DNS/ICMP de fondo.
    Anómalo: SYN flood, DNS tunneling, escaneo de puertos, ICMP flood.
    """
    # Tráfico normal
    normal = {
        "syn_ratio":     rng.uniform(0.02, 0.08, n_normal),
        "dur_seg":       rng.exponential(45, n_normal).clip(0.5, 300),
        "bytes_pkt":     rng.normal(650, 200, n_normal).clip(100, 1400),
        "unique_dsts":   rng.integers(1, 9, n_normal).astype(float),
        "fin_ratio":     rng.uniform(0.02, 0.10, n_normal),
        "dns_label_len": rng.normal(9, 3, n_normal).clip(4, 20),
        "icmp_ratio":    rng.uniform(0.001, 0.02, n_normal),
        "label":         np.zeros(n_normal, dtype=int),
    }

    # Anómalos — 4 subtipos
    n_each = n_anomalous // 4
    remainder = n_anomalous - n_each * 4

    # SYN flood
    syn_flood = {
        "syn_ratio":     rng.uniform(0.90, 1.0, n_each),
        "dur_seg":       rng.uniform(0.001, 0.05, n_each),
        "bytes_pkt":     rng.uniform(40, 60, n_each),
        "unique_dsts":   rng.integers(1, 3, n_each).astype(float),
        "fin_ratio":     rng.uniform(0, 0.001, n_each),
        "dns_label_len": rng.normal(9, 2, n_each).clip(4, 15),
        "icmp_ratio":    rng.uniform(0, 0.005, n_each),
        "label":         np.ones(n_each, dtype=int),
    }

    # DNS tunneling
    dns_tunnel = {
        "syn_ratio":     rng.uniform(0.02, 0.07, n_each),
        "dur_seg":       rng.uniform(60, 300, n_each),
        "bytes_pkt":     rng.uniform(300, 600, n_each),
        "unique_dsts":   rng.integers(1, 4, n_each).astype(float),
        "fin_ratio":     rng.uniform(0.02, 0.07, n_each),
        "dns_label_len": rng.normal(40, 8, n_each).clip(28, 63),
        "icmp_ratio":    rng.uniform(0, 0.01, n_each),
        "label":         np.ones(n_each, dtype=int),
    }

    # Escaneo de puertos
    port_scan = {
        "syn_ratio":     rng.uniform(0.80, 0.98, n_each),
        "dur_seg":       rng.uniform(0.0001, 0.01, n_each),
        "bytes_pkt":     rng.uniform(40, 70, n_each),
        "unique_dsts":   rng.integers(40, 200, n_each).astype(float),
        "fin_ratio":     rng.uniform(0, 0.002, n_each),
        "dns_label_len": rng.normal(8, 2, n_each).clip(4, 15),
        "icmp_ratio":    rng.uniform(0, 0.01, n_each),
        "label":         np.ones(n_each, dtype=int),
    }

    # ICMP flood / túnel
    icmp_attack = {
        "syn_ratio":     rng.uniform(0.001, 0.02, n_each + remainder),
        "dur_seg":       rng.uniform(60, 450, n_each + remainder),
        "bytes_pkt":     rng.uniform(1200, 1480, n_each + remainder),
        "unique_dsts":   rng.integers(1, 3, n_each + remainder).astype(float),
        "fin_ratio":     rng.uniform(0, 0.005, n_each + remainder),
        "dns_label_len": rng.normal(8, 2, n_each + remainder).clip(4, 15),
        "icmp_ratio":    rng.uniform(0.30, 0.90, n_each + remainder),
        "label":         np.ones(n_each + remainder, dtype=int),
    }

    frames = [
        pd.DataFrame(normal),
        pd.DataFrame(syn_flood),
        pd.DataFrame(dns_tunnel),
        pd.DataFrame(port_scan),
        pd.DataFrame(icmp_attack),
    ]
    df = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=42)
    return df


# ── 2. Preparación del dataset ────────────────────────────────────────────────
print("Generando dataset sintético...")
df = generate_dataset()
print(f"  Total: {len(df):,} flujos — Normal: {(df.label==0).sum():,} · Anómalos: {(df.label==1).sum():,}")

FEATURES = ["syn_ratio", "dur_seg", "bytes_pkt", "unique_dsts", "fin_ratio", "dns_label_len", "icmp_ratio"]
X = df[FEATURES].values
y = df["label"].values

# Split temporal simulado: 80% train, 20% test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

# ── 3. Modelo Isolation Forest ────────────────────────────────────────────────
print("\nEntrenando Isolation Forest...")
clf = IsolationForest(
    n_estimators=200,
    contamination=0.15,  # ~15% del tráfico de entrenamiento es anómalo
    max_features=len(FEATURES),
    random_state=42,
    n_jobs=-1,
)
clf.fit(X_train_s)

# IsolationForest: -1 = anómalo, 1 = normal → convertir a 0/1
raw_preds = clf.predict(X_test_s)
y_pred = (raw_preds == -1).astype(int)

# Score de anomalía (invertido para que valores altos = más anómalo)
scores = -clf.score_samples(X_test_s)

# ── 4. Métricas ───────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("RESULTADOS DEL MODELO")
print("="*60)
print(classification_report(y_test, y_pred, target_names=["Normal", "Anómalo"]))

auc = roc_auc_score(y_test, scores)
print(f"AUC-ROC: {auc:.4f}")

cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()
print(f"\nMatriz de confusión:")
print(f"  Verdaderos negativos (TN): {tn}")
print(f"  Falsos positivos    (FP): {fp}  ({fp/(tn+fp)*100:.1f}% de los normales)")
print(f"  Falsos negativos    (FN): {fn}  ({fn/(fn+tp)*100:.1f}% de los anómalos)")
print(f"  Verdaderos positivos(TP): {tp}")

# ── 5. Importancia de características (permutation-based proxy) ───────────────
print("\nAnálisis de características por varianza en datos anómalos vs normales:")
df_test = pd.DataFrame(X_test, columns=FEATURES)
df_test["label"] = y_test
df_test["predicted"] = y_pred

stats = df_test.groupby("label")[FEATURES].mean().T
stats.columns = ["Media_Normal", "Media_Anómalo"]
stats["Ratio"] = stats["Media_Anómalo"] / stats["Media_Normal"].replace(0, 1e-9)
stats = stats.sort_values("Ratio", ascending=False)
print(stats.round(4).to_string())

# ── 6. Visualizaciones ────────────────────────────────────────────────────────
fig, axes = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle("Caso 4 — Detector de Anomalías en Tráfico TCP/IP\nTaller 2 - Mecanismos de Seguridad", fontsize=13)

# 6a. Matriz de confusión
ax = axes[0, 0]
sns.heatmap(
    cm, annot=True, fmt="d", cmap="Blues", ax=ax,
    xticklabels=["Normal", "Anómalo"],
    yticklabels=["Normal", "Anómalo"],
)
ax.set_title("Matriz de confusión")
ax.set_ylabel("Verdad")
ax.set_xlabel("Predicción")

# 6b. Distribución del score de anomalía
ax = axes[0, 1]
ax.hist(scores[y_test == 0], bins=50, alpha=0.6, label="Normal", color="#3b82f6")
ax.hist(scores[y_test == 1], bins=50, alpha=0.6, label="Anómalo", color="#ef4444")
ax.set_title("Distribución del score de anomalía")
ax.set_xlabel("Score (mayor = más anómalo)")
ax.set_ylabel("Cantidad de flujos")
ax.legend()

# 6c. ROC Curve
ax = axes[1, 0]
RocCurveDisplay.from_predictions(y_test, scores, ax=ax, name=f"IF (AUC={auc:.3f})")
ax.set_title("Curva ROC")
ax.plot([0, 1], [0, 1], "k--", alpha=0.4)

# 6d. scatter syn_ratio vs icmp_ratio
ax = axes[1, 1]
mask_n = y_test == 0
mask_a = y_test == 1
ax.scatter(X_test[mask_n, 0], X_test[mask_n, 6], alpha=0.3, s=5, c="#3b82f6", label="Normal")
ax.scatter(X_test[mask_a, 0], X_test[mask_a, 6], alpha=0.4, s=5, c="#ef4444", label="Anómalo")
ax.set_xlabel("syn_ratio")
ax.set_ylabel("icmp_ratio")
ax.set_title("Distribución: syn_ratio vs icmp_ratio")
ax.legend(markerscale=4)

plt.tight_layout()
plt.savefig("caso4_resultados.png", dpi=150, bbox_inches="tight")
print("\nGráfica guardada en caso4_resultados.png")

# ── 7. Ejemplos de alertas anonimizadas ───────────────────────────────────────
print("\n" + "="*60)
print("EJEMPLO DE ALERTAS PRIORIZADAS (top 10 por score)")
print("="*60)

df_alerts = df_test[df_test["predicted"] == 1].copy()
df_alerts["anomaly_score"] = -clf.score_samples(
    scaler.transform(df_alerts[FEATURES].values)
)
top10 = df_alerts.nlargest(10, "anomaly_score")[FEATURES + ["anomaly_score", "label"]]
print(top10.round(4).to_string())

print(
    "\nNOTA: Este modelo es una herramienta de TRIAGE. "
    "Toda alerta requiere revisión humana antes de cualquier acción de bloqueo."
)
