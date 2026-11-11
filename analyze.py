#!/usr/bin/env python3
"""
analyze.py - Agrega los resultados JSON de Semgrep (core, admin, soap)
y genera las graficas del laboratorio SAST sobre bWAPP.
Uso:  python3 analyze.py        (ejecutar dentro de ~/lab-sast)
Salida: charts/*.png  y  summary.json
"""
import json, os, collections
import matplotlib
matplotlib.use("Agg")                      # sin entorno grafico
import matplotlib.pyplot as plt

PROYECTOS = {"Core bWAPP": "out/core.json", "admin": "out/admin.json", "soap (NuSOAP)": "out/soap.json"}
SEV_ORDEN = ["ERROR", "WARNING", "INFO"]
SEV_NOMBRE = {"ERROR": "Alta", "WARNING": "Media", "INFO": "Baja"}
SEV_COLOR = {"ERROR": "#c0392b", "WARNING": "#e67e22", "INFO": "#f1c40f"}
PESO = {"ERROR": 5, "WARNING": 3, "INFO": 1}

os.makedirs("charts", exist_ok=True)

# ---------- 1. Cargar y normalizar hallazgos ----------
hallazgos = []
for proyecto, ruta in PROYECTOS.items():
    with open(ruta) as f:
        datos = json.load(f)
    for r in datos["results"]:
        meta = r["extra"].get("metadata", {})
        hallazgos.append({
            "proyecto": proyecto,
            "regla": r["check_id"].split(".")[-1],
            "severidad": r["extra"]["severity"],
            "owasp": meta.get("owasp", "N/D"),
            "cwe": meta.get("cwe", "N/D"),
            "categoria": meta.get("categoria", "N/D"),
            "archivo": r["path"],
            "linea": r["start"]["line"],
        })

total = len(hallazgos)
por_sev = collections.Counter(h["severidad"] for h in hallazgos)
por_owasp = collections.Counter(h["owasp"] for h in hallazgos)
por_cat = collections.Counter(h["categoria"] for h in hallazgos)
por_archivo_core = collections.Counter(os.path.basename(h["archivo"]) for h in hallazgos if h["proyecto"] == "Core bWAPP")
por_proy_sev = {p: collections.Counter(h["severidad"] for h in hallazgos if h["proyecto"] == p) for p in PROYECTOS}
indice = sum(PESO[s] * n for s, n in por_sev.items())

def guardar(nombre):
    plt.tight_layout()
    plt.savefig(f"charts/{nombre}", dpi=150)
    plt.close()
    print(f"  [+] charts/{nombre}")

print(f"Total de hallazgos: {total}")
print("Generando graficas...")

# ---------- G1. Hallazgos por proyecto y severidad (barras apiladas) ----------
fig, ax = plt.subplots(figsize=(8, 5))
nombres = list(PROYECTOS)
base = [0] * len(nombres)
for s in SEV_ORDEN:
    vals = [por_proy_sev[p][s] for p in nombres]
    ax.bar(nombres, vals, bottom=base, color=SEV_COLOR[s], label=SEV_NOMBRE[s])
    base = [b + v for b, v in zip(base, vals)]
for i, t in enumerate(base):
    ax.text(i, t + 2, str(t), ha="center", fontweight="bold")
ax.set_title("Hallazgos por proyecto y severidad")
ax.set_ylabel("Hallazgos")
ax.legend(title="Severidad")
guardar("1_proyecto_severidad.png")

# ---------- G2. Distribucion por severidad (pastel) ----------
fig, ax = plt.subplots(figsize=(6, 6))
sevs = [s for s in SEV_ORDEN if por_sev[s]]
ax.pie([por_sev[s] for s in sevs],
       labels=[f"{SEV_NOMBRE[s]} ({por_sev[s]})" for s in sevs],
       colors=[SEV_COLOR[s] for s in sevs], autopct="%1.1f%%", startangle=90)
ax.set_title(f"Distribucion por severidad (total {total})")
guardar("2_severidad.png")

# ---------- G3. Por categoria OWASP Top 10 (2021) ----------
fig, ax = plt.subplots(figsize=(9, 5))
items = por_owasp.most_common()[::-1]
ax.barh([k for k, _ in items], [v for _, v in items], color="#2c3e50")
for i, (_, v) in enumerate(items):
    ax.text(v + 1, i, str(v), va="center")
ax.set_title("Hallazgos por categoria OWASP Top 10 (2021)")
ax.set_xlabel("Hallazgos")
guardar("3_owasp.png")

# ---------- G4. Por tipo de vulnerabilidad ----------
fig, ax = plt.subplots(figsize=(9, 6))
items = por_cat.most_common()[::-1]
ax.barh([k for k, _ in items], [v for _, v in items], color="#2980b9")
for i, (_, v) in enumerate(items):
    ax.text(v + 1, i, str(v), va="center")
ax.set_title("Hallazgos por tipo de vulnerabilidad")
ax.set_xlabel("Hallazgos")
guardar("4_tipo_vulnerabilidad.png")

# ---------- G5. Top 10 archivos con mas hallazgos (Core) ----------
fig, ax = plt.subplots(figsize=(9, 5))
items = por_archivo_core.most_common(10)[::-1]
ax.barh([k for k, _ in items], [v for _, v in items], color="#8e44ad")
for i, (_, v) in enumerate(items):
    ax.text(v + 0.1, i, str(v), va="center")
ax.set_title("Top 10 archivos con mas hallazgos (Core bWAPP)")
ax.set_xlabel("Hallazgos")
guardar("5_top_archivos.png")

# ---------- Resumen agregado ----------
resumen = {
    "total_hallazgos": total,
    "indice_riesgo_ponderado": indice,
    "formula_indice": "Alta*5 + Media*3 + Baja*1",
    "por_severidad": {SEV_NOMBRE[s]: por_sev[s] for s in SEV_ORDEN},
    "por_proyecto": {p: {"total": sum(c.values()), **{SEV_NOMBRE[s]: c[s] for s in SEV_ORDEN}} for p, c in por_proy_sev.items()},
    "por_owasp": dict(por_owasp.most_common()),
    "por_tipo": dict(por_cat.most_common()),
    "top10_archivos_core": dict(por_archivo_core.most_common(10)),
}
with open("summary.json", "w") as f:
    json.dump(resumen, f, indent=2, ensure_ascii=False)
print("  [+] summary.json")
print(json.dumps(resumen, indent=2, ensure_ascii=False))
