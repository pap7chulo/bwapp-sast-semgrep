#!/usr/bin/env python3
"""
generate_report.py - Genera reporte.html (dashboard navegable y autocontenido)
con los resultados SAST de Semgrep sobre bWAPP.
Requisitos previos: out/core.json, out/admin.json, out/soap.json, summary.json y charts/*.png
Uso:  python3 generate_report.py      (dentro de ~/lab-sast)
"""
import json, base64, html, os, datetime, collections

# ---------- Datos editables ----------
ESTUDIANTE = "Irvin Alexander Barrera Sabán"
CURSO = "Seguridad de Aplicaciones"
UNIVERSIDAD = "Universidad Mariano Gálvez de Guatemala"
# -------------------------------------

PROYECTOS = {"Core bWAPP": "out/core.json", "admin": "out/admin.json", "soap (NuSOAP)": "out/soap.json"}
SEV = {"ERROR": ("Alta", "alta"), "WARNING": ("Media", "media"), "INFO": ("Baja", "baja")}
E = html.escape

def linea_fuente(ruta, n):
    try:
        with open(ruta, encoding="utf-8", errors="replace") as f:
            for i, l in enumerate(f, 1):
                if i == n:
                    return l.strip()
    except OSError:
        pass
    return ""

def img64(ruta):
    with open(ruta, "rb") as f:
        return "data:image/png;base64," + base64.b64encode(f.read()).decode()

resumen = json.load(open("summary.json", encoding="utf-8"))
hallazgos = []
for proy, ruta in PROYECTOS.items():
    for r in json.load(open(ruta))["results"]:
        m = r["extra"].get("metadata", {})
        hallazgos.append(dict(
            proyecto=proy, regla=r["check_id"].split(".")[-1], sev=r["extra"]["severity"],
            owasp=m.get("owasp", ""), cwe=m.get("cwe", ""), msg=r["extra"]["message"],
            ruta=r["path"], linea=r["start"]["line"], codigo=linea_fuente(r["path"], r["start"]["line"])))

total = len(hallazgos)
pp = resumen["por_proyecto"]
fecha = datetime.date.today().strftime("%d/%m/%Y")

# ---------- Semáforo ----------
postura = [
    ("Core bWAPP", "critica", "Crítica", "SQLi masiva, RCE por eval e inyección de comandos, XSS, LFI y LDAP."),
    ("soap (NuSOAP)", "altap", "Alta", "eval() dinámico y MD5 en una librería de terceros sin mantenimiento."),
    ("admin", "mediap", "Media", "Expone phpinfo() y una contraseña embebida en settings.php."),
]
semaforo = ""
for nombre, cls, etiqueta, txt in postura:
    d = pp[nombre]
    semaforo += f"""
    <article class="luz {cls}">
      <div class="foco" aria-hidden="true"></div>
      <div>
        <h3>{E(nombre)}</h3>
        <p class="estado">Postura {etiqueta}</p>
        <p class="cifra">{d['total']} <span>hallazgos</span></p>
        <p class="desglose">{d['Alta']} altos · {d['Media']} medios · {d['Baja']} bajos</p>
        <p class="motivo">{E(txt)}</p>
      </div>
    </article>"""

# ---------- Gráficas ----------
graficas = [
    ("1_proyecto_severidad.png", "Hallazgos por proyecto y severidad"),
    ("2_severidad.png", "Distribución por severidad"),
    ("3_owasp.png", "Hallazgos por categoría OWASP Top 10 (2021)"),
    ("4_tipo_vulnerabilidad.png", "Hallazgos por tipo de vulnerabilidad"),
    ("5_top_archivos.png", "Top 10 archivos con más hallazgos (Core)"),
]
figs = "".join(f'<figure><img src="{img64("charts/"+a)}" alt="{E(t)}"><figcaption>Gráfica {i}. {E(t)}</figcaption></figure>'
               for i, (a, t) in enumerate(graficas, 1) if os.path.exists("charts/" + a))

# ---------- Hallazgos destacados ----------
destacados = [
    ("Inyección SQL", "bWAPP/app/sqli_1.php", 145, "A03:2021 / CWE-89", "alta",
     '$title = $_GET["title"];\n$sql = "SELECT * FROM movies WHERE title LIKE \'%" . sqli($title) . "%\'";\n$recordset = mysql_query($sql, $link);',
     'Consultas preparadas: $stmt = $mysqli->prepare("SELECT * FROM movies WHERE title LIKE ?"); $stmt->bind_param("s", $like);'),
    ("Inyección de comandos", "bWAPP/app/commandi.php", 140, "A03:2021 / CWE-78", "alta",
     '$target = $_POST["target"];\necho "<p>" . shell_exec("nslookup  " . commandi($target)) . "</p>";',
     "Lista blanca con preg_match, escapeshellarg($target) y salida codificada; mejor aún, dns_get_record() sin shell."),
    ("Ejecución de código (eval)", "bWAPP/app/php_eval.php", 82, "A03:2021 / CWE-95", "alta",
     '@eval($_REQUEST["eval"]);',
     "Eliminar eval(). No existe un uso seguro con entrada del usuario; usar un mapa cerrado de acciones permitidas."),
    ("XSS reflejado", "bWAPP/app/xss_get.php", 144, "A03:2021 / CWE-79", "media",
     '$firstname = $_GET["firstname"];\necho "Welcome " . xss($firstname) . " " . xss($lastname);',
     "Codificar la salida con htmlspecialchars($v, ENT_QUOTES, 'UTF-8'), más CSP y cookies HttpOnly."),
    ("Redirección abierta", "bWAPP/app/unvalidated_redir_fwd_1.php", 82, "A01:2021 / CWE-601", "media",
     'header("Location: " . $_REQUEST["url"]);',
     "Redirigir solo a destinos de una lista blanca, usando claves en lugar de URL."),
]
dest_html = ""
for titulo, ruta, ln, ow, sev, cod, rem in destacados:
    dest_html += f"""
    <details class="hallazgo">
      <summary><span class="sev {sev}">{sev.capitalize()}</span><strong>{E(titulo)}</strong>
        <code>{E(ruta)}:{ln}</code><span class="ow">{E(ow)}</span></summary>
      <pre>{E(cod)}</pre>
      <p><b>Remediación.</b> {E(rem)}</p>
    </details>"""

# ---------- Tabla completa ----------
filas = ""
for h in sorted(hallazgos, key=lambda x: (list(SEV).index(x["sev"]), x["ruta"], x["linea"])):
    nom, cls = SEV[h["sev"]]
    filas += (f'<tr data-p="{E(h["proyecto"])}" data-s="{cls}">'
              f'<td><span class="sev {cls}">{nom}</span></td><td>{E(h["proyecto"])}</td>'
              f'<td><code>{E(h["ruta"].replace("bWAPP/app/",""))}:{h["linea"]}</code></td>'
              f'<td>{E(h["regla"])}</td><td>{E(h["owasp"][:3])} · {E(h["cwe"])}</td>'
              f'<td><code class="src">{E(h["codigo"][:140])}</code></td></tr>')

owasp_li = "".join(f"<li><span>{E(k)}</span><b>{v}</b></li>" for k, v in resumen["por_owasp"].items())

doc = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reporte SAST · bWAPP · Semgrep</title>
<style>
:root{{--tinta:#1b2733;--papel:#ffffff;--fondo:#edf1f4;--linea:#cdd6de;--suave:#5a6876;
--rojo:#b3261e;--naranja:#c8620a;--ambar:#b58a00;--azul:#1f5f8b;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--fondo);color:var(--tinta);font:16px/1.6 "Source Sans 3","Segoe UI","DejaVu Sans",sans-serif}}
code,pre{{font-family:"DejaVu Sans Mono",Consolas,monospace;font-size:.85em}}
header{{background:var(--tinta);color:#fff;padding:2.5rem 1.5rem 2rem}}
header .in,main{{max-width:1150px;margin:0 auto}}
header h1{{margin:0 0 .3rem;font-size:2.1rem;line-height:1.2;font-weight:700}}
header p{{margin:.15rem 0;color:#c6d2dc}}
nav{{position:sticky;top:0;z-index:5;background:var(--papel);border-bottom:1px solid var(--linea)}}
nav .in{{max-width:1150px;margin:0 auto;display:flex;gap:1.4rem;padding:.7rem 1.5rem;overflow-x:auto}}
nav a{{color:var(--azul);text-decoration:none;white-space:nowrap;font-weight:600}}
nav a:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible{{outline:3px solid var(--azul);outline-offset:2px}}
main{{padding:1.5rem}}
section{{background:var(--papel);border:1px solid var(--linea);border-radius:6px;padding:1.6rem;margin:0 0 1.5rem}}
h2{{margin:0 0 1rem;font-size:1.45rem}}
p.lead{{max-width:75ch;color:var(--suave);margin-top:0}}
/* Semáforo: elemento central del reporte */
.semaforo{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}}
.luz{{display:flex;gap:1rem;align-items:flex-start;padding:1.2rem;border-radius:6px;border:1px solid var(--linea);border-top:6px solid}}
.foco{{flex:0 0 46px;height:46px;border-radius:50%}}
.critica{{border-top-color:var(--rojo)}} .critica .foco{{background:var(--rojo);box-shadow:0 0 0 6px #b3261e22,0 0 22px #b3261e88}}
.altap{{border-top-color:var(--naranja)}} .altap .foco{{background:var(--naranja);box-shadow:0 0 0 6px #c8620a22,0 0 22px #c8620a88}}
.mediap{{border-top-color:var(--ambar)}} .mediap .foco{{background:#e3b505;box-shadow:0 0 0 6px #e3b50522,0 0 22px #e3b50588}}
.luz h3{{margin:0;font-size:1.15rem}} .luz p{{margin:.2rem 0}}
.estado{{font-weight:700}} .critica .estado{{color:var(--rojo)}} .altap .estado{{color:var(--naranja)}} .mediap .estado{{color:var(--ambar)}}
.cifra{{font-size:2rem;font-weight:700;line-height:1.1}} .cifra span{{font-size:.95rem;font-weight:400;color:var(--suave)}}
.desglose,.motivo{{color:var(--suave);font-size:.93rem}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1rem;margin-top:1.3rem}}
.kpis div{{border-left:4px solid var(--azul);padding:.2rem .9rem}}
.kpis b{{display:block;font-size:1.6rem}} .kpis span{{color:var(--suave);font-size:.92rem}}
.owasp{{list-style:none;padding:0;margin:1rem 0 0;max-width:640px}}
.owasp li{{display:flex;justify-content:space-between;border-bottom:1px dashed var(--linea);padding:.3rem 0}}
.figs{{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:1.2rem}}
figure{{margin:0;border:1px solid var(--linea);border-radius:6px;padding:.6rem;background:#fff}}
figure img{{width:100%;height:auto;display:block}} figcaption{{font-size:.9rem;color:var(--suave);padding-top:.4rem}}
.sev{{display:inline-block;padding:.05rem .55rem;border-radius:3px;font-size:.8rem;font-weight:700;color:#fff}}
.sev.alta{{background:var(--rojo)}} .sev.media{{background:var(--naranja)}} .sev.baja{{background:var(--ambar)}}
.hallazgo{{border:1px solid var(--linea);border-radius:6px;margin:.6rem 0;padding:.2rem 1rem}}
.hallazgo summary{{cursor:pointer;display:flex;flex-wrap:wrap;gap:.7rem;align-items:center;padding:.6rem 0}}
.hallazgo .ow{{color:var(--suave);font-size:.9rem;margin-left:auto}}
pre{{background:#f4f6f8;border:1px solid var(--linea);padding:.8rem;overflow-x:auto;border-radius:4px}}
table{{width:100%;border-collapse:collapse;font-size:.9rem}}
th,td{{text-align:left;padding:.45rem .5rem;border-bottom:1px solid var(--linea);vertical-align:top}}
th{{position:sticky;top:0;background:#f4f6f8}}
.tabla{{max-height:620px;overflow:auto;border:1px solid var(--linea);border-radius:6px}}
code.src{{color:#384655;word-break:break-all}}
.filtros{{display:flex;flex-wrap:wrap;gap:.8rem;margin-bottom:.9rem;align-items:center}}
.filtros input,.filtros select{{font:inherit;padding:.4rem .6rem;border:1px solid var(--linea);border-radius:4px}}
.filtros input{{flex:1 1 260px}}
#cuenta{{color:var(--suave)}}
.triaje td:last-child{{font-weight:700}}
.ok{{color:#1e7a3c}} .fp{{color:var(--suave)}}
footer{{text-align:center;color:var(--suave);font-size:.85rem;padding:1rem 0 2rem}}
@media (max-width:600px){{.figs{{grid-template-columns:1fr}} header h1{{font-size:1.6rem}}}}
</style></head><body>
<header><div class="in">
  <h1>Evaluación SAST de bWAPP con Semgrep</h1>
  <p>{E(UNIVERSIDAD)} · {E(CURSO)}</p>
  <p>{E(ESTUDIANTE)} · Generado el {fecha} · Semgrep, 14 reglas OWASP/CWE · Repositorio raesene/bWAPP</p>
</div></header>
<nav><div class="in">
  <a href="#postura">Postura</a><a href="#graficas">Gráficas</a><a href="#destacados">Hallazgos destacados</a>
  <a href="#triaje">Triaje</a><a href="#todos">Todos los hallazgos</a><a href="#metodo">Metodología</a>
</div></nav>
<main>
<section id="postura">
  <h2>Postura de seguridad</h2>
  <p class="lead">La aplicación está en estado crítico, como corresponde a un entorno de entrenamiento. En un sistema real, estos hallazgos bloquearían el despliegue a producción.</p>
  <div class="semaforo">{semaforo}</div>
  <div class="kpis">
    <div><b>{total}</b><span>hallazgos en 198 archivos PHP</span></div>
    <div><b>{resumen['por_severidad']['Alta']}</b><span>de severidad alta</span></div>
    <div><b>{resumen['indice_riesgo_ponderado']}</b><span>índice de riesgo (Alta×5 + Media×3 + Baja×1)</span></div>
    <div><b>770</b><span>índice ajustado tras descartar 4 falsos positivos</span></div>
  </div>
  <ul class="owasp">{owasp_li}</ul>
  <h3>Prioridades de remediación</h3>
  <ol>
    <li>Parametrizar todas las consultas SQL (mysqli/PDO) y retirar la API obsoleta mysql_*.</li>
    <li>Eliminar eval() y las llamadas a la shell con entrada externa.</li>
    <li>Codificar toda salida HTML con htmlspecialchars(), más CSP y cookies HttpOnly.</li>
    <li>Sustituir MD5/SHA1/Base64 por password_hash() y cifrado autenticado; retirar credenciales embebidas, phpinfo() y NuSOAP.</li>
  </ol>
</section>
<section id="graficas"><h2>Gráficas</h2><div class="figs">{figs}</div></section>
<section id="destacados"><h2>Hallazgos destacados</h2>
  <p class="lead">Selecciona un hallazgo para ver el código vulnerable y su remediación.</p>{dest_html}</section>
<section id="triaje"><h2>Triaje de falsos positivos</h2>
  <p class="lead">La regla php-weak-crypto marcó 5 usos de base64_encode(). Base64 es codificación, no cifrado, y la autenticación HTTP Basic (RFC 7617) lo exige, así que 4 hallazgos son falsos positivos.</p>
  <div class="tabla" style="max-height:none"><table class="triaje">
    <tr><th>Archivo</th><th>Línea</th><th>Contexto</th><th>Clasificación</th></tr>
    <tr><td><code>insecure_crypt_storage_3.php</code></td><td>55</td><td>Secreto almacenado solo con Base64</td><td class="ok">Verdadero positivo</td></tr>
    <tr><td><code>soap/class.soap_transport_http.php</code></td><td>475</td><td>Cabecera Authorization: Basic</td><td class="fp">Falso positivo</td></tr>
    <tr><td><code>soap/class.soap_transport_http.php</code></td><td>586</td><td>Cabecera Proxy-Authorization: Basic</td><td class="fp">Falso positivo</td></tr>
    <tr><td><code>soap/nusoap.php</code></td><td>2629</td><td>Cabecera Authorization: Basic</td><td class="fp">Falso positivo</td></tr>
    <tr><td><code>soap/nusoap.php</code></td><td>2740</td><td>Cabecera Proxy-Authorization: Basic</td><td class="fp">Falso positivo</td></tr>
  </table></div>
  <p>Ajuste aplicado en <code>weak-crypto-v2.yml</code>: <code>pattern-not-inside: $O-&gt;setHeader(...)</code>. Resultado: de 5 a 1 hallazgo, conservando el verdadero positivo.</p>
</section>
<section id="todos"><h2>Todos los hallazgos</h2>
  <div class="filtros">
    <input id="q" type="search" placeholder="Buscar archivo, regla, CWE o código" aria-label="Buscar">
    <select id="fp" aria-label="Proyecto"><option value="">Todos los proyectos</option>{''.join(f'<option>{E(p)}</option>' for p in PROYECTOS)}</select>
    <select id="fs" aria-label="Severidad"><option value="">Todas las severidades</option><option value="alta">Alta</option><option value="media">Media</option><option value="baja">Baja</option></select>
    <span id="cuenta"></span>
  </div>
  <div class="tabla"><table>
    <thead><tr><th>Severidad</th><th>Proyecto</th><th>Archivo:línea</th><th>Regla</th><th>OWASP · CWE</th><th>Código</th></tr></thead>
    <tbody id="cuerpo">{filas}</tbody></table></div>
</section>
<section id="metodo"><h2>Metodología</h2>
<pre>semgrep scan --config php-sast-rules.yml --metrics=off --disable-version-check --no-git-ignore --timeout 0 \\
  --exclude admin --exclude soap --json -o out/core.json bWAPP/app
semgrep scan --config php-sast-rules.yml ... --json -o out/admin.json bWAPP/app/admin
semgrep scan --config php-sast-rules.yml ... --json -o out/soap.json  bWAPP/app/soap
python3 analyze.py           # gráficas y summary.json
python3 generate_report.py   # este reporte</pre>
</section>
</main>
<footer>Reporte generado automáticamente a partir de los resultados JSON de Semgrep.</footer>
<script>
const q=document.getElementById('q'),fp=document.getElementById('fp'),fs=document.getElementById('fs'),
filas=[...document.querySelectorAll('#cuerpo tr')],cuenta=document.getElementById('cuenta');
function filtrar(){{const t=q.value.toLowerCase();let n=0;
 filas.forEach(r=>{{const ok=(!fp.value||r.dataset.p===fp.value)&&(!fs.value||r.dataset.s===fs.value)&&(!t||r.textContent.toLowerCase().includes(t));
 r.hidden=!ok;if(ok)n++;}});cuenta.textContent=n+' de '+filas.length+' hallazgos';}}
[q,fp,fs].forEach(e=>e.addEventListener('input',filtrar));filtrar();
</script>
</body></html>"""

with open("reporte.html", "w", encoding="utf-8") as f:
    f.write(doc)
print(f"[+] reporte.html generado ({os.path.getsize('reporte.html')//1024} KB, {total} hallazgos)")
