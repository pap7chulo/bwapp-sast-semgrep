# SAST de bWAPP con Semgrep

Laboratorio de Seguridad de Aplicaciones — Maestría en Seguridad Informática, UMG.

- `php-sast-rules.yml`: ruleset de 14 reglas mapeadas a OWASP Top 10 (2021) y CWE.
- `weak-crypto-v2.yml`: regla ajustada tras el triaje de falsos positivos.
- `analyze.py` / `generate_report.py`: gráficas y dashboard HTML.
- `.github/workflows/semgrep.yml`: en cada push escanea el código, sube el SARIF a Code Scanning y publica el dashboard en GitHub Pages.

> bWAPP es una aplicación deliberadamente vulnerable con fines de entrenamiento.
