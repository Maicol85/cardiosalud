#!/usr/bin/env python3
"""
CeiboMed — escáner Semgrep offline para apps HTML de un solo archivo.
Extrae el JavaScript inline de cada index.html y lo pasa por el ruleset local.

Uso:
    python3 .ceibomed-security/scan.py                 # toda la suite
    python3 .ceibomed-security/scan.py app/index.html  # una app

Código de salida: 1 si hay hallazgos de severidad ERROR (para gate de pre-push),
0 en caso contrario. Los WARNING se reportan pero no bloquean.
"""
import os, re, sys, json, tempfile, subprocess, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(HERE, 'ceibomed-rules.yml')
APPS_DIR = os.path.dirname(HERE)  # .ceibomed-security vive dentro de APLICACIONES


def find_semgrep():
    exe = shutil.which('semgrep')
    if exe:
        return [exe]
    # fallback: módulo de python
    return [sys.executable, '-m', 'semgrep']


def extract_js(html_path):
    html = open(html_path, encoding='utf-8', errors='replace').read()
    scripts = re.findall(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', html, re.S)
    return '\n;\n'.join(scripts)


def scan_files(html_paths):
    tmp = tempfile.mkdtemp(prefix='ceibo-scan-')
    mapping = {}
    for hp in html_paths:
        app = os.path.basename(os.path.dirname(os.path.abspath(hp))) or 'root'
        safe = app.strip().replace(' ', '_').replace('/', '_') + '.js'
        out = os.path.join(tmp, safe)
        open(out, 'w', encoding='utf-8').write(extract_js(hp))
        mapping[safe[:-3]] = app.strip()
    cmd = find_semgrep() + ['--config', RULES, '--disable-version-check',
                            '--metrics', 'off', '--json',
                            # Sin esto Semgrep saltea en silencio todo archivo de más de
                            # 1 MB. EcoSmart lo superó y el escáner devolvía «0 app(s)» con
                            # un ✅ al lado. Las apps de un solo archivo crecen: el límite
                            # tiene que estar holgado y la omisión no puede ser silenciosa.
                            '--max-target-bytes', '20000000', tmp]
    env = dict(os.environ, SEMGREP_SEND_METRICS='off')
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
    except FileNotFoundError:
        print('❌ Semgrep no está instalado. Ejecutá: pip install semgrep --break-system-packages')
        return 2
    finally:
        pass
    try:
        data = json.loads(r.stdout)
    except Exception:
        print('❌ Error corriendo Semgrep:\n', r.stderr[-800:])
        shutil.rmtree(tmp, ignore_errors=True)
        return 2
    shutil.rmtree(tmp, ignore_errors=True)

    results = data.get('results', [])
    # Un escáner que no escaneó nada NO es un escáner que no encontró nada. Se compara
    # contra lo que se le pidió: si Semgrep saltó archivos, se dice cuáles y por qué.
    escaneados = len(data.get('paths', {}).get('scanned', []))
    if escaneados < len(mapping):
        omitidos = [a for a in mapping.values()]
        print('❌ Semgrep escaneó %d de %d archivo(s). Omitidos o ilegibles: %s'
              % (escaneados, len(mapping), ', '.join(sorted(omitidos))))
        for sk in data.get('paths', {}).get('skipped', [])[:10]:
            print('   · %s — %s' % (sk.get('path', '?'), sk.get('reason', '?')))
        print('   Esto NO es un resultado limpio: no se leyó el código.')
        return 2
    by_app = {}
    for it in results:
        app = mapping.get(os.path.basename(it['path'])[:-3], it['path'])
        by_app.setdefault(app, []).append(it)

    n_err = sum(1 for it in results if it['extra']['severity'] == 'ERROR')
    n_warn = sum(1 for it in results if it['extra']['severity'] == 'WARNING')
    print(f'Semgrep CeiboMed — {len(results)} hallazgos '
          f'(🔴 {n_err} ERROR · 🟡 {n_warn} WARNING) en {len(by_app)} app(s)')
    for app in sorted(by_app):
        items = by_app[app]
        errs = [x for x in items if x['extra']['severity'] == 'ERROR']
        mark = '🔴' if errs else '🟡'
        print(f'  {mark} {app}: {len(items)} '
              f'({len(errs)} ERROR)')
        for it in errs:
            rid = it['check_id'].split('.')[-1]
            print(f'       ERROR L{it["start"]["line"]} · {rid}')
    if n_err:
        print('\n❌ Hallazgos ERROR presentes — resolver antes de push (CLAUDE.md Nivel 2).')
        return 1
    print('\n✅ Sin hallazgos de severidad ERROR.')
    return 0


def main():
    args = sys.argv[1:]
    if args:
        paths = [a for a in args if os.path.isfile(a)]
        if not paths:
            print('No se encontró el archivo indicado.')
            return 2
    else:
        paths = []
        for d in sorted(os.listdir(APPS_DIR)):
            p = os.path.join(APPS_DIR, d, 'index.html')
            if os.path.isfile(p):
                paths.append(p)
    return scan_files(paths)


if __name__ == '__main__':
    sys.exit(main())
