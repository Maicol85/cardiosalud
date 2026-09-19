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


def _sanear(s):
    """Nombre de archivo temporal seguro: sin espacios ni separadores."""
    return re.sub(r'[^A-Za-z0-9_.-]', '_', s.strip()) or 'x'


def scan_files(html_paths):
    tmp = tempfile.mkdtemp(prefix='ceibo-scan-')
    mapping = {}
    # El nombre del temporal sale del ARCHIVO, no del directorio. Antes salía del
    # directorio, así que dos .html de la misma app escribían el MISMO temporal y el
    # segundo pisaba al primero: Semgrep escaneaba uno solo y el reporte lo daba por
    # completo. Medido en cardiosalud — `scan.py index.html "syntax calculator.html"`
    # devolvía 16 hallazgos (los de la calculadora) y los 103 de index.html
    # desaparecían con un ✅ verde.
    # La guarda de denominador de más abajo NO lo cazaba: al pisarse el archivo, el
    # mapeo colapsaba al mismo tamaño que lo escaneado y la comparación daba falso.
    # Con una clave por archivo, esa guarda además empieza a contar de verdad.
    vistos = {}
    for hp in html_paths:
        ap = os.path.abspath(hp)
        app = os.path.basename(os.path.dirname(ap)) or 'root'
        base = os.path.splitext(os.path.basename(ap))[0]
        clave = _sanear(app) + '__' + _sanear(base)
        # Desempate final: dos rutas distintas pueden sanear al mismo texto (un
        # «a b.html» y un «a_b.html» conviven sin problema en disco). Sin esto
        # volveríamos a pisar un archivo, que es justo lo que este cambio arregla.
        n = vistos.get(clave, 0)
        vistos[clave] = n + 1
        if n:
            clave = '%s_%d' % (clave, n + 1)
        out = os.path.join(tmp, clave + '.js')
        open(out, 'w', encoding='utf-8').write(extract_js(hp))
        # La ETIQUETA del reporte sigue siendo la app cuando es el único archivo suyo,
        # para que el barrido de toda la suite imprima exactamente lo de siempre. Con
        # varios archivos de la misma app se agrega el nombre, que es la única forma de
        # saber cuál de los dos trajo el hallazgo.
        mapping[clave] = {'app': app.strip(), 'arch': os.path.basename(ap)}
    _por_app = {}
    for v in mapping.values():
        _por_app[v['app']] = _por_app.get(v['app'], 0) + 1
    for k, v in mapping.items():
        v['lbl'] = v['app'] if _por_app[v['app']] == 1 else '%s/%s' % (v['app'], v['arch'])
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
    escaneados_l = data.get('paths', {}).get('scanned', [])
    escaneados = len(escaneados_l)
    if escaneados < len(mapping):
        # Se nombra lo que FALTA, no todo lo que se pidió. La versión anterior listaba
        # el mapeo entero bajo el rótulo «Omitidos o ilegibles», así que en el momento
        # en que la guarda importa acusaba de omitidas también a las apps que sí se
        # habían escaneado — un mensaje que manda a buscar donde no es.
        leidos = set(os.path.basename(p)[:-3] for p in escaneados_l)
        faltan = sorted(v['lbl'] for k, v in mapping.items() if k not in leidos)
        print('❌ Semgrep escaneó %d de %d archivo(s). Sin leer: %s'
              % (escaneados, len(mapping), ', '.join(faltan) if faltan else '(no identificados)'))
        for sk in data.get('paths', {}).get('skipped', [])[:10]:
            print('   · %s — %s' % (sk.get('path', '?'), sk.get('reason', '?')))
        print('   Esto NO es un resultado limpio: no se leyó el código.')
        return 2
    by_app = {}
    for it in results:
        ent = mapping.get(os.path.basename(it['path'])[:-3])
        app = ent['lbl'] if ent else it['path']
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
