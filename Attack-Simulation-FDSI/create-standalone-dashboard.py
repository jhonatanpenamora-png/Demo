#!/usr/bin/env python3
"""
Generate a self-contained standalone dashboard from combined-report.json.
The output HTML has all data embedded as a JS variable so it works via file://.
"""

import json
import sys
import re
from pathlib import Path


def create_standalone_dashboard():
    report_file = Path('combined-report.json')
    if not report_file.exists():
        print("❌ Error: combined-report.json not found")
        print("   Run the analysis pipeline first to generate it")
        sys.exit(1)

    dashboard_file = Path('dashboard.html')
    if not dashboard_file.exists():
        print("❌ Error: dashboard.html not found")
        print("   Make sure you are in the Attack-Simulation-FDSI directory")
        sys.exit(1)

    print("📊 Reading combined-report.json...")
    with open(report_file, 'r', encoding='utf-8') as f:
        report_data = json.load(f)

    print("📄 Reading dashboard.html...")
    with open(dashboard_file, 'r', encoding='utf-8') as f:
        template = f.read()

    # Embed data and replace fetch with inline loader
    data_js = json.dumps(report_data, ensure_ascii=False)

    fetch_block = (
        "fetch('combined-report.json?' + Date.now())\n"
        "            .then(r => { if (!r.ok) throw new Error('combined-report.json no encontrado'); return r.json(); })\n"
        "            .then(data => { reportData = data; renderAll(data); })\n"
        "            .catch(err => {\n"
        "                document.getElementById('threatsContainer').innerHTML =\n"
        "                    `<div class=\"error-box\">⚠️ ${err.message}<br><small>Asegúrate de estar sirviendo el dashboard con un servidor web.</small></div>`;\n"
        "                document.getElementById('reportTimestamp').textContent = 'Error al cargar datos';\n"
        "            });"
    )

    inline_block = (
        "// Datos embebidos — generado por create-standalone-dashboard.py\n"
        "        const EMBEDDED_DATA = " + data_js + ";\n"
        "        Promise.resolve(EMBEDDED_DATA)\n"
        "            .then(data => { reportData = data; renderAll(data); })\n"
        "            .catch(err => {\n"
        "                document.getElementById('threatsContainer').innerHTML =\n"
        "                    `<div class=\"error-box\">⚠️ Error cargando datos embebidos: ${err.message}</div>`;\n"
        "            });"
    )

    if fetch_block not in template:
        print("⚠️  Warning: fetch block not found verbatim — using regex fallback")
        # Regex fallback: replace the loadData function body
        pattern = r"(function loadData\(\) \{)(.*?)(\})"
        replacement = (
            r"\1\n"
            "        // Datos embebidos — generado por create-standalone-dashboard.py\n"
            "        const EMBEDDED_DATA = " + data_js + r";\n"
            "        Promise.resolve(EMBEDDED_DATA)\n"
            "            .then(data => { reportData = data; renderAll(data); });\n"
            r"    \3"
        )
        standalone = re.sub(pattern, replacement, template, flags=re.DOTALL)
    else:
        standalone = template.replace(fetch_block, inline_block)

    # Replace Chart.js CDN with local note (keep CDN, standalone still needs internet for Chart.js)
    # Chart.js is loaded from CDN — fine for file:// as long as there is internet.

    output_file = Path('dashboard-standalone.html')
    print(f"💾 Writing {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(standalone)

    # Summary
    summary = report_data.get('executive_summary', {})
    total = summary.get('total_detected', '?')
    alta = summary.get('total_alta', '?')
    media = summary.get('total_media', '?')
    baja = summary.get('total_baja', '?')
    rate = summary.get('confirmation_rate_percent', '?')

    print()
    print("✅ Standalone dashboard created successfully!")
    print()
    print(f"📊 File  : {output_file.absolute()}")
    print(f"🌐 Open  : file://{output_file.absolute()}")
    print()
    print("📈 Executive Summary:")
    print(f"   Total amenazas : {total}")
    print(f"   Alta           : {alta}")
    print(f"   Media          : {media}")
    print(f"   Baja           : {baja}")
    print(f"   Confirmación   : {rate}%")


if __name__ == '__main__':
    try:
        create_standalone_dashboard()
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
