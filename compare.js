#!/usr/bin/env node
'use strict';

/**
 * compare.js - US-08: Manual vs Automated STRIDE Comparison
 *
 * Usage:
 *   node compare.js
 *   node compare.js --manual-insecure <path> --manual-secure <path> --automated <path>
 *
 * By default uses:
 *   manual-analysis-insecure.json
 *   manual-analysis-secure.json
 *   Attack-Simulation-FDSI/combined-report.json  (combined_threats field)
 *
 * Outputs:
 *   metrics-report.json
 *   metrics-report.html
 */

const fs   = require('fs');
const path = require('path');

// ─── STRIDE canonical category names ──────────────────────────────────────────
const STRIDE_CATEGORIES = [
  'Spoofing',
  'Tampering',
  'Repudiation',
  'InformationDisclosure',
  'DenialOfService',
  'ElevationOfPrivilege'
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Normalise a string for deterministic matching:
 * lowercase, trim, collapse whitespace, remove non-alphanumeric chars.
 */
function normalize(str) {
  return (str || '')
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '')
    .replace(/[^a-z0-9]/g, '');
}

/**
 * Build a normalised ID for a threat item.
 * Format: <category>|<component>|<severity>
 */
function threatId(threat) {
  const cat  = normalize(threat.category   || '');
  const comp = normalize(threat.component  || threat.description || '');
  const sev  = normalize(threat.severity   || '');
  return `${cat}|${comp}|${sev}`;
}

function loadJson(filePath) {
  const absPath = path.resolve(process.cwd(), filePath);
  if (!fs.existsSync(absPath)) {
    console.error(`\x1b[31mError: file not found: ${absPath}\x1b[0m`);
    process.exit(1);
  }
  try {
    return JSON.parse(fs.readFileSync(absPath, 'utf-8'));
  } catch (e) {
    console.error(`\x1b[31mError: could not parse ${absPath}: ${e.message}\x1b[0m`);
    process.exit(1);
  }
}

function parseArgs() {
  const args   = process.argv.slice(2);
  const result = {
    manualInsecurePath : 'manual-analysis-insecure.json',
    manualSecurePath   : 'manual-analysis-secure.json',
    automatedPath      : 'Attack-Simulation-FDSI/combined-report.json'
  };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--manual-insecure' && args[i + 1]) { result.manualInsecurePath = args[++i]; }
    if (args[i] === '--manual-secure'   && args[i + 1]) { result.manualSecurePath   = args[++i]; }
    if (args[i] === '--automated'       && args[i + 1]) { result.automatedPath      = args[++i]; }
  }
  return result;
}

// ─── Core metrics calculation ─────────────────────────────────────────────────

/**
 * Compute TP/FP/FN and derived metrics given two threat arrays.
 * @param {object[]} manualThreats   - Threats from manual analysis (ground truth).
 * @param {object[]} autoThreats     - Threats from automated analysis.
 * @returns {object} metrics object
 */
function computeMetrics(manualThreats, autoThreats) {
  // Build id → threat maps (deduplicated; last duplicate wins)
  const manualMap = new Map();
  manualThreats.forEach(t => manualMap.set(threatId(t), t));

  const autoMap = new Map();
  autoThreats.forEach(t => autoMap.set(threatId(t), t));

  const allAutoIds   = [...autoMap.keys()];
  const allManualIds = [...manualMap.keys()];

  const tpItems = allAutoIds
    .filter(id => manualMap.has(id))
    .map(id => ({ id, threat: autoMap.get(id) }));

  const fpItems = allAutoIds
    .filter(id => !manualMap.has(id))
    .map(id => ({ id, threat: autoMap.get(id) }));

  const fnItems = allManualIds
    .filter(id => !autoMap.has(id))
    .map(id => ({ id, threat: manualMap.get(id) }));

  const TP = tpItems.length;
  const FP = fpItems.length;
  const FN = fnItems.length;

  const precision = (TP + FP) === 0 ? null : TP / (TP + FP);
  const recall    = (TP + FN) === 0 ? null : TP / (TP + FN);
  const f1        = (precision !== null && recall !== null && (precision + recall) > 0)
    ? 2 * precision * recall / (precision + recall)
    : null;

  // STRIDE coverage per scenario
  const manualCats   = new Set(manualThreats.map(t => normalize(t.category)));
  const tpCats       = new Set(tpItems.map(item => item.id.split('|')[0]));
  const strideCoverage = manualCats.size === 0
    ? null
    : [...manualCats].filter(c => tpCats.has(c)).length / manualCats.size;

  // Breakdown by severity
  const bySeverity = {};
  ['Alta', 'Media', 'Baja'].forEach(sev => {
    const s = normalize(sev);
    bySeverity[sev] = {
      TP: tpItems.filter(x => x.id.split('|')[2] === s).length,
      FP: fpItems.filter(x => x.id.split('|')[2] === s).length,
      FN: fnItems.filter(x => x.id.split('|')[2] === s).length
    };
  });

  // Breakdown by STRIDE category
  const byCategory = {};
  STRIDE_CATEGORIES.forEach(cat => {
    const c = normalize(cat);
    byCategory[cat] = {
      TP: tpItems.filter(x => x.id.split('|')[0] === c).length,
      FP: fpItems.filter(x => x.id.split('|')[0] === c).length,
      FN: fnItems.filter(x => x.id.split('|')[0] === c).length
    };
  });

  return {
    counts: { TP, FP, FN },
    precision       : precision !== null ? +precision.toFixed(4) : null,
    recall          : recall    !== null ? +recall.toFixed(4)    : null,
    f1              : f1        !== null ? +f1.toFixed(4)        : null,
    strideCoverage  : strideCoverage !== null ? +strideCoverage.toFixed(4) : null,
    bySeverity,
    byCategory,
    details         : { tp: tpItems, fp: fpItems, fn: fnItems }
  };
}

// ─── HTML generation ──────────────────────────────────────────────────────────

function pct(v) {
  if (v === null || v === undefined) return 'N/A';
  return (v * 100).toFixed(1) + '%';
}

function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function metricCards(m, title) {
  const prec  = m.precision !== null ? pct(m.precision) : 'N/A';
  const rec   = m.recall    !== null ? pct(m.recall)    : 'N/A';
  const f1    = m.f1        !== null ? pct(m.f1)        : 'N/A';
  const cov   = m.strideCoverage !== null ? pct(m.strideCoverage) : 'N/A';
  return `
  <div class="section">
    <h2>${escHtml(title)}</h2>
    <div class="cards">
      <div class="card blue"><div class="card-value">${prec}</div><div class="card-label">Precision</div></div>
      <div class="card green"><div class="card-value">${rec}</div><div class="card-label">Recall</div></div>
      <div class="card purple"><div class="card-value">${f1}</div><div class="card-label">F1 Score</div></div>
      <div class="card orange"><div class="card-value">${cov}</div><div class="card-label">STRIDE Coverage</div></div>
      <div class="card teal"><div class="card-value">${m.counts.TP}</div><div class="card-label">True Positives</div></div>
      <div class="card red"><div class="card-value">${m.counts.FP}</div><div class="card-label">False Positives</div></div>
      <div class="card yellow"><div class="card-value">${m.counts.FN}</div><div class="card-label">False Negatives</div></div>
    </div>
  </div>`;
}

function categoryTable(m, scenarioId) {
  const rows = STRIDE_CATEGORIES.map(cat => {
    const d = m.byCategory[cat] || { TP: 0, FP: 0, FN: 0 };
    return `
      <tr>
        <td><span class="badge">${escHtml(cat)}</span></td>
        <td class="num tp">${d.TP}</td>
        <td class="num fp">${d.FP}</td>
        <td class="num fn">${d.FN}</td>
      </tr>`;
  }).join('');

  return `
  <div class="section">
    <h3>STRIDE Category Breakdown</h3>
    <table>
      <thead><tr><th>Category</th><th>TP ✅</th><th>FP ⚠️</th><th>FN ❌</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function severityTable(m) {
  const rows = ['Alta', 'Media', 'Baja'].map(sev => {
    const d = m.bySeverity[sev] || { TP: 0, FP: 0, FN: 0 };
    const cls = sev === 'Alta' ? 'sev-alta' : sev === 'Media' ? 'sev-media' : 'sev-baja';
    return `
      <tr>
        <td><span class="${cls}">${escHtml(sev)}</span></td>
        <td class="num tp">${d.TP}</td>
        <td class="num fp">${d.FP}</td>
        <td class="num fn">${d.FN}</td>
      </tr>`;
  }).join('');

  return `
  <div class="section">
    <h3>Severity Breakdown</h3>
    <table>
      <thead><tr><th>Severity</th><th>TP ✅</th><th>FP ⚠️</th><th>FN ❌</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function detailsSection(items, type, label, colorClass, uid) {
  if (items.length === 0) {
    return `<p class="empty">No ${label} found.</p>`;
  }
  const rows = items.map(item => {
    const t   = item.threat || {};
    const cat = escHtml(t.category  || item.id.split('|')[0] || '–');
    const com = escHtml(t.component || item.id.split('|')[1] || '–');
    const sev = escHtml(t.severity  || item.id.split('|')[2] || '–');
    const desc = escHtml(t.description || '');
    return `<tr>
      <td><span class="badge">${cat}</span></td>
      <td>${com}</td>
      <td><span class="sev-${sev.toLowerCase()}">${sev}</span></td>
      <td>${desc}</td>
    </tr>`;
  }).join('');

  return `
  <details id="${uid}">
    <summary class="${colorClass}">${label} (${items.length})</summary>
    <table>
      <thead><tr><th>Category</th><th>Component</th><th>Severity</th><th>Description</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </details>`;
}

function generateHtml(report) {
  const ts = new Date(report.metadata.timestamp).toLocaleString();
  const g  = report.global;
  const ins = report.scenarios.insecure;
  const sec = report.scenarios.secure;

  const insDetails = `
    ${detailsSection(ins.details.fp, 'fp', 'False Positives (automated only)', 'det-fp', 'ins-fp')}
    ${detailsSection(ins.details.fn, 'fn', 'False Negatives (manual only)',     'det-fn', 'ins-fn')}
    ${detailsSection(ins.details.tp, 'tp', 'True Positives (matched)',          'det-tp', 'ins-tp')}`;

  const secDetails = `
    ${detailsSection(sec.details.fp, 'fp', 'False Positives (automated only)', 'det-fp', 'sec-fp')}
    ${detailsSection(sec.details.fn, 'fn', 'False Negatives (manual only)',     'det-fn', 'sec-fn')}
    ${detailsSection(sec.details.tp, 'tp', 'True Positives (matched)',          'det-tp', 'sec-tp')}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>STRIDE Comparison Metrics Report</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --subtext: #8b949e;
    --blue: #388bfd; --green: #3fb950; --red: #f85149;
    --purple: #bc8cff; --orange: #d29922; --teal: #39c5cf;
    --yellow: #e3b341;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 24px; }
  h1 { font-size: 1.8rem; margin-bottom: 4px; }
  .subtitle { color: var(--subtext); margin-bottom: 32px; font-size: 0.9rem; }
  .section { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 24px; }
  h2 { font-size: 1.2rem; margin-bottom: 16px; color: var(--blue); }
  h3 { font-size: 1rem; margin-bottom: 12px; color: var(--subtext); }
  .cards { display: flex; flex-wrap: wrap; gap: 14px; }
  .card { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; min-width: 120px; text-align: center; }
  .card-value { font-size: 2rem; font-weight: 700; }
  .card-label { font-size: 0.75rem; color: var(--subtext); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .card.blue   .card-value { color: var(--blue); }
  .card.green  .card-value { color: var(--green); }
  .card.red    .card-value { color: var(--red); }
  .card.purple .card-value { color: var(--purple); }
  .card.orange .card-value { color: var(--orange); }
  .card.teal   .card-value { color: var(--teal); }
  .card.yellow .card-value { color: var(--yellow); }
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  th { text-align: left; padding: 8px 12px; color: var(--subtext); border-bottom: 1px solid var(--border); }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .num { text-align: center; font-weight: 600; font-size: 1rem; }
  .tp { color: var(--green); }
  .fp { color: var(--red); }
  .fn { color: var(--yellow); }
  .badge { background: #21262d; border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; font-size: 0.8rem; white-space: nowrap; }
  .sev-alta  { color: var(--red); font-weight: 600; }
  .sev-media { color: var(--orange); font-weight: 600; }
  .sev-baja  { color: var(--green); font-weight: 600; }
  details { border: 1px solid var(--border); border-radius: 8px; margin-bottom: 10px; overflow: hidden; }
  summary { padding: 12px 16px; cursor: pointer; font-weight: 600; user-select: none; }
  details[open] summary { border-bottom: 1px solid var(--border); }
  summary.det-fp { background: rgba(248,81,73,0.12); color: var(--red); }
  summary.det-fn { background: rgba(227,179,65,0.12); color: var(--yellow); }
  summary.det-tp { background: rgba(63,185,80,0.12); color: var(--green); }
  details table { margin: 0; }
  details td, details th { background: var(--bg); }
  .empty { color: var(--subtext); font-style: italic; margin: 8px 0; }
  .tabs { display: flex; gap: 0; margin-bottom: -1px; }
  .tab { padding: 10px 20px; cursor: pointer; border: 1px solid var(--border); border-bottom: none; border-radius: 6px 6px 0 0; background: var(--bg); color: var(--subtext); font-weight: 600; }
  .tab.active { background: var(--surface); color: var(--text); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  .tab-wrap { border: 1px solid var(--border); border-radius: 0 8px 8px 8px; background: var(--surface); padding: 20px; margin-bottom: 24px; }
  @media (max-width: 640px) { .cards { flex-direction: column; } }
</style>
</head>
<body>
<h1>🛡️ STRIDE Comparison Metrics Report</h1>
<p class="subtitle">Generated: ${escHtml(ts)} &nbsp;·&nbsp; Automated source: <code>${escHtml(report.metadata.inputs.automated)}</code></p>

${metricCards(g, '🌐 Global Metrics (Both Scenarios)')}

<div class="section">
  <h3>Global STRIDE Category Breakdown</h3>
  <table>
    <thead><tr><th>Category</th><th>TP ✅</th><th>FP ⚠️</th><th>FN ❌</th></tr></thead>
    <tbody>${STRIDE_CATEGORIES.map(cat => {
      const d = g.byCategory[cat] || { TP: 0, FP: 0, FN: 0 };
      return `<tr><td><span class="badge">${escHtml(cat)}</span></td><td class="num tp">${d.TP}</td><td class="num fp">${d.FP}</td><td class="num fn">${d.FN}</td></tr>`;
    }).join('')}
    </tbody>
  </table>
</div>

<div class="tabs">
  <div class="tab active" onclick="showTab('insecure', this)">🔴 Insecure Scenario</div>
  <div class="tab" onclick="showTab('secure', this)">🟢 Secure Scenario</div>
</div>
<div class="tab-wrap">
  <div id="tab-insecure" class="tab-content active">
    ${metricCards(ins, 'Insecure Scenario')}
    ${categoryTable(ins, 'insecure')}
    ${severityTable(ins)}
    <div class="section"><h3>Details</h3>${insDetails}</div>
  </div>
  <div id="tab-secure" class="tab-content">
    ${metricCards(sec, 'Secure Scenario')}
    ${categoryTable(sec, 'secure')}
    ${severityTable(sec)}
    <div class="section"><h3>Details</h3>${secDetails}</div>
  </div>
</div>

<script>
function showTab(name, el) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  el.classList.add('active');
}
</script>
</body>
</html>`;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

function main() {
  const args = parseArgs();

  console.log('\x1b[1m\x1b[34m=== US-08: STRIDE Manual vs Automated Comparison ===\x1b[0m\n');

  // Load inputs
  const insecureManual = loadJson(args.manualInsecurePath);
  const secureManual   = loadJson(args.manualSecurePath);
  const autoReport     = loadJson(args.automatedPath);

  const autoThreats = autoReport.combined_threats || [];
  if (autoThreats.length === 0) {
    console.warn('\x1b[33mWarning: no combined_threats found in automated report.\x1b[0m');
  }

  // Per-scenario metrics
  const insecureMetrics = computeMetrics(insecureManual.threats || [], autoThreats);
  const secureMetrics   = computeMetrics(secureManual.threats   || [], autoThreats);

  // Global metrics: deduplicated union of both manual sets vs auto
  const allManualThreats = [
    ...(insecureManual.threats || []),
    ...(secureManual.threats   || [])
  ];
  const globalMetrics = computeMetrics(allManualThreats, autoThreats);

  // Build report object
  const report = {
    metadata: {
      timestamp: new Date().toISOString(),
      inputs: {
        automated       : args.automatedPath,
        manual_insecure : args.manualInsecurePath,
        manual_secure   : args.manualSecurePath
      }
    },
    global   : globalMetrics,
    scenarios: {
      insecure: insecureMetrics,
      secure  : secureMetrics
    }
  };

  // Write JSON report
  fs.writeFileSync('metrics-report.json', JSON.stringify(report, null, 2));

  // Write HTML report
  fs.writeFileSync('metrics-report.html', generateHtml(report));

  // ── Console summary ──────────────────────────────────────────────────────────
  const g = globalMetrics;
  console.log('\x1b[1mGlobal Metrics\x1b[0m');
  console.log(`  Precision       : \x1b[34m${pct(g.precision)}\x1b[0m`);
  console.log(`  Recall          : \x1b[32m${pct(g.recall)}\x1b[0m`);
  console.log(`  F1 Score        : \x1b[35m${pct(g.f1)}\x1b[0m`);
  console.log(`  STRIDE Coverage : \x1b[33m${pct(g.strideCoverage)}\x1b[0m`);
  console.log(`  True Positives  : \x1b[32m${g.counts.TP}\x1b[0m`);
  console.log(`  False Positives : \x1b[31m${g.counts.FP}\x1b[0m`);
  console.log(`  False Negatives : \x1b[33m${g.counts.FN}\x1b[0m`);

  console.log('\n\x1b[1mInsecure Scenario\x1b[0m');
  const i = insecureMetrics;
  console.log(`  Precision: ${pct(i.precision)}  Recall: ${pct(i.recall)}  F1: ${pct(i.f1)}  Coverage: ${pct(i.strideCoverage)}`);
  console.log(`  TP=${i.counts.TP}  FP=${i.counts.FP}  FN=${i.counts.FN}`);

  console.log('\n\x1b[1mSecure Scenario\x1b[0m');
  const s = secureMetrics;
  console.log(`  Precision: ${pct(s.precision)}  Recall: ${pct(s.recall)}  F1: ${pct(s.f1)}  Coverage: ${pct(s.strideCoverage)}`);
  console.log(`  TP=${s.counts.TP}  FP=${s.counts.FP}  FN=${s.counts.FN}`);

  console.log('\n\x1b[32m✓ Reports generated:\x1b[0m');
  console.log('  metrics-report.json');
  console.log('  metrics-report.html\n');
}

main();
