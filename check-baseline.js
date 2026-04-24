#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

// Colors
const RED    = '\x1b[31m';
const GREEN  = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE   = '\x1b[34m';
const BOLD   = '\x1b[1m';
const NC     = '\x1b[0m';

const UPDATE_MODE = process.argv.includes('--update');

const threatsPath  = path.resolve(process.cwd(), 'threats-output.json');
const baselinePath = path.resolve(process.cwd(), 'security', 'baseline.json');

// --- Helpers ---

function loadJson(filePath, defaultValue) {
    if (!fs.existsSync(filePath)) return defaultValue;
    try {
        return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    } catch (e) {
        console.error(YELLOW + `Warning: could not parse ${filePath}: ${e.message}` + NC);
        return defaultValue;
    }
}

/**
 * Flatten the nested threats object from STRIDE analysis output into a flat array.
 * Each threat gets its category added as a field.
 */
function flattenThreats(threatsOutput) {
    const flat = [];
    const categories = threatsOutput.threats || {};
    for (const cat of Object.keys(categories)) {
        const list = categories[cat];
        if (Array.isArray(list)) {
            list.forEach(t => flat.push({ ...t, category: t.category || cat }));
        }
    }
    return flat;
}

/**
 * Build a normalised key from a threat for deduplication against baseline.
 * Uses category + component (lowercased, trimmed) so minor wording differences
 * in AI-generated descriptions do not create false positives.
 */
function threatKey(t) {
    const cat  = (t.category  || '').toLowerCase().trim();
    const comp = (t.component || '').toLowerCase().trim();
    return `${cat}::${comp}`;
}

/**
 * Return true when a detected threat is already covered by the baseline.
 */
function isApproved(threat, approvedThreats) {
    const key = threatKey(threat);
    return approvedThreats.some(a => threatKey(a) === key);
}

// --- Main ---

function main() {
    // 1. Load threats-output.json
    const threatsOutput = loadJson(threatsPath, null);
    if (!threatsOutput) {
        console.log(YELLOW + 'threats-output.json not found – skipping baseline check.' + NC);
        process.exit(0);
    }

    // 2. Load security/baseline.json
    const baseline = loadJson(baselinePath, { version: '1.0', last_updated: '', approved_threats: [] });
    const approvedThreats = baseline.approved_threats || [];

    // 3. Flatten detected threats
    const detected = flattenThreats(threatsOutput);

    console.log(BLUE + BOLD + '\n=== Baseline Comparison Report ===' + NC);
    console.log(`Detected threats : ${detected.length}`);
    console.log(`Baseline entries : ${approvedThreats.length}\n`);

    // 4. Classify threats
    const newThreats  = detected.filter(t => !isApproved(t, approvedThreats));
    const knownThreats = detected.filter(t =>  isApproved(t, approvedThreats));

    if (knownThreats.length > 0) {
        console.log(GREEN + `✓ ${knownThreats.length} known/approved threat(s) ignored:` + NC);
        knownThreats.forEach(t =>
            console.log(GREEN + `  - [${t.severity}] ${t.category} / ${t.component}` + NC)
        );
        console.log();
    }

    // 5. Update mode: add new threats to baseline then exit 0
    if (UPDATE_MODE) {
        if (newThreats.length === 0) {
            console.log(GREEN + '✓ No new threats to add to baseline.' + NC);
            process.exit(0);
        }

        const today = new Date().toISOString().slice(0, 10);
        const added = newThreats.map((t, i) => ({
            id:            `threat-${Date.now()}-${i}-${Math.random().toString(36).slice(2, 9)}`,
            category:      t.category   || '',
            component:     t.component  || '',
            severity:      t.severity   || '',
            approved_date: today,
            reason:        'Accepted via update-baseline'
        }));

        baseline.approved_threats = [...approvedThreats, ...added];
        baseline.last_updated = today;
        fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2));

        console.log(GREEN + `✓ Added ${added.length} threat(s) to baseline:` + NC);
        added.forEach(a =>
            console.log(GREEN + `  + [${a.severity}] ${a.category} / ${a.component}` + NC)
        );
        console.log(GREEN + '\nBaseline updated successfully.' + NC);
        process.exit(0);
    }

    // 6. Normal check mode
    if (newThreats.length === 0) {
        console.log(GREEN + BOLD + '✅ No new threats detected. Pipeline PASSES.' + NC);
        process.exit(0);
    }

    const newAlta = newThreats.filter(t => t.severity === 'Alta');

    if (newAlta.length > 0) {
        console.log(RED + BOLD + `❌ ${newAlta.length} NEW HIGH-SEVERITY threat(s) detected:\n` + NC);
        newAlta.forEach(t => {
            console.log(RED + BOLD + '--- NEW THREAT (Alta) ---' + NC);
            console.log(RED  + 'Category:    ' + NC + (t.category    || 'N/A'));
            console.log(RED  + 'Component:   ' + NC + (t.component   || 'N/A'));
            console.log(RED  + 'Description: ' + NC + (t.description || 'N/A'));
            console.log(RED  + 'Evidence:    ' + YELLOW + (t.evidence    || 'N/A') + NC);
            console.log(RED  + 'Mitigation:  ' + GREEN  + (t.mitigation  || 'N/A') + NC);
            console.log(RED  + '------------------------' + NC + '\n');
        });
        console.log(RED + BOLD + '❌ Pipeline FAILS: new Alta threats found. Run `npm run update-baseline` to approve.' + NC);
        process.exit(1);
    }

    // Only Media/Baja new threats – warn but pass
    console.log(YELLOW + BOLD + `⚠️  ${newThreats.length} new non-critical threat(s) detected (Media/Baja):` + NC);
    newThreats.forEach(t =>
        console.log(YELLOW + `  - [${t.severity}] ${t.category} / ${t.component}` + NC)
    );
    console.log(YELLOW + '\n⚠️  Pipeline PASSES (no new Alta threats).' + NC);
    process.exit(0);
}

main();
