const { ipcRenderer } = require('electron');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

let activeTarget = '';
let currentAIMode = 'ask';
let modules = {};
const PROJECT_ROOT = path.join(__dirname, '..');

// ── BACKGROUND PARTICLES ────────────────────────────────────────────────

const canvas = document.getElementById('particleCanvas');
const ctx = canvas.getContext('2d');
let particles = [];
function initParticles() {
    canvas.width = window.innerWidth; canvas.height = window.innerHeight;
    particles = [];
    for (let i = 0; i < 60; i++) {
        particles.push({ x: Math.random()*canvas.width, y: Math.random()*canvas.height, vx: (Math.random()-0.5)*0.5, vy: (Math.random()-0.5)*0.5, size: Math.random()*3 });
    }
}
let mouse = { x: null, y: null };
window.addEventListener('mousemove', (e) => { mouse.x = e.x; mouse.y = e.y; });
function animateParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'rgba(255, 34, 68, 0.4)'; ctx.strokeStyle = 'rgba(255, 34, 68, 0.1)';
    particles.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2); ctx.fill();
        const dx = mouse.x - p.x; const dy = mouse.y - p.y;
        if (Math.sqrt(dx*dx + dy*dy) < 150) { ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(mouse.x, mouse.y); ctx.stroke(); }
    });
    requestAnimationFrame(animateParticles);
}

// ── SIDEBAR & AI HOVER LOGIC ─────────────────────────────────────────────

const sidebar = document.getElementById('sidebar');
const logoTrigger = document.getElementById('logoTrigger');
const aiTrigger = document.getElementById('aiTrigger');
const aiContainer = document.getElementById('aiContainer');

logoTrigger.onmouseenter = () => { sidebar.classList.remove('-translate-x-full'); sidebar.classList.add('translate-x-0'); sidebar.style.pointerEvents = 'auto'; };
sidebar.onmouseleave = () => { sidebar.classList.add('-translate-x-full'); sidebar.classList.remove('translate-x-0'); sidebar.style.pointerEvents = 'none'; };

// FIX: Track whether user manually closed so hover doesn't reopen it
let aiManuallyOpen = false;

aiTrigger.onmouseenter = () => {
    if (!aiManuallyOpen) {
        aiContainer.classList.remove('translate-x-full');
        aiContainer.classList.add('translate-x-0');
    }
};

function toggleAI() {
    const isHidden = aiContainer.classList.contains('translate-x-full');
    if (isHidden) {
        aiContainer.classList.remove('translate-x-full');
        aiContainer.classList.add('translate-x-0');
        aiManuallyOpen = true;
    } else {
        aiContainer.classList.add('translate-x-full');
        aiContainer.classList.remove('translate-x-0');
        aiManuallyOpen = false;
    }
}

// The × button inside the panel calls this — distinct from toggleAI
// so there's no ambiguity about open/close state
function closeAI() {
    aiContainer.classList.add('translate-x-full');
    aiContainer.classList.remove('translate-x-0');
    aiManuallyOpen = false;
}

// ── AI PANEL RESIZE ────────────────────────────────────────────────────
// Same drag-resize pattern as the repro shell so the chatbox can be expanded
// when AI responses are long and need more reading space.

const aiResizeHandle = document.getElementById('aiResizeHandle');
if (aiResizeHandle) {
    let aiResizing = false, aiStartX, aiStartW;
    aiResizeHandle.onmousedown = (e) => {
        aiResizing = true;
        aiStartX = e.clientX;
        aiStartW = aiContainer.offsetWidth;
        document.onmousemove = (ev) => {
            if (!aiResizing) return;
            // Dragging left expands, right shrinks (panel is on the right edge)
            const newW = Math.max(320, Math.min(700, aiStartW - (ev.clientX - aiStartX)));
            aiContainer.style.width = newW + 'px';
        };
        document.onmouseup = () => { aiResizing = false; document.onmousemove = null; };
    };
}

function showSection(id, el) {
    document.querySelectorAll('.nav-item').forEach(li => {
        li.classList.remove('active', 'text-primary', 'bg-primary/10', 'border-l-4', 'border-primary');
        li.classList.add('text-white/30');
    });
    if (el) el.classList.add('active', 'text-primary', 'bg-primary/10', 'border-l-4', 'border-primary');
    document.querySelectorAll('.content-area').forEach(sec => sec.classList.add('hidden'));
    const target = document.getElementById(id);
    if (target) {
        target.classList.remove('hidden');
        target.classList.add(id === 'arsenal' || id === 'ops' || id === 'intel' ? 'flex' : 'block');
    }
    if (id === 'intel') refreshIntel();
}

// ── INTEL CENTER LOGIC ────────────────────────────────────────────────
let selectedIntelTargets = new Set();

function refreshIntel() {
    document.getElementById('intelGrid').classList.add('hidden');
    document.getElementById('intelEmpty').classList.add('hidden');
    document.getElementById('intelLoading').classList.remove('hidden');
    selectedIntelTargets.clear();
    updateAnalyzeBtn();
    
    // Request target list from AI analyze
    ipcRenderer.send('ai-analyze', 'LIST');
}

ipcRenderer.on('intel-target-list', (event, targets) => {
    renderIntelSelection(targets);
});

function renderIntelSelection(targets) {
    const grid = document.getElementById('intelGrid');
    const loading = document.getElementById('intelLoading');
    const empty = document.getElementById('intelEmpty');
    
    loading.classList.add('hidden');
    if (!targets || targets.length === 0) {
        empty.classList.remove('hidden');
        grid.classList.add('hidden');
        return;
    }

    grid.innerHTML = '';
    grid.classList.remove('hidden');
    empty.classList.add('hidden');

    targets.forEach(t => {
        const card = document.createElement('div');
        const isSelected = selectedIntelTargets.has(t.id);
        
        const sevColors = {
            'CRITICAL': 'text-purple-400',
            'HIGH':     'text-primary',
            'MEDIUM':   'text-yellow-400',
            'LOW':      'text-white/40'
        };
        const color = sevColors[t.severity.toUpperCase()] || 'text-white';

        card.className = `intel-card p-6 bg-white/5 border border-white/10 rounded-lg cursor-pointer ${isSelected ? 'selected' : ''}`;
        card.innerHTML = `
            <div class="neon-indicator"></div>
            <div class="flex flex-col h-full justify-between">
                <div>
                    <div class="flex items-center gap-2 mb-3">
                        <span class="font-label-surgical text-[8px] px-2 py-0.5 border border-white/10 text-white/40 uppercase tracking-widest">${t.module}</span>
                        <span class="font-label-surgical text-[8px] font-bold ${color} uppercase tracking-widest">${t.severity}</span>
                    </div>
                    <h3 class="font-h2-tactical text-[12px] text-white uppercase tracking-wider mb-2">${t.type}</h3>
                    <p class="font-data-mono text-[10px] text-white/30 truncate mb-4">${t.url}</p>
                </div>
                <div class="flex items-center justify-between pt-4 border-t border-white/5">
                    <span class="font-label-surgical text-[8px] text-white/20 uppercase tracking-tighter">ID: ${t.id}</span>
                    <span class="material-symbols-outlined text-[16px] text-white/10">${isSelected ? 'check_circle' : 'circle'}</span>
                </div>
            </div>
        `;

        card.onclick = () => {
            if (selectedIntelTargets.has(t.id)) {
                selectedIntelTargets.delete(t.id);
                card.classList.remove('selected');
                card.querySelector('.material-symbols-outlined').innerText = 'circle';
            } else {
                selectedIntelTargets.add(t.id);
                card.classList.add('selected');
                card.querySelector('.material-symbols-outlined').innerText = 'check_circle';
            }
            updateAnalyzeBtn();
        };

        grid.appendChild(card);
    });
}

function updateAnalyzeBtn() {
    const btn = document.getElementById('analyzeSelectedBtn');
    btn.disabled = selectedIntelTargets.size === 0;
    btn.innerText = selectedIntelTargets.size > 0 ? `ANALYZE_${selectedIntelTargets.size}_SELECTED` : 'ANALYZE_SELECTION';
}

function runHowl() {
    toggleAI();
    pushActivity('Initiating full attack-chain correlation (HOWL)', 'intel');
    ipcRenderer.send('ai-howl');
}

function analyzeSelectedTargets() {
    if (selectedIntelTargets.size === 0) return;
    
    const selection = Array.from(selectedIntelTargets).join(',');
    ipcRenderer.send('intel-selection-confirmed', selection);
    
    // Switch to AI sidebar to see results? 
    // Or stay here and show a modal?
    // User wants "Full-Screen Analysis", so maybe we should show the results in the Intel Center?
    // But the user proposed "A new top-level navigation panel (id="intel") to replace the old tab-switching logic."
    // Let's open the AI sidebar for now as the "Results" panel.
    toggleAI();
    pushActivity(`Analyzing ${selectedIntelTargets.size} findings in Intel Center`, 'intel');
}

// ── REPRO SHELL (Universal Resizing) ───────────────────────────────────

const reproPanel = document.getElementById('reproPanel');
const reproHeader = document.getElementById('reproHeader');

let isMoving = false, isResizing = false, resizeDir = '';
let startX, startY, startW, startH, startL, startT;

reproHeader.onmousedown = (e) => {
    // Clear CSS anchors so JS top/left/width/height have full control
    reproPanel.style.bottom = 'auto';
    reproPanel.style.right = 'auto';
    isMoving = true;
    startX = e.clientX; startY = e.clientY;
    startL = reproPanel.offsetLeft; startT = reproPanel.offsetTop;
    document.onmousemove = (ev) => {
        if (isMoving) {
            reproPanel.style.left = (startL + ev.clientX - startX) + 'px';
            reproPanel.style.top  = (startT + ev.clientY - startY) + 'px';
        }
    };
    document.onmouseup = () => { isMoving = false; document.onmousemove = null; };
};

document.querySelectorAll('.resize-handle').forEach(handle => {
    handle.onmousedown = (e) => {
        e.stopPropagation();
        // Clear anchors on first resize too
        reproPanel.style.bottom = 'auto';
        reproPanel.style.right = 'auto';
        isResizing = true; resizeDir = handle.dataset.dir;
        startX = e.clientX; startY = e.clientY;
        startW = reproPanel.offsetWidth; startH = reproPanel.offsetHeight;
        startL = reproPanel.offsetLeft;  startT = reproPanel.offsetTop;
        document.onmousemove = (ev) => {
            if (!isResizing) return;
            const dx = ev.clientX - startX;
            const dy = ev.clientY - startY;
            if (resizeDir.includes('e')) reproPanel.style.width  = Math.max(300, startW + dx) + 'px';
            if (resizeDir.includes('w')) { reproPanel.style.width = Math.max(300, startW - dx) + 'px'; reproPanel.style.left = (startL + dx) + 'px'; }
            if (resizeDir.includes('s')) reproPanel.style.height = Math.max(200, startH + dy) + 'px';
            if (resizeDir.includes('n')) { reproPanel.style.height = Math.max(200, startH - dy) + 'px'; reproPanel.style.top = (startT + dy) + 'px'; }
            // Fixed readable font size — not tied to panel width
            document.getElementById('reproOutput').style.fontSize = '13px';
            document.getElementById('reproInput').style.fontSize  = '13px';
        };
        document.onmouseup = () => { isResizing = false; document.onmousemove = null; };
    };
});

function toggleRepro() { reproPanel.classList.toggle('hidden'); if(!reproPanel.classList.contains('hidden')) document.getElementById('reproInput').focus(); }

// Repro shell: kept as bash for curl/repro command execution (intentional for pentest workflow)
const reproShell = spawn('/bin/bash', { env: process.env, shell: true, cwd: PROJECT_ROOT });
// Repro shell — plain bash for curl/pentest commands
// stdout and stderr both go to the same pre element — no div boxing
// Curl progress (stderr) is filtered: those lines are purely numeric stats

const CURL_PROGRESS_RE = /^\s*%\s+Total|^\s*\d+\s+\d+\s+\d+|Dload|Upload|Speed|Time/;

function appendRepro(text, isError = false) {
    const output = document.getElementById('reproOutput');
    if (!output) return;

    // Filter curl's stderr progress block — it's not useful output
    if (isError && CURL_PROGRESS_RE.test(text)) return;

    // Append as plain text to a single pre — no divs, full width, no coloring
    let pre = output.querySelector('pre.repro-pre');
    if (!pre) {
        pre = document.createElement('pre');
        pre.className = 'repro-pre font-data-mono text-[13px] text-white whitespace-pre-wrap break-all w-full';
        output.appendChild(pre);
    }
    pre.textContent += text;
    output.scrollTop = output.scrollHeight;
}

reproShell.stdout.on('data', (data) => appendRepro(data.toString()));
reproShell.stderr.on('data', (data) => appendRepro(data.toString(), true));

function handleRepro(event) {
    if (event.key === 'Enter') {
        const input = document.getElementById('reproInput');
        if (input.value.trim()) { reproShell.stdin.write(input.value + '\n'); appendRepro(`› ${input.value}\n`); }
        input.value = '';
    }
}

// ── MODULE NAME NORMALIZATION ─────────────────────────────────────────
// FIX: Consistent normalization — strip underscores, title-case each word

function normalizeName(raw) {
    return raw
        .replace(/_/g, ' ')
        .replace(/([a-z])([A-Z])/g, '$1 $2') // split camelCase
        .toUpperCase()
        .trim();
}

// ── ARSENAL (Corrected Phase Map) ────────────────────────────────────
// FIX: Removed POST phase. Phases are RECON, VULN, EXPLOIT, ANALYSIS
// matching actual Hellhound module categories

const PHASE_ORDER = ['RECON', 'VULN', 'EXPLOIT', 'ANALYSIS'];
const CATEGORY_MAP = {
    'recon':    'RECON',
    'intel':    'RECON',
    'vuln':     'VULN',
    'web':      'VULN',
    'exploit':  'EXPLOIT',
    'post':     'EXPLOIT',  // map post → exploit since we removed POST phase
    'analysis': 'ANALYSIS'
};

const PHASE_LABELS = {
    'RECON':    'RECONNAISSANCE',
    'VULN':     'VULNERABILITY DETECTION',
    'EXPLOIT':  'EXPLOITATION',
    'ANALYSIS': 'ANALYSIS'
};

ipcRenderer.on('modules-data', (event, data) => { modules = data; renderArsenal(); });

function renderArsenal() {
    const grid = document.getElementById('moduleGrid');
    const filter = document.getElementById('phaseSelector').value;
    if (!grid) return; grid.innerHTML = '';

    PHASE_ORDER.forEach(phase => {
        if (filter !== 'ALL' && filter !== phase) return;
        const mods = Object.keys(modules).filter(k => (CATEGORY_MAP[modules[k].category] || 'VULN') === phase);
        if (mods.length === 0) return;

        // Spider Priority in Recon
        mods.sort((a, b) => {
            if (a === 'spider') return -1; if (b === 'spider') return 1;
            return modules[a].name.localeCompare(modules[b].name);
        });

        const header = document.createElement('div');
        header.className = 'py-2 border-b border-white/10 mb-6';
        header.innerHTML = `<h4 class="font-label-surgical text-[10px] text-primary font-bold uppercase tracking-[0.4em]">${PHASE_LABELS[phase]} PHASE</h4>`;
        grid.appendChild(header);

        mods.forEach(key => {
            const m = modules[key];
            const card = document.createElement('div');
            // FIX: use normalizeName() consistently
            const displayName = normalizeName(m.name);
            card.className = 'p-6 bg-white/5 border border-white/5 cursor-pointer hover:border-primary/40 hover:bg-primary/5 transition-all group';
            card.innerHTML = `<h3 class="text-[11px] font-bold uppercase text-white group-hover:text-primary transition-colors">${displayName}</h3>`;
            card.onclick = () => openForge(key);
            grid.appendChild(card);
        });
    });
}

let selectedModuleKey = '';
function openForge(key) {
    selectedModuleKey = key;
    const m = modules[key];
    // FIX: normalizeName for the forge header too
    document.getElementById('selectedModuleName').innerText = normalizeName(m.name);
    document.getElementById('selectedModuleDesc').innerText = m.description;
    const container = document.getElementById('forgeOptions');
    container.innerHTML = '';

    Object.keys(m.options || {}).forEach(oname => {
        const opt = m.options[oname];
        const div = document.createElement('div');
        div.className = 'space-y-3 p-5 bg-white/5 border-l-4 border-primary/20';
        div.innerHTML = `
            <label class="text-white text-[12px] font-bold uppercase">${oname}</label>
            <p class="text-[12px] text-white/50">${opt.description}</p>
            <input type="text" class="forge-input term-input w-full font-bold text-white text-[13px] p-3" data-opt="${oname}" value="${opt.default || ''}">
        `;
        container.appendChild(div);
    });
}

// ── MISSION STRIKE — PREFLIGHT CONFIRMATION ───────────────────────────

let pendingStrikeArgs = null;

function initiateStrike() {
    if (!activeTarget) { alert('No target engaged. Set a target first.'); return; }
    if (!selectedModuleKey) { alert('No module selected. Choose a module from Arsenal.'); return; }

    const args = { target: activeTarget };
    document.querySelectorAll('.forge-input').forEach(input => {
        if (input.value.trim()) args[input.dataset.opt] = input.value.trim();
    });
    pendingStrikeArgs = { module: selectedModuleKey, args };

    // Reset modal to loading state
    document.getElementById('strikeConfirmModal').classList.remove('hidden');
    document.getElementById('confirmLoading').classList.remove('hidden');
    document.getElementById('confirmOptionsTable').classList.add('hidden');
    document.getElementById('confirmError').classList.add('hidden');
    const confirmBtn = document.getElementById('confirmStrikeBtn');
    confirmBtn.disabled = true;
    confirmBtn.classList.add('opacity-40');

    ipcRenderer.send('get-options', pendingStrikeArgs);
}

ipcRenderer.on('options-data', (event, { output, success }) => {
    document.getElementById('confirmLoading').classList.add('hidden');

    if (!success || !output.trim()) {
        document.getElementById('confirmError').classList.remove('hidden');
        return;
    }

    const container = document.getElementById('confirmRows');
    container.innerHTML = '';

    const SKIP_RE = [
        /^-{2,}/, /^={2,}/,
        /^category\s*[:\s]/i,
        /^name\s+(current|setting)/i,
        /^current\s+setting/i,
        /^\s*name\s*$/i,
        /^module\s*:/i, /^target\s*:/i,
        /^\[strike\]/i, /^\[equip\]/i,
        /web target acquired/i,
        /^\[>\]/, /^\[\+\]/, /^\[!\]/,
        /type 'help'/i, /type 'activate/i, /created by/i,
    ];

    const lines = output.split('\n').filter(l => {
        const t = l.trim();
        return t && !SKIP_RE.some(re => re.test(t));
    });

    let hasRows = false;
    lines.forEach(line => {
        const cols = line.trim().split(/\s{2,}/);
        if (cols.length < 2) return;
        const first = cols[0].toLowerCase().trim();
        if (['option', 'name', 'category', 'setting', 'required'].includes(first)) return;
        if (/^-+$/.test(cols[0]) || /^=+$/.test(cols[0])) return;

        hasRows = true;
        const optName = cols[0].trim();
        const optVal  = (cols[1] || '').trim() || '—';
        const optReq  = (cols[2] || '').toLowerCase();
        const isSet = optVal && optVal !== '—' && optVal !== 'None' && optVal !== '';
        const isRequired = optReq.includes('required') || optReq.includes('yes') || optReq === 'true';
        const isMissing = isRequired && !isSet;

        const row = document.createElement('div');
        row.className = `grid grid-cols-3 gap-4 px-4 py-3 ${isMissing ? 'bg-primary/10 border-l-2 border-primary' : 'hover:bg-white/3'} transition-colors`;
        row.innerHTML = `
            <span class="font-data-mono text-[11px] text-white font-bold truncate">${optName}</span>
            <span class="font-data-mono text-[11px] ${isSet ? 'text-green-400' : 'text-white/30'} truncate">${optVal}</span>
            <span class="font-label-surgical text-[9px] uppercase tracking-widest ${isMissing ? 'text-primary font-bold' : isRequired ? 'text-yellow-500' : 'text-white/30'}">
                ${isMissing ? '⚠ MISSING' : isRequired ? 'REQUIRED' : 'optional'}
            </span>`;
        container.appendChild(row);
    });

    if (!hasRows) {
        const pre = document.createElement('pre');
        pre.className = 'font-data-mono text-[11px] text-white/70 whitespace-pre-wrap px-4 py-3';
        pre.textContent = output;
        container.appendChild(pre);
    }

    document.getElementById('confirmOptionsTable').classList.remove('hidden');
    const confirmBtn = document.getElementById('confirmStrikeBtn');
    confirmBtn.disabled = false;
    confirmBtn.classList.remove('opacity-40');
});

function confirmStrike() {
    document.getElementById('strikeConfirmModal').classList.add('hidden');
    if (!pendingStrikeArgs) return;

    showSection('ops');
    const displayName = normalizeName(modules[selectedModuleKey]?.name || selectedModuleKey);

    // Clear raw output, show running state in telemetry
    const output = document.getElementById('opsOutput');
    if (output) output.innerText = '';
    setMissionState('running', displayName, activeTarget);

    ipcRenderer.send('strike-confirmed');
    setEngineDot('ops', 'busy');
    pushActivity(`Strike confirmed: ${displayName} @ ${activeTarget}`, 'strike');
    pendingStrikeArgs = null;
}

function abortStrike() {
    document.getElementById('strikeConfirmModal').classList.add('hidden');
    ipcRenderer.send('abort-strike');
    pushActivity('Strike aborted — module released', 'warn');
    pendingStrikeArgs = null;
}

function appendOpsLine(text) {
    const output = document.getElementById('opsOutput');
    if (output) {
        output.innerText += text + '\n';
        output.scrollTop = output.scrollHeight;
    }
}

// ── OPS TELEMETRY STATE ───────────────────────────────────────────────
// The telemetry panel shows running state only — no raw output flood.
// Raw output is hidden behind a toggle for debugging.
// All findings go to the right panel via telemetry-event.

let missionTimer = null;
let missionStart = null;

function switchOpsTab(tab, el) {
    document.querySelectorAll('.ops-tab').forEach(t => {
        t.classList.remove('text-primary', 'border-b-2', 'border-primary', 'bg-black/60');
        t.classList.add('text-white/30', 'bg-black/40');
    });
    el.classList.add('text-primary', 'border-b-2', 'border-primary', 'bg-black/60');
    el.classList.remove('text-white/30', 'bg-black/40');

    document.getElementById('opsTelemetryPanel').classList.toggle('hidden', tab !== 'telemetry');
    document.getElementById('opsSessionLogPanel').classList.toggle('hidden', tab !== 'sessionlog');

    if (tab === 'sessionlog') refreshSessionLog();
}

function setMissionState(state, moduleName, target) {
    const statusBlock = document.getElementById('missionStatusBlock');
    const idleBlock = document.getElementById('missionIdleBlock');
    const rawToggle = document.getElementById('rawOutputToggle');
    const dot = document.getElementById('missionRunningDot');
    const statusLabel = document.getElementById('missionStatusLabel');
    const moduleLabel = document.getElementById('missionModuleLabel');
    const targetLabel = document.getElementById('missionTargetLabel');

    if (state === 'idle') {
        statusBlock.classList.add('hidden');
        idleBlock.classList.remove('hidden');
        rawToggle.classList.add('hidden');
        clearInterval(missionTimer); missionTimer = null;
        return;
    }

    idleBlock.classList.add('hidden');
    statusBlock.classList.remove('hidden');
    rawToggle.classList.remove('hidden');
    if (moduleName) moduleLabel.innerText = moduleName;
    if (target) targetLabel.innerText = target;

    if (state === 'running') {
        dot.className = 'w-2 h-2 rounded-full bg-primary animate-pulse shadow-[0_0_10px_#ff2244]';
        statusLabel.className = 'text-primary font-bold';
        statusLabel.innerText = 'RUNNING';
        missionStart = Date.now();
        missionTimer = setInterval(() => {
            const elapsed = Math.floor((Date.now() - missionStart) / 1000);
            const m = Math.floor(elapsed / 60).toString().padStart(2, '0');
            const s = (elapsed % 60).toString().padStart(2, '0');
            const el2 = document.getElementById('missionElapsed');
            if (el2) el2.innerText = `${m}:${s}`;
        }, 1000);
    } else if (state === 'complete') {
        clearInterval(missionTimer); missionTimer = null;
        dot.className = 'w-2 h-2 rounded-full bg-green-500';
        statusLabel.className = 'text-green-400 font-bold';
        statusLabel.innerText = 'COMPLETE';
    } else if (state === 'error') {
        clearInterval(missionTimer); missionTimer = null;
        dot.className = 'w-2 h-2 rounded-full bg-red-500';
        statusLabel.className = 'text-red-400 font-bold';
        statusLabel.innerText = 'ERROR';
    }
}

function toggleRawOutput() {
    const output = document.getElementById('opsOutput');
    const btn = document.querySelector('[onclick="toggleRawOutput()"]');
    const hidden = output.classList.toggle('hidden');
    if (btn) btn.innerText = hidden ? '▶ SHOW RAW OUTPUT' : '▼ HIDE RAW OUTPUT';
}

function clearOpsOutput() {
    const output = document.getElementById('opsOutput');
    if (output) output.innerText = '';
}

// Session log — reads recursive loot files grouped by target/module
function refreshSessionLog() {
    ipcRenderer.send('get-loot');
}

function renderSessionLog(lootMap) {
    const container = document.getElementById('sessionLogContent');
    if (!container) return;
    container.innerHTML = '';

    const files = Object.keys(lootMap).filter(k => !k.endsWith('.md'));
    if (files.length === 0) {
        container.innerHTML = `<div class="font-label-surgical text-[9px] text-white/20 uppercase tracking-widest text-center py-8">
            No loot files yet — run a strike first<br>
            <span class="text-white/10 text-[8px]">Files saved to: loot/[target]/[module].json</span>
        </div>`;
        return;
    }

    // Group by top-level directory (target name)
    const groups = {};
    files.forEach(relPath => {
        const parts = relPath.split(/[/\\]/);
        const groupKey = parts.length > 1 ? parts[0] : '_root';
        const fileKey = parts.slice(1).join('/') || parts[0];
        if (!groups[groupKey]) groups[groupKey] = [];
        groups[groupKey].push({ fileKey, relPath });
    });

    Object.entries(groups).forEach(([target, fileList]) => {
        const groupDiv = document.createElement('div');
        groupDiv.className = 'space-y-3 pb-4 border-b border-white/5 mb-4';

        const targetHeader = document.createElement('div');
        targetHeader.className = 'flex items-center gap-3 py-2';
        targetHeader.innerHTML = `
            <span class="material-symbols-outlined text-[14px] text-primary">target</span>
            <span class="font-label-surgical text-[10px] text-primary uppercase tracking-widest font-bold">${target === '_root' ? 'global' : target}</span>
            <span class="font-data-mono text-[9px] text-white/20">${fileList.length} file${fileList.length !== 1 ? 's' : ''}</span>
        `;
        groupDiv.appendChild(targetHeader);

        fileList.forEach(({ fileKey, relPath }) => {
            const lines = lootMap[relPath] || [];
            const modName = fileKey.replace(/\.(json|txt)$/, '').replace(/_/g, ' ').toUpperCase();

            const section = document.createElement('div');
            section.className = 'ml-5 space-y-1 mb-3';

            const modHeader = document.createElement('div');
            modHeader.className = 'flex items-center justify-between py-1 border-b border-white/5';
            modHeader.innerHTML = `
                <span class="font-label-surgical text-[9px] text-white/50 uppercase tracking-widest">${modName}</span>
                <span class="font-data-mono text-[9px] text-white/20">${lines.length} entries</span>
            `;
            section.appendChild(modHeader);

            lines.slice(0, 30).forEach(line => {
                const div = document.createElement('div');
                div.className = 'font-data-mono text-[10px] text-white/55 py-0.5 px-2 hover:bg-white/3 break-all leading-relaxed select-text cursor-text';
                div.style.userSelect = 'text';
                div.textContent = line;
                section.appendChild(div);
            });

            if (lines.length > 30) {
                const more = document.createElement('div');
                more.className = 'font-label-surgical text-[8px] text-white/20 uppercase tracking-widest px-2 py-1';
                more.textContent = `... ${lines.length - 30} more entries`;
                section.appendChild(more);
            }

            groupDiv.appendChild(section);
        });

        container.appendChild(groupDiv);
    });
}

// ── CONSOLE READY ─────────────────────────────────────────────────────
// Called twice - once per engine. Apply settings when ops engine ready.
const enginesReady = new Set();

ipcRenderer.on('console-ready', (event, { engine }) => {
    enginesReady.add(engine);
    setEngineDot(engine, 'online');
    pushActivity(`Hellhound ${engine} engine ready`, 'ok');

    if (engine === 'ops') {
        const saved = localStorage.getItem('hh_global_settings');
        if (saved) {
            try { ipcRenderer.send('sync-settings-to-console', JSON.parse(saved)); } catch (_) {}
        }
    }

    if (enginesReady.size === 2) {
        pushActivity('Twin-engine online — strikes and AI run in parallel', 'ok');
    }
});

ipcRenderer.on('proc-out', (event, { pid, data }) => {
    // Raw output goes to the hidden toggle area only
    const output = document.getElementById('opsOutput');
    if (output && data.trim()) {
        output.innerText += data;
        output.scrollTop = output.scrollHeight;
    }
});

ipcRenderer.on('telemetry-event', (event, { line, severity }) => {
    const container = document.getElementById('opsFindings');
    if (!container) return;

    const colors = {
        critical: 'border-red-500 text-red-400 bg-red-500/5',
        high:     'border-primary text-primary bg-primary/5',
        medium:   'border-yellow-500 text-yellow-400 bg-yellow-500/5',
        low:      'border-white/20 text-white/50 bg-white/2',
        info:     'border-blue-400 text-blue-300 bg-blue-400/5'
    };
    const labels = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' };

    const div = document.createElement('div');
    div.className = `p-3 border-l-2 ${colors[severity] || colors.info} text-[11px] font-data-mono animate-fade-in flex gap-3 items-start`;
    div.innerHTML = `
        <span class="font-bold text-[9px] uppercase tracking-widest opacity-70 mt-0.5 whitespace-nowrap">${labels[severity] || 'INFO'}</span>
        <span class="leading-relaxed break-all select-text" style="user-select:text">${line}</span>
    `;
    container.prepend(div);
    while (container.children.length > 200) container.removeChild(container.lastChild);
});

ipcRenderer.on('proc-exit', (event, { pid, code }) => {
    const displayName = normalizeName(modules[selectedModuleKey]?.name || selectedModuleKey);
    setMissionState(code === 0 ? 'complete' : 'error', displayName, activeTarget);
    setEngineDot('ops', 'online');
    updateLastModule(displayName, code === 0 ? 'COMPLETE' : 'ERROR');
    pushActivity(`Mission complete: ${displayName} (exit ${code})`, code === 0 ? 'ok' : 'warn');
    pollLoot();
});

// ── AI NEURAL CORE ────────────────────────────────────────────────────

let aiThinking = false;

function setAIMethod(method, el) {
    currentAIMode = method;
    document.querySelectorAll('.ai-tab').forEach(t => {
        t.classList.remove('active', 'text-primary', 'border-primary', 'border-b-2');
        t.classList.add('text-white/30');
    });
    el.classList.add('active', 'text-primary', 'border-primary', 'border-b-2');
    el.classList.remove('text-white/30');
}

function sendAI() {
    if (aiThinking) return;
    const input = document.getElementById('aiInput');
    const msg = input.value.trim();
    if (!msg) return;

    let payload = msg;
    if (currentAIMode === 'analyze' && activeTarget) {
        payload = `Target: ${activeTarget}\n\n${msg}`;
    }

    appendHellhoundMessage('user', msg);
    input.value = '';
    aiThinking = true;
    setEngineDot('intel', 'busy');

    const container = document.getElementById('ask-history');
    const thinking = document.createElement('div');
    thinking.id = 'ai-thinking-' + Date.now();
    thinking.className = 'p-4 bg-primary/5 border-l-2 border-primary text-primary text-[13px] font-data-mono animate-pulse';
    thinking.innerHTML = `<span>HELLHOUND processing...</span>`;
    container.appendChild(thinking);
    container.scrollTop = container.scrollHeight;

    ipcRenderer.send(`ai-${currentAIMode}`, payload);
}

// Chatbox keyboard shortcuts — Enter sends, Shift+Enter newline, Ctrl+A selects all in history
document.addEventListener('DOMContentLoaded', () => {
    const aiInput = document.getElementById('aiInput');
    if (aiInput) {
        aiInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendAI(); }
            // Shift+Enter naturally inserts newline in textarea — no handler needed
        });
    }
});

function clearAIHistory() {
    const container = document.getElementById('ask-history');
    if (container) container.innerHTML = '';
}

function copyAllChat() {
    const container = document.getElementById('ask-history');
    if (!container) return;
    const text = Array.from(container.querySelectorAll('pre'))
        .map(p => p.textContent)
        .join('\n\n---\n\n');
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copyAllBtn');
        if (btn) { const o = btn.textContent; btn.textContent = 'COPIED'; setTimeout(() => { btn.textContent = o; }, 1500); }
    });
}

function appendHellhoundMessage(role, text) {
    const container = document.getElementById('ask-history');
    const wrapper = document.createElement('div');
    wrapper.className = `group relative p-4 ${role === 'user' ? 'bg-white/5 border-l-2 border-white/20' : 'bg-primary/5 border-l-2 border-primary'} animate-fade-in`;

    // Copy button — appears on hover
    const copyBtn = document.createElement('button');
    copyBtn.className = 'absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity font-label-surgical text-[8px] uppercase tracking-widest text-white/30 hover:text-white px-2 py-1 bg-white/5 hover:bg-white/10';
    copyBtn.textContent = 'COPY';
    copyBtn.onclick = () => {
        navigator.clipboard.writeText(text).then(() => {
            copyBtn.textContent = 'COPIED';
            setTimeout(() => { copyBtn.textContent = 'COPY'; }, 1500);
        });
    };

    // Role label
    const label = document.createElement('div');
    label.className = `font-label-surgical text-[8px] uppercase tracking-widest mb-2 ${role === 'user' ? 'text-white/30' : 'text-primary/60'}`;
    label.textContent = role === 'user' ? 'YOU' : 'HELLHOUND';

    // Message content — user-select: text so it can be highlighted and copied natively
    const pre = document.createElement('pre');
    pre.className = `text-[13px] font-data-mono whitespace-pre-wrap leading-relaxed select-text ${role === 'user' ? 'text-white/80' : 'text-white/90'}`;
    pre.style.userSelect = 'text';
    pre.textContent = text;

    wrapper.appendChild(copyBtn);
    wrapper.appendChild(label);
    wrapper.appendChild(pre);
    container.appendChild(wrapper);
    container.scrollTop = container.scrollHeight;
}


function initializeNeuralHandshake() {
    const settings = JSON.parse(localStorage.getItem('hh_global_settings') || '{}');
    const provider = (settings.ai_provider || '').toLowerCase();
    const isLocal = provider.includes('local') || provider === 'ollama' || provider === '';
    const key = isLocal ? 'local' : (settings.ai_key || '');

    setAIStatus('connecting', 'Connecting to AI engine...');

    // Sync settings first, then handshake
    ipcRenderer.send('sync-settings-to-console', settings);
    ipcRenderer.send('ai-handshake', key);

    const btn = document.querySelector('[onclick="initializeNeuralHandshake()"]');
    if (btn) { const o = btn.textContent; btn.textContent = 'CONNECTING...'; setTimeout(() => { btn.textContent = o; }, 6000); }
}

// Show AI connection status in both the settings panel and the chatbox
function setAIStatus(state, message) {
    // Update settings panel status
    const panel = document.getElementById('aiStatusPanel');
    if (panel) {
        panel.classList.remove('hidden');
        const dot = document.getElementById('aiStatusDot');
        const msg = document.getElementById('aiStatusMsg');
        const colors = { connecting: 'bg-yellow-500 animate-pulse', ok: 'bg-green-500', error: 'bg-red-500' };
        const textColors = { connecting: 'text-yellow-400', ok: 'text-green-400', error: 'text-primary' };
        if (dot) dot.className = `w-2 h-2 rounded-full ${colors[state] || colors.connecting}`;
        if (msg) { msg.className = `font-data-mono text-[11px] ${textColors[state] || 'text-white/60'}`; msg.textContent = message; }
    }
    // Also echo into chatbox
    appendHellhoundMessage(message);
}

// ai-response handler updates status too
ipcRenderer.on('ai-response', (event, data) => {
    aiThinking = false;
    setEngineDot('intel', 'online');
    const thinking = document.querySelector('[id^="ai-thinking-"]');
    if (thinking) thinking.remove();

    const responseText = (data && data.trim()) ? data.trim() : 'No response. Check AI provider in Settings.';

    // Detect AI status messages from the console
    if (responseText.includes('ONLINE') || responseText.includes('connected') || responseText.includes('● ONLINE')) {
        setAIStatus('ok', 'AI engine connected and ready');
    } else if (responseText.includes('not configured') || responseText.includes('setg ai') || responseText.includes('OFFLINE')) {
        setAIStatus('error', responseText.split('\n')[0]);
    }

    appendHellhoundMessage(responseText);
});

// ── SETTINGS ─────────────────────────────────────────────────────────

function toggleAiKeyInput() {
    const provider = document.getElementById('ai_provider').value;
    document.getElementById('aiKeyContainer').classList.toggle('hidden', provider === 'LOCAL');
}

function checkAIStatus() {
    const panel = document.getElementById('aiStatusPanel');
    const msg = document.getElementById('aiStatusMsg');
    const dot = document.getElementById('aiStatusDot');
    panel.classList.remove('hidden');
    dot.className = 'w-2 h-2 rounded-full bg-yellow-500 mt-1 flex-shrink-0 animate-pulse';
    msg.textContent = 'Querying console...';
    ipcRenderer.send('check-ai-status');
}

ipcRenderer.on('ai-status-result', (event, output) => {
    const panel = document.getElementById('aiStatusPanel');
    const msg = document.getElementById('aiStatusMsg');
    const dot = document.getElementById('aiStatusDot');
    if (!panel) return;
    panel.classList.remove('hidden');

    const isOnline = output && (output.includes('ONLINE') || output.includes('INTELLIGENCE') || output.includes('● ONLINE'));
    const isNotConfigured = output && output.includes('not configured');

    dot.className = `w-2 h-2 rounded-full mt-1 flex-shrink-0 ${isOnline ? 'bg-green-500' : isNotConfigured ? 'bg-red-500' : 'bg-yellow-500'}`;
    msg.textContent = output || 'No response from console.';
});

function saveGlobalSettings() {
    const settings = {
        proxy: document.getElementById('proxy').value,
        proxy_mode: document.getElementById('proxy_mode').value,
        bugbounty: document.getElementById('bugbounty').value,
        wafbypass: document.getElementById('wafbypass').value,
        oob: document.getElementById('oob').value,
        ai_provider: document.getElementById('ai_provider').value,
        ai_key: document.getElementById('ai_key').value
    };
    // Persist to localStorage for GUI restores
    localStorage.setItem('hh_global_settings', JSON.stringify(settings));
    // Also pipe to the live console backend so settings take effect immediately
    ipcRenderer.send('sync-settings-to-console', settings);

    const btn = document.querySelector('[onclick="saveGlobalSettings()"]');
    if (btn) { const o = btn.textContent; btn.textContent = 'SYNCHRONIZED'; setTimeout(() => { btn.textContent = o; }, 2000); }
}

function loadGlobalSettings() {
    const raw = localStorage.getItem('hh_global_settings');
    if (!raw) return;
    const settings = JSON.parse(raw);
    Object.keys(settings).forEach(key => {
        const el = document.getElementById(key);
        if (el) el.value = settings[key];
    });
    toggleAiKeyInput();
}

// ── REPRO ENGINE ──────────────────────────────────────────────────────
// Fires the console's `repro` command which replays ALL session findings
// through the configured proxy (set via Settings → proxy).
// Uses the persistent console so self.results is already populated from
// the current strike — no need to pass finding data manually.

function fireRepro() {
    const timeout = document.getElementById('reproTimeout')?.value || '10';
    const delay = document.getElementById('reproDelay')?.value || '0.5';

    // Build the repro command with optional overrides
    let cmd = 'repro';
    const overrides = [];
    if (timeout !== '10') overrides.push(`timeout=${timeout}`);
    if (delay !== '0.5') overrides.push(`delay=${delay}`);
    if (overrides.length > 0) cmd += ' ' + overrides.join(' ');

    // Check proxy is configured — warn if not
    const settings = JSON.parse(localStorage.getItem('hh_global_settings') || '{}');
    if (!settings.proxy) {
        appendOpsLine('\n[!] WARNING: No proxy configured in Settings. Repro will run without proxy routing.');
        appendOpsLine('[!] Go to Settings → proxy to set your Burp/ZAP listener.\n');
    }

    // Visual feedback on button
    const btn = document.getElementById('reproFireBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="material-symbols-outlined text-[16px] animate-spin">refresh</span> REPLAYING...`;
    }

    appendOpsLine(`\n╔══════════════════════════════════════════════════════`);
    appendOpsLine(`║  REPRO ENGINE  : INITIATED`);
    appendOpsLine(`║  PROXY         : ${settings.proxy || 'NONE'}`);
    appendOpsLine(`║  TIMEOUT       : ${timeout}s   DELAY: ${delay}s`);
    appendOpsLine(`╚══════════════════════════════════════════════════════\n`);

    ipcRenderer.send('run-repro', { cmd });
    pushActivity(`Repro engine fired — proxy: ${settings.proxy || 'none'}`, 'strike');
}

// Repro complete signal from main.js
ipcRenderer.on('repro-done', (event, { code }) => {
    const btn = document.getElementById('reproFireBtn');
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<span class="material-symbols-outlined text-[16px]">replay</span> REPLAY_VIA_PROXY`;
    }
    appendOpsLine(`\n╔══════════════════════════════════════════════════════`);
    appendOpsLine(`║  REPRO ENGINE  : COMPLETE (exit ${code})`);
    appendOpsLine(`╚══════════════════════════════════════════════════════\n`);
    pushActivity(`Repro complete (exit ${code})`, code === 0 ? 'ok' : 'warn');
});

function clearOpsOutput() {
    const output = document.getElementById('opsOutput');
    if (output) output.innerText = '';
}

function clearFindings() {
    const findings = document.getElementById('opsFindings');
    if (findings) findings.innerHTML = '';
}
// ── PROXY STATUS ──────────────────────────────────────────────────────
function checkProxyStatus() {
    const settings = JSON.parse(localStorage.getItem('hh_global_settings') || '{}');
    const proxy = settings.proxy;
    const dot = document.getElementById('proxyStatusDot');
    const label = document.getElementById('proxyStatusLabel');
    if (!proxy) { dot.className = 'w-2 h-2 rounded-full bg-white/20'; label.textContent = 'NO PROXY'; return; }
    dot.className = 'w-2 h-2 rounded-full bg-yellow-500 animate-pulse';
    label.textContent = 'CHECKING';
    try {
        const xhr = new XMLHttpRequest();
        xhr.timeout = 3000;
        xhr.onloadend = () => { dot.className = 'w-2 h-2 rounded-full bg-green-500 shadow-[0_0_6px_#22c55e]'; label.textContent = 'PROXY UP'; };
        xhr.onerror = () => { dot.className = 'w-2 h-2 rounded-full bg-red-500'; label.textContent = 'DOWN'; };
        xhr.ontimeout = () => { dot.className = 'w-2 h-2 rounded-full bg-red-500'; label.textContent = 'TIMEOUT'; };
        xhr.open('GET', proxy, true);
        xhr.send();
    } catch (_) { dot.className = 'w-2 h-2 rounded-full bg-red-500'; label.textContent = 'BAD URL'; }
}

// ── SESSION EXPORT ────────────────────────────────────────────────────
function exportSession() {
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const target = activeTarget || 'unknown';
    let md = `# Hellhound Session Export\n\n**Target:** ${target}  \n**Exported:** ${new Date().toLocaleString()}\n\n---\n\n`;
    const findings = document.getElementById('opsFindings');
    if (findings && findings.children.length > 0) {
        md += `## Findings\n\n`;
        Array.from(findings.children).forEach(div => {
            const badge = div.querySelector('span:first-child')?.textContent?.trim() || '';
            const text = div.querySelector('span:last-child')?.textContent?.trim() || '';
            if (text) md += `- **[${badge}]** ${text}\n`;
        });
        md += `\n`;
    }
    const chatHistory = document.getElementById('ask-history');
    if (chatHistory && chatHistory.children.length > 0) {
        md += `## AI Session\n\n`;
        Array.from(chatHistory.children).forEach(div => {
            const lbl = div.querySelector('.font-label-surgical')?.textContent?.trim() || '';
            const text = div.querySelector('pre')?.textContent?.trim() || '';
            if (text) md += `**${lbl}:** ${text}\n\n`;
        });
    }
    const activity = document.getElementById('activityFeed');
    if (activity && activity.children.length > 0) {
        md += `## Activity\n\n`;
        Array.from(activity.children).reverse().forEach(div => {
            const spans = div.querySelectorAll('span');
            if (spans.length >= 3) md += `- \`${spans[0].textContent.trim()}\` ${spans[2].textContent.trim()}\n`;
        });
    }
    ipcRenderer.send('export-session', { filename: `hellhound-session-${ts}.md`, content: md });
    pushActivity(`Session exported: hellhound-session-${ts}.md`, 'ok');
}

// Default: dark (our custom hellhound theme). Light: clean readable mode.
// Persisted in localStorage so it survives restarts.

function toggleTheme() {
    const isLight = document.body.classList.toggle('theme-light');
    const icon = document.getElementById('themeIcon');
    if (icon) icon.textContent = isLight ? 'light_mode' : 'dark_mode';
    localStorage.setItem('hh_theme', isLight ? 'light' : 'dark');
}

function loadTheme() {
    const saved = localStorage.getItem('hh_theme');
    if (saved === 'light') {
        document.body.classList.add('theme-light');
        const icon = document.getElementById('themeIcon');
        if (icon) icon.textContent = 'light_mode';
    }
}
// FIX: Removed ip-api.com geolocation call (OPSEC risk — leaks operator IP to third party)
// The map section is replaced in the dashboard with a findings chart

function openTargetModal() { document.getElementById('targetModal').classList.remove('hidden'); document.getElementById('modalTargetInput').focus(); }
function closeModal(id) { document.getElementById(id).classList.add('hidden'); }
function confirmTarget() {
    activeTarget = document.getElementById('modalTargetInput').value.trim();
    if (activeTarget) {
        document.getElementById('headerTarget').innerText = activeTarget;
        document.getElementById('monitorShortcut').classList.remove('hidden');
        closeModal('targetModal');
        ipcRenderer.send('save-target', activeTarget);
        pushActivity(`Target engaged: ${activeTarget}`, 'info');
        // Update target display on dashboard
        const tLoc = document.getElementById('targetLocation');
        if (tLoc) tLoc.innerText = activeTarget.toUpperCase();
    }
}

function navigateMonitor() {
    showSection('monitor');
    const url = activeTarget.startsWith('http') ? activeTarget : 'http://' + activeTarget;
    document.getElementById('browserUrl').value = url; document.getElementById('tacticalWebview').src = url;
}

function navigateBrowser() {
    const url = document.getElementById('browserUrl').value.trim();
    if (url) document.getElementById('tacticalWebview').src = url.startsWith('http') ? url : 'http://' + url;
}

function windowControl(action) { ipcRenderer.send(`window-${action}`); }

// ── ACTIVITY FEED ─────────────────────────────────────────────────────

const ACTIVITY_ICONS = { strike: '⚡', ok: '✔', warn: '⚠', info: '●', loot: '◆' };
function pushActivity(message, type = 'info') {
    const feed = document.getElementById('activityFeed');
    if (!feed) return;
    const div = document.createElement('div');
    div.className = 'flex items-start gap-4 animate-fade-in';
    const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
    const color = { strike: 'text-primary', ok: 'text-green-400', warn: 'text-yellow-400', info: 'text-white/40', loot: 'text-blue-400' }[type] || 'text-white/40';
    div.innerHTML = `
        <span class="font-data-mono text-[9px] text-white/20 pt-1 whitespace-nowrap">${ts}</span>
        <span class="${color} text-[11px] font-bold">${ACTIVITY_ICONS[type] || '●'}</span>
        <span class="font-data-mono text-[11px] text-white/70 leading-relaxed">${message}</span>
    `;
    feed.prepend(div);
    // Keep feed lean
    while (feed.children.length > 30) feed.removeChild(feed.lastChild);
}

// ── LOOT POLLING & FINDINGS CHART ─────────────────────────────────────

const SAMPLE_CHART_DATA = {
    'Recon':    12,
    'SQLi':      4,
    'XSS':       7,
    'IDOR':      3,
    'CMDi':      1,
    'Path Trav': 2,
};
let hasRealData = false;

function pollLoot() {
    ipcRenderer.send('get-loot');
}

ipcRenderer.on('loot-data', (event, lootMap) => {
    const totalFindings = Object.values(lootMap).reduce((s, l) => s + l.length, 0);
    const endpoints = new Set();
    const categoryTotals = {};
    let criticals = 0;
    const topFindings = [];

    Object.keys(lootMap).forEach(file => {
        const lines = lootMap[file];
        const fname = file.toLowerCase();

        if (fname.includes('spider') || fname.includes('recon')) {
            lines.forEach(l => { if (l.includes('http')) endpoints.add(l.trim()); });
        }

        let cat = 'Other';
        if (fname.includes('sqli') || fname.includes('sql')) cat = 'SQLi';
        else if (fname.includes('cmdi') || fname.includes('cmd')) cat = 'CMDi';
        else if (fname.includes('idor')) cat = 'IDOR';
        else if (fname.includes('xss')) cat = 'XSS';
        else if (fname.includes('nosql')) cat = 'NoSQLi';
        else if (fname.includes('spider') || fname.includes('recon')) cat = 'Recon';
        else if (fname.includes('path') || fname.includes('traversal')) cat = 'Path Trav';
        else if (fname.includes('bac') || fname.includes('access')) cat = 'BAC';
        else if (fname.includes('secret') || fname.includes('source')) cat = 'Secrets';
        else cat = normalizeName(fname.split(/[/\\]/).pop()).substring(0, 12);

        categoryTotals[cat] = (categoryTotals[cat] || 0) + lines.length;

        // Collect top findings (high severity lines)
        lines.forEach(l => {
            const lower = l.toLowerCase();
            if (lower.includes('[critical]') || lower.includes('[high]') || lower.includes('[secret]') || lower.includes('[vuln]')) {
                criticals++;
                if (topFindings.length < 5) topFindings.push({ text: l.trim(), severity: lower.includes('[critical]') ? 'critical' : 'high' });
            }
        });
    });

    // Update stat counters with animation
    animateCounter('endpointCount', endpoints.size || Object.values(lootMap).reduce((s,l)=>s+l.length,0));
    animateCounter('findingCount', totalFindings);
    animateCounter('criticalCount', criticals);

    // Update top findings panel
    updateTopFindings(topFindings);

    // Update kill-chain based on what categories exist
    updateKillChain(categoryTotals);

    if (totalFindings > 0) {
        hasRealData = true;
        renderFindingsChart(categoryTotals, totalFindings, true);
        renderSessionLog(lootMap);
        pushActivity(`Loot updated: ${totalFindings} findings across ${Object.keys(lootMap).length} files`, 'loot');

        // Update dashboard subtitle
        const sub = document.getElementById('dashSubtitle');
        if (sub) sub.innerText = `Active Session — ${totalFindings} findings · ${endpoints.size} endpoints`;
    }
});

// ── DASHBOARD UPGRADE FUNCTIONS ───────────────────────────────────────────

// Smooth counter animation
function animateCounter(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const start = parseInt(el.innerText) || 0;
    if (start === target) return;
    const duration = 600;
    const startTime = Date.now();
    const tick = () => {
        const progress = Math.min((Date.now() - startTime) / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        el.innerText = Math.round(start + (target - start) * ease);
        if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
}

// Module phase → kill-chain phase mapping
const PHASE_MAP = {
    'Recon': 'RECON', 'Secrets': 'RECON',
    'SQLi': 'VULN', 'XSS': 'VULN', 'IDOR': 'VULN', 'NoSQLi': 'VULN', 'Path Trav': 'VULN', 'BAC': 'VULN',
    'CMDi': 'EXPLOIT', 'Other': 'VULN'
};
let sessionPhasesReached = new Set();
let modulesRunThisSession = 0;

function updateKillChain(categoryTotals) {
    // Determine which phases have data
    Object.keys(categoryTotals).forEach(cat => {
        const phase = PHASE_MAP[cat] || 'VULN';
        if (categoryTotals[cat] > 0) sessionPhasesReached.add(phase);
    });

    // If we have vuln or exploit data, recon is implied
    if (sessionPhasesReached.has('VULN') || sessionPhasesReached.has('EXPLOIT')) {
        sessionPhasesReached.add('RECON');
    }

    // Render phases
    PHASE_ORDER.forEach((phase, idx) => {
        const node = document.querySelector(`.kill-phase[data-phase="${phase}"] .kill-node`);
        const line = document.querySelector(`.kill-line[data-after="${phase}"]`);

        if (!node) return;
        node.classList.remove('done', 'active');

        if (sessionPhasesReached.has(phase)) {
            node.classList.add('done');
            if (line) line.classList.add('done');
        }
    });

    // Update detail text
    const detail = document.getElementById('killChainDetail');
    const phaseLabel = document.getElementById('killChainPhaseLabel');
    if (detail && sessionPhasesReached.size > 0) {
        const reached = PHASE_ORDER.filter(p => sessionPhasesReached.has(p));
        detail.innerText = `Completed: ${reached.join(' → ')}`;
        if (phaseLabel) phaseLabel.innerText = reached[reached.length - 1] || 'STANDBY';
    }
}

// Called when a module completes — update last module indicator and kill-chain
function updateLastModule(moduleName, status = 'COMPLETE') {
    modulesRunThisSession++;
    animateCounter('modulesRunCount', modulesRunThisSession);

    const dot = document.getElementById('lastModuleDot');
    const label = document.getElementById('lastModuleLabel');
    const statusEl = document.getElementById('lastModuleStatus');

    if (dot) dot.className = `w-1.5 h-1.5 rounded-full flex-shrink-0 ${status === 'COMPLETE' ? 'bg-green-500' : 'bg-red-500'}`;
    if (label) label.innerText = moduleName || 'UNKNOWN';
    if (statusEl) {
        statusEl.innerText = status;
        statusEl.className = `font-label-surgical text-[7px] uppercase tracking-widest ${status === 'COMPLETE' ? 'text-green-400' : 'text-red-400'}`;
    }

    // Mark analysis phase reachable if AI has been used
    const sub = document.getElementById('dashSubtitle');
    if (sub && modulesRunThisSession > 0) {
        sub.innerText = `Active Session — ${modulesRunThisSession} module${modulesRunThisSession !== 1 ? 's' : ''} executed`;
    }
}

// Top findings panel — shows 5 most critical findings on dashboard
function updateTopFindings(findings) {
    const container = document.getElementById('topFindingsList');
    if (!container) return;

    if (!findings || findings.length === 0) {
        container.innerHTML = `<div class="font-label-surgical text-[9px] text-white/15 uppercase tracking-widest text-center py-4">No high-severity findings yet</div>`;
        return;
    }

    container.innerHTML = '';
    findings.forEach(({ text, severity }) => {
        const colors = { critical: 'border-red-500 text-red-400', high: 'border-primary text-primary/80' };
        const div = document.createElement('div');
        div.className = `p-2 border-l-2 ${colors[severity] || colors.high} bg-white/2 font-data-mono text-[10px] leading-relaxed break-all hover:bg-white/5 transition-colors select-text`;
        div.style.userSelect = 'text';
        div.textContent = text.length > 80 ? text.substring(0, 80) + '…' : text;
        container.appendChild(div);
    });
}

// Engine status dot updater
function setEngineDot(engine, state) {
    const id = engine === 'ops' ? 'opsEngineDot' : 'intelEngineDot';
    const dot = document.getElementById(id);
    if (!dot) return;
    const states = {
        offline: 'w-2 h-2 rounded-full bg-white/15',
        online:  'w-2 h-2 rounded-full bg-green-500 shadow-[0_0_6px_#22c55e]',
        busy:    'w-2 h-2 rounded-full bg-primary shadow-[0_0_6px_#ff2244] animate-pulse',
    };
    dot.className = states[state] || states.offline;
}

function renderFindingsChart(data, total, isReal = false) {
    const container = document.getElementById('findingsChart');
    if (!container) return;
    container.innerHTML = '';

    const badge = document.getElementById('chartStatusBadge');
    const disclaimer = document.getElementById('chartDisclaimer');

    if (isReal) {
        if (badge) { badge.textContent = 'LIVE DATA'; badge.className = 'font-label-surgical text-[8px] text-primary uppercase tracking-widest border border-primary/40 px-3 py-1'; }
        if (disclaimer) disclaimer.style.display = 'none';
    }

    const keys = Object.keys(data);
    if (keys.length === 0) return;
    const maxVal = Math.max(...Object.values(data));

    const titleRow = document.createElement('div');
    titleRow.className = 'flex items-center justify-between mb-4';
    titleRow.innerHTML = `
        <span class="font-label-surgical text-[9px] text-white/30 uppercase tracking-widest">Category breakdown</span>
        <span class="font-data-mono text-[11px] text-white/50">${total} finding${total !== 1 ? 's' : ''}</span>
    `;
    container.appendChild(titleRow);

    const chart = document.createElement('div');
    chart.className = 'space-y-3 overflow-y-auto flex-1';
    chart.style.minHeight = '0';

    keys.sort((a, b) => data[b] - data[a]).forEach(cat => {
        const val = data[cat];
        const pct = maxVal > 0 ? (val / maxVal * 100) : 0;
        const BAR_COLORS = {
            'CMDi': 'bg-red-500', 'SQLi': 'bg-red-500',
            'IDOR': 'bg-orange-500', 'NoSQLi': 'bg-orange-500',
            'XSS': 'bg-yellow-500', 'Path Trav': 'bg-yellow-500',
            'Recon': 'bg-blue-400', 'BAC': 'bg-purple-400', 'Secrets': 'bg-pink-400',
        };
        const barColor = BAR_COLORS[cat] || 'bg-primary/70';

        const row = document.createElement('div');
        row.className = 'space-y-1';
        row.innerHTML = `
            <div class="flex justify-between items-baseline">
                <span class="font-label-surgical text-[9px] text-white/50 uppercase tracking-widest">${cat}</span>
                <span class="font-data-mono text-[11px] text-white font-bold">${val}</span>
            </div>
            <div class="w-full h-2 bg-white/5 rounded-full overflow-hidden">
                <div class="${barColor} h-full rounded-full transition-all duration-700" style="width:0%"
                     data-target="${pct}"></div>
            </div>
        `;
        chart.appendChild(row);
    });

    container.appendChild(chart);

    // Animate bars in after render
    requestAnimationFrame(() => {
        chart.querySelectorAll('[data-target]').forEach(bar => {
            bar.style.width = bar.dataset.target + '%';
        });
    });
}

// ── INIT ─────────────────────────────────────────────────────────────

window.onload = () => {
    loadTheme();
    initParticles();
    animateParticles();
    ipcRenderer.send('get-modules');
    ipcRenderer.send('get-history');
    loadGlobalSettings();
    pollLoot();
    setInterval(pollLoot, 10000);
    pushActivity('Hellhound Apex-King HUD online', 'info');
    const sampleTotal = Object.values(SAMPLE_CHART_DATA).reduce((a, b) => a + b, 0);
    renderFindingsChart(SAMPLE_CHART_DATA, sampleTotal, false);
};