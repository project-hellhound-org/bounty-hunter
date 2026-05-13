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

aiTrigger.onclick = () => toggleAI();

aiTrigger.onmouseenter = () => {
    if (!aiManuallyOpen) {
        aiContainer.classList.remove('translate-x-full');
        aiContainer.classList.add('translate-x-0');
        aiContainer.style.pointerEvents = 'auto';
    }
};

function toggleAI() {
    const isHidden = aiContainer.classList.contains('translate-x-full');
    if (isHidden) {
        aiContainer.classList.remove('translate-x-full');
        aiContainer.classList.add('translate-x-0');
        aiContainer.style.pointerEvents = 'auto';
        aiManuallyOpen = true;
    } else {
        aiContainer.classList.add('translate-x-full');
        aiContainer.classList.remove('translate-x-0');
        aiContainer.style.pointerEvents = 'none';
        aiManuallyOpen = false;
    }
}

// The × button inside the panel calls this — distinct from toggleAI
// so there's no ambiguity about open/close state
function closeAI() {
    aiContainer.classList.add('translate-x-full');
    aiContainer.classList.remove('translate-x-0');
    aiContainer.style.pointerEvents = 'none';
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
    document.querySelectorAll('.content-area, .section').forEach(sec => sec.classList.add('hidden'));
    const target = document.getElementById(id);
    if (target) {
        target.classList.remove('hidden');
        target.classList.add(id === 'arsenal' || id === 'ops' || id === 'intel' || id === 'loot' || id === 'repro' || id === 'graph' ? 'flex' : 'block');
    }
    
    if (id === 'intel') {
        // Default to HOWL tab
        const howlBtn = document.querySelector('.intel-tab');
        if (howlBtn) switchIntelTab('howl', howlBtn);
        ipcRenderer.send('get-intel-targets'); 
    }
    if (id === 'loot') pollLoot();
    if (id === 'graph') {
        setTimeout(initAttackGraph, 100);
    }
}

function switchIntelTab(tabId, el) {
    document.querySelectorAll('.intel-subpanel').forEach(p => p.classList.add('hidden'));
    document.getElementById(tabId + 'Panel').classList.remove('hidden');
    
    document.querySelectorAll('.intel-tab').forEach(t => {
        t.classList.remove('text-primary', 'border-primary', 'border-b-2');
        t.classList.add('text-white/30');
    });
    el.classList.add('text-primary', 'border-primary', 'border-b-2');
    el.classList.remove('text-white/30');
    
    const subtitle = document.getElementById('intelSubtitle');
    if (subtitle) {
        subtitle.innerText = tabId === 'howl' ? 'Correlation Matrix // NEURAL HOWL' : 'Correlation Matrix // SURGICAL ANALYZE';
    }
    
    if (tabId === 'analyze') refreshIntel();
}

// ── INTEL CENTER LOGIC ────────────────────────────────────────────────
let selectedIntelTargets = new Set();
let lastIntelTargets = [];
const SPIDER_DEPENDENT_MODULES = ['Hydra', 'IDORdetector', 'RBACdetector', 'CORSbuster', 'SQLI_Tester', 'PATHtraveller', 'JWTdetector', 'Spider_Analyzer'];

function showNotification(title, message, actionText = '', actionFn = null) {
    const notify = document.getElementById('notificationBox');
    if (!notify) return;
    
    document.getElementById('notifyTitle').innerText = title;
    document.getElementById('notifyMsg').innerText = message;
    
    const actionBtn = document.getElementById('notifyAction');
    if (actionText && actionFn) {
        actionBtn.innerText = actionText;
        actionBtn.onclick = () => { actionFn(); hideNotification(); };
        actionBtn.classList.remove('hidden');
    } else {
        actionBtn.classList.add('hidden');
    }
    
    notify.classList.remove('translate-y-full', 'opacity-0');
    notify.classList.add('translate-y-0', 'opacity-100');
    
    // Auto-hide after 10s if no action
    setTimeout(hideNotification, 10000);
}

function hideNotification() {
    const notify = document.getElementById('notificationBox');
    if (notify) {
        notify.classList.add('translate-y-full', 'opacity-0');
        notify.classList.remove('translate-y-0', 'opacity-100');
    }
}

function refreshIntel() {
    document.getElementById('intelGrid').classList.add('hidden');
    document.getElementById('intelEmpty').classList.add('hidden');
    document.getElementById('intelLoading').classList.remove('hidden');
    selectedIntelTargets.clear();
    updateAnalyzeBtn();
    ipcRenderer.send('get-intel-targets');
}

ipcRenderer.on('intel-target-list', (event, targets) => {
    lastIntelTargets = targets || [];
    if (!targets || targets.length === 0) {
        document.getElementById('intelGrid').innerHTML = '<div class="col-span-full py-20 text-center font-label-surgical text-white/20 uppercase tracking-widest italic">Waiting for module output to populate matrix...</div>';
        return;
    }
    renderIntelSelection(targets);
});

function renderIntelSelection(targets) {
    const grid = document.getElementById('intelGrid');
    grid.innerHTML = '';
    grid.classList.remove('hidden');
    document.getElementById('intelEmpty').classList.add('hidden');

    targets.forEach(t => {
        const card = document.createElement('div');
        const isSelected = selectedIntelTargets.has(t.id);
        const sevColors = { 'CRITICAL': 'text-purple-400', 'HIGH': 'text-primary', 'MEDIUM': 'text-yellow-400', 'LOW': 'text-white/40' };
        const color = sevColors[t.severity] || 'text-white';

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
                    <span class="font-label-surgical text-[8px] text-white/20 uppercase tracking-tighter">${t.raw ? t.raw.substring(0, 40) + '…' : t.id}</span>
                    <span class="material-symbols-outlined text-[16px] ${isSelected ? 'text-primary' : 'text-white/10'}">${isSelected ? 'check_circle' : 'circle'}</span>
                </div>
            </div>
        `;
        card.onclick = () => {
            if (selectedIntelTargets.has(t.id)) {
                selectedIntelTargets.delete(t.id);
                card.classList.remove('selected');
                const icon = card.querySelector('.material-symbols-outlined');
                icon.className = 'material-symbols-outlined text-[16px] text-white/10';
                icon.innerText = 'circle';
            } else {
                selectedIntelTargets.add(t.id);
                card.classList.add('selected');
                const icon = card.querySelector('.material-symbols-outlined');
                icon.className = 'material-symbols-outlined text-[16px] text-primary';
                icon.innerText = 'check_circle';
            }
            updateAnalyzeBtn();
            updateSelectionCount();
        };
        grid.appendChild(card);
    });
    
    // Force grid display if data exists
    grid.classList.remove('hidden');
    grid.classList.add('grid');
    document.getElementById('intelEmpty').classList.add('hidden');
}

function intelSelectAll() {
    const cards = document.querySelectorAll('.intel-card');
    const allSelected = Array.from(cards).every(c => c.classList.contains('selected'));
    
    cards.forEach(card => {
        // We need to trigger the same logic as the click
        const isSelected = card.classList.contains('selected');
        if (allSelected && isSelected) {
            card.click(); // Toggle off
        } else if (!allSelected && !isSelected) {
            card.click(); // Toggle on
        }
    });
}

function updateAnalyzeBtn() {
    const btn = document.getElementById('startAnalyzeBtn');
    if (!btn) return;
    btn.disabled = selectedIntelTargets.size === 0;
    if (selectedIntelTargets.size > 0) {
        btn.classList.add('shadow-[0_0_30px_#ff2244]');
    } else {
        btn.classList.remove('shadow-[0_0_30px_#ff2244]');
    }
    btn.innerText = selectedIntelTargets.size > 0 ? `ANALYZE_${selectedIntelTargets.size}_SELECTED` : 'ANALYZE_SELECTION';
}

function updateSelectionCount() {
    const el = document.getElementById('selectionCount');
    if (el) el.innerText = `${selectedIntelTargets.size} ITEMS SELECTED`;
}

function runHowl() {
    switchIntelTab('howl');
    const output = document.getElementById('howlOutput');
    if (output) {
        output.innerHTML = '<div class="flex items-center gap-4 text-primary animate-pulse py-10 font-label-surgical tracking-widest"><span class="material-symbols-outlined spin">sync</span> COLLATING ATTACK VECTORS...</div>';
    }
    pushActivity('Initiating full attack-chain correlation (HOWL)', 'intel');
    ipcRenderer.send('ai-howl');
    
    // Auto-refresh intel data after a delay
    setTimeout(refreshIntel, 5000);
}

function analyzeSelectedTargets() {
    if (selectedIntelTargets.size === 0) return;
    const ids = Array.from(selectedIntelTargets);
    const selection = ids.join(',');
    ipcRenderer.send('intel-selection-confirmed', selection);
    aiManuallyOpen = true;
    aiContainer.classList.remove('translate-x-full');
    aiContainer.classList.add('translate-x-0');
    appendAIMessage('user', `Analyzing ${ids.length} selected finding${ids.length !== 1 ? 's' : ''}: ${ids.slice(0, 3).join(', ')}${ids.length > 3 ? '...' : ''}`);
    pushActivity(`Intel analysis: ${ids.length} findings queued`, 'intel');
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
    const output = document.getElementById('reproTerminal');
    if (!output) return;

    if (isError && CURL_PROGRESS_RE.test(text)) return;
    
    // Auto-clear the placeholder on first output
    const placeholder = output.querySelector('.py-40');
    if (placeholder) placeholder.remove();

    let pre = output.querySelector('pre.repro-pre');
    if (!pre) {
        pre = document.createElement('pre');
        pre.className = 'repro-pre font-data-mono text-[13px] text-white whitespace-pre-wrap break-all w-full select-text';
        output.appendChild(pre);
    }
    
    // ── SURGICAL FORMATTING: Red for commands, White for responses ─────
    // We use a helper to wrap text in spans for coloring
    const isCommand = text.includes('› curl') || text.includes('> curl');
    
    if (isCommand) {
        // Add a clean gap before new requests
        const gap = document.createElement('div');
        gap.className = 'h-6 border-b border-white/5 mb-6';
        pre.appendChild(gap);
        
        const span = document.createElement('span');
        span.className = 'text-primary font-bold'; // Red/Primary color
        span.textContent = text.replace('›', '> ');
        pre.appendChild(span);
    } else {
        const span = document.createElement('span');
        span.className = 'text-white/80';
        span.textContent = text;
        pre.appendChild(span);
    }
    
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
    const search = document.getElementById('moduleSearch').value.toLowerCase();
    if (!grid) return; 
    grid.innerHTML = '';

    // ── SURGICAL PRIORITY (MISSION START) ──────────────────────────
    // Only show if no search filter or if searching specifically for these
    // ── RECOMMENDED MODULES (Only show in RECON or ALL) ────────────────
    const isRecon = filter === 'ALL' || filter === 'RECON';
    if (isRecon && (!search || 'Spider'.toLowerCase().includes(search))) {
        const priorityHeader = document.createElement('div');
        priorityHeader.className = 'py-4 border-b border-primary/40 mb-8 bg-primary/5 px-6';
        priorityHeader.innerHTML = `
            <div class="flex items-center justify-between">
                <h4 class="font-label-surgical text-[13px] text-primary font-bold uppercase tracking-[0.4em]">Recommended Modules</h4>
                <span class="font-label-surgical text-[11px] text-primary/60 uppercase">Mandatory First Strike</span>
            </div>
            <p class="font-data-mono text-[11px] text-white/40 mt-3 leading-relaxed">Spider reconnaissance is required before launching specialized agents.</p>
        `;
        grid.appendChild(priorityHeader);

        if (modules['Spider']) {
            const m = modules['Spider'];
            const card = document.createElement('div');
            card.className = 'p-8 bg-primary/10 border border-primary/30 cursor-pointer transition-all group relative overflow-hidden pop-out-red';
            card.innerHTML = `
                <div class="absolute top-0 right-0 p-2 bg-primary text-background font-label-surgical text-[10px] font-bold">CORE_AGENT</div>
                <h3 class="text-[14px] font-bold uppercase text-white group-hover:text-primary transition-colors">${normalizeName(m.name)}</h3>
                <p class="text-[11px] text-white/40 mt-3 uppercase tracking-widest font-data-mono">Universal Recon & Target Seeding</p>
            `;
            card.onclick = () => openForge('Spider');
            grid.appendChild(card);
        }
    }

    PHASE_ORDER.forEach(phase => {
        if (filter !== 'ALL' && filter !== phase) return;
        
        let mods = Object.keys(modules).filter(k => (CATEGORY_MAP[modules[k].category] || 'VULN') === phase);
        
        // Apply Search Filter
        if (search) {
            mods = mods.filter(k => 
                modules[k].name.toLowerCase().includes(search) || 
                modules[k].description.toLowerCase().includes(search) ||
                k.toLowerCase().includes(search)
            );
        }

        if (mods.length === 0) return;

        // Sorting (Spider already handled in priority)
        mods.sort((a, b) => modules[a].name.localeCompare(modules[b].name));

        const header = document.createElement('div');
        header.className = 'py-2 border-b border-white/10 mt-10 mb-6';
        header.innerHTML = `<h4 class="font-label-surgical text-[10px] text-white/40 font-bold uppercase tracking-[0.4em]">${PHASE_LABELS[phase]} PHASE</h4>`;
        grid.appendChild(header);

        mods.forEach(key => {
            if (key === 'Spider' && !search && isRecon) return; // Skip if already shown in priority and not searching
            
            const m = modules[key];
            const card = document.createElement('div');
            const displayName = normalizeName(m.name);
            card.className = 'p-6 bg-white/5 border border-white/5 cursor-pointer transition-all group mb-4 pop-out-red';
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
    
    // Manage Forge UI States
    document.getElementById('moduleForgeEmpty').classList.add('hidden');
    document.getElementById('moduleForgeContent').classList.remove('hidden');

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

    // ── SURGICAL: Intelligence Dependency Check ──────────────────────
    const needsSpider = SPIDER_DEPENDENT_MODULES.includes(selectedModuleKey);
    const hasSpiderLoot = lastIntelTargets.length > 0; // Simplified check: any loot usually implies spider or recon has run
    
    if (needsSpider && !hasSpiderLoot) {
        showNotification(
            'INTELLIGENCE_GAP_DETECTED',
            `${selectedModuleKey} requires spider reconnaissance data to seed targets. Run Spider first to avoid mission failure.`,
            'INITIALIZE SPIDER',
            () => openForge('spider')
        );
        return; // Lock the strike
    }

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
        targetHeader.className = 'flex items-center gap-3 py-3 border-b border-white/10 mb-2';
        targetHeader.innerHTML = `
            <span class="material-symbols-outlined text-[18px] text-primary">target</span>
            <span class="font-label-surgical text-[12px] text-primary uppercase tracking-[0.2em] font-bold">${target === '_root' ? 'global intelligence' : target}</span>
            <span class="font-data-mono text-[10px] text-white/40 ml-auto">${fileList.length} artifacts</span>
        `;
        groupDiv.appendChild(targetHeader);

        fileList.forEach(({ fileKey, relPath }) => {
            const lines = lootMap[relPath] || [];
            const modName = fileKey.replace(/\.(json|txt)$/, '').replace(/_/g, ' ').toUpperCase();

            const section = document.createElement('div');
            section.className = 'ml-5 space-y-1 mb-3';

            const modHeader = document.createElement('div');
            modHeader.className = 'flex items-center justify-between py-1 border-b border-white/10';
            modHeader.innerHTML = `
                <span class="font-label-surgical text-[11px] text-white/70 uppercase tracking-widest font-bold">${modName}</span>
                <span class="font-data-mono text-[10px] text-white/30">${lines.length} entries</span>
            `;
            section.appendChild(modHeader);

            lines.slice(0, 30).forEach(line => {
                const div = document.createElement('div');
                div.className = 'font-data-mono text-[12px] text-white/85 py-1 px-2 hover:bg-white/5 break-all leading-relaxed select-text cursor-text transition-colors';
                div.style.userSelect = 'text';
                div.textContent = line;
                section.appendChild(div);
            });

            if (lines.length > 30) {
                const more = document.createElement('div');
                more.className = 'font-label-surgical text-[10px] text-white/40 uppercase tracking-widest px-2 py-2';
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
    const output = document.getElementById('opsOutput');
    if (output && data.trim()) {
        output.innerText += data;
        output.scrollTop = output.scrollHeight;
        
        // Detect strike completion in raw stream for instant status update
        if (data.includes('[+] Strike complete')) {
            const displayName = normalizeName(modules[selectedModuleKey]?.name || selectedModuleKey);
            setMissionState('complete', displayName, activeTarget);
            setEngineDot('ops', 'online');
        }
    }
});

ipcRenderer.on('telemetry-event', (event, { line, severity }) => {
    const container = document.getElementById('opsFindings');
    if (!container) return;

    const colors = {
        critical: 'border-red-600 text-red-400 bg-red-600/10',
        high:     'border-primary text-primary bg-primary/10',
        medium:   'border-yellow-500 text-yellow-300 bg-yellow-500/10',
        low:      'border-white/30 text-white/90 bg-white/5',
        info:     'border-blue-400 text-blue-200 bg-blue-400/10'
    };
    const labels = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' };

    // Filter: Only show Medium, High, and Critical in the main Findings panel
    const isHighValue = severity === 'high' || severity === 'critical' || severity === 'medium';
    if (isHighValue) {
        const div = document.createElement('div');
        div.className = `p-4 border-l-4 ${colors[severity] || colors.info} text-[13px] font-data-mono animate-fade-in flex gap-4 items-start shadow-lg`;
        div.innerHTML = `
            <span class="font-bold text-[10px] uppercase tracking-widest mt-1 whitespace-nowrap">${labels[severity] || 'INFO'}</span>
            <span class="leading-relaxed break-all select-text text-white/95" style="user-select:text">${line}</span>
        `;
        container.prepend(div);
        while (container.children.length > 200) container.removeChild(container.lastChild);
    }

    // SURGICAL: Extract cURL commands for the Repro Hub
    const mKey = selectedModuleKey ? selectedModuleKey.toLowerCase() : '';
    const isSpider = mKey.includes('spider');
    const hasCurl = line.includes('curl ') || line.includes('curl_poc');
    const isFinding = line.includes('[VULN]') || line.includes('[HIGH]') || line.includes('[CRITICAL]');

    // Extract cURL if it's a finding or if it's a direct cURL line (not from spider noise)
    if (hasCurl && (isFinding || !isSpider || line.startsWith('curl'))) {
        let curlMatch = line.match(/curl\s+.+?($|(?= \[))/i);
        if (curlMatch && curlMatch[0]) {
            appendReproCommand(curlMatch[0].trim(), severity);
        }
    }
});

function appendReproCommand(cmd, severity) {
    const list = document.getElementById('reproCommandsList');
    if (!list) return;
    
    const empty = list.querySelector('.italic');
    if (empty) empty.remove();

    const div = document.createElement('div');
    div.className = 'poc-item group p-4 bg-white/5 border border-white/5 cursor-pointer';
    div.onclick = () => selectPoC(cmd, div);
    
    div.innerHTML = `
        <div class="flex items-center justify-between">
            <span class="font-label-surgical text-[8px] text-primary uppercase tracking-[0.2em]">CURL_ARTIFACT</span>
            <span class="font-data-mono text-[8px] text-white/20 uppercase tracking-widest">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="font-data-mono text-[10px] text-white/70 break-all leading-relaxed">${cmd}</div>
    `;
    list.prepend(div);
}

let activePoCCmd = '';

function selectPoC(cmd, el) {
    activePoCCmd = cmd;
    document.querySelectorAll('.poc-item').forEach(item => {
        item.classList.remove('bg-primary/10', 'border-primary/40');
        item.classList.add('bg-white/5', 'border-white/5');
    });
    el.classList.add('bg-primary/10', 'border-primary/40');
    el.classList.remove('bg-white/5', 'border-white/5');

    const terminal = document.getElementById('reproTerminal');
    if (terminal) {
        terminal.innerHTML = `<div class="text-primary font-bold mb-4 uppercase tracking-[0.3em]">Payload_Loaded // Ready for replay</div><div class="p-4 bg-white/5 border border-white/5 rounded text-white/90">${cmd}</div>`;
    }
}

function copyActivePoC() {
    if (!activePoCCmd) {
        pushActivity('No payload selected to copy', 'warn');
        return;
    }
    navigator.clipboard.writeText(activePoCCmd).then(() => {
        pushActivity('Payload copied to neural clipboard', 'ok');
    });
}

function saveActivePoC() {
    if (!activePoCCmd) return;
    ipcRenderer.send('save-loot-file', {
        filename: `repro_${Date.now()}.sh`,
        content: `#!/bin/bash\n${activePoCCmd}`
    });
    pushActivity('Payload saved to local artifacts', 'ok');
}

function copyToRepro(b64) {
    const cmd = atob(b64);
    navigator.clipboard.writeText(cmd).then(() => {
        pushActivity('cURL command copied to clipboard', 'ok');
    });
}

function fireRepro() {
    if (!activePoCCmd) {
        pushActivity('No tactical payload loaded', 'warn');
        return;
    }
    
    if (!reproShell || !reproShell.stdin.writable) {
        pushActivity('Repro engine disconnected', 'warn');
        return;
    }
    
    const terminal = document.getElementById('reproTerminal');
    if (terminal) {
        terminal.innerHTML += `\n<div class="text-green-500 font-bold mt-4 mb-2 uppercase tracking-[0.2em] animate-pulse">› INITIATING REPLAY...</div>`;
    }
    
    reproShell.stdin.write(activePoCCmd + '\n');
    pushActivity('Surgical payload piped to execution hub', 'strike');
}

function clearReproCommands() {
    const list = document.getElementById('reproCommandsList');
    if (list) {
        list.innerHTML = '<div class="font-label-surgical text-[8px] text-white/10 uppercase tracking-widest text-center py-4 italic">No repro commands detected</div>';
    }
}

ipcRenderer.on('proc-exit', (event, { pid, code }) => {
    const displayName = normalizeName(modules[selectedModuleKey]?.name || selectedModuleKey);
    // Only update to error if not already marked complete by string detection
    const statusLabel = document.getElementById('missionStatusLabel');
    if (statusLabel && statusLabel.innerText !== 'COMPLETE') {
        setMissionState(code === 0 ? 'complete' : 'error', displayName, activeTarget);
    }
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
    
    // Only block send button while thinking, NOT the input
    const btn = document.querySelector('[onclick="sendAI()"]');
    if (btn) {
        btn.disabled = true;
        btn.classList.add('opacity-30', 'pointer-events-none');
    }
}

function appendHellhoundMessage(role, text) {
    const container = document.getElementById('ask-history');
    if (!container) return;

    // SURGICAL: Aggressive filtration for professional HUD aesthetics
    let cleanText = stripAnsi(text)
        .replace(/HELLHOUND (is|IS) thINKING/gi, '')
        .replace(/⡀|⡄|⡆|⡇|⣇|⣧|⣷|⣿/g, '') // Braille noise
        .replace(/─{5,}/g, '') // Long horizontal dividers
        .replace(/═{5,}/g, '') 
        .replace(/^[ \t]*[*+!✓x>][ \t]/gm, '') // CLI bullet markers at start of lines
        .replace(/\[[*+!✓x>]\]/g, '') // Brackets around markers
        .replace(/\[(INFO|WARN|CRIT|HIGH|MED|LOW)\]/g, '') // Severity tags if leaked
        .replace(/\n{3,}/g, '\n\n') // Normalize spacing
        .trim();

    if (!cleanText && role === 'hellhound') return;

    const bubble = document.createElement('div');
    bubble.className = `chat-bubble ${role} animate-fade-in chat-noise-filtered group mb-4`;
    
    const roleLabel = role === 'hellhound' ? 'HELLHOUND' : 'YOU';
    const labelColor = role === 'hellhound' ? 'text-primary/60' : 'text-blue-400/60';

    bubble.innerHTML = `
        <div class="flex items-center justify-between mb-2">
            <div class="font-label-surgical text-[9px] ${labelColor} uppercase tracking-[0.2em] font-bold">${roleLabel}</div>
            <div class="flex items-center gap-3">
                <button onclick="copyMessage(this)" class="text-white/20 hover:text-white/60 transition-colors p-1" title="Copy Message">
                    <span class="material-symbols-outlined text-[14px]">content_copy</span>
                </button>
                <div class="text-[8px] text-white/10 font-data-mono opacity-0 group-hover:opacity-100 transition-opacity uppercase">${new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</div>
            </div>
        </div>
        <div class="chat-text-container bg-white/3 border border-white/5 p-4 rounded-lg relative overflow-hidden">
            <div class="absolute top-0 left-0 w-1 h-full ${role === 'hellhound' ? 'bg-primary/20' : 'bg-blue-500/20'}"></div>
            <pre class="font-data-mono text-[13px] text-white/90 whitespace-pre-wrap leading-relaxed select-text">${cleanText}</pre>
        </div>
    `;
    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
}

function copyMessage(btn) {
    const bubble = btn.closest('.chat-bubble');
    const pre = bubble.querySelector('pre');
    if (pre) {
        navigator.clipboard.writeText(pre.innerText).then(() => {
            pushActivity('Intel copied to neural clipboard', 'ok');
            const icon = btn.querySelector('.material-symbols-outlined');
            icon.innerText = 'check';
            setTimeout(() => icon.innerText = 'content_copy', 2000);
        });
    }
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

// ── NEURAL ATTACK GRAPH ────────────────────────────────────────────────
let obsidianGraph = null;
let isPhysicsEnabled = true;
let currentLayout = 'cose';
let graphStyle = 'maltego'; // 'maltego' or 'obsidian'

const SAMPLE_ATTACK_GRAPH = {
    "nodes": [
        { 
            "id": 0, "label": "HELLHOUND_CORE", "type": "engine", "layer": "core", 
            "description": "Central Intelligence & Orchestration Engine.", 
            "recommendation": "Maintain core encryption and isolation.",
            "version": "12.5.1-Apex", "uptime": 345600, "scan_status": "COMPLETE",
            "active_modules": ["Spider", "Hydra", "SecretScanner", "XSStrike"],
            "confidence": "HIGH", "date_discovered": "2026-05-10T08:00:00Z"
        },
        
        // PERIMETER
        { 
            "id": 1, "label": "CORP_FW_01", "type": "system", "layer": "external", 
            "description": "Primary Enterprise Firewall.", 
            "recommendation": "Audit egress rules for anomalies.",
            "vendor": "Fortinet", "version": "v7.4.1", "rule_count": 1250, "last_updated": "2026-05-12T04:00:00Z",
            "confidence": "HIGH", "date_discovered": "2026-05-13T10:00:00Z", "remediation_effort": "MEDIUM", "remediation_time": 8
        },
        { 
            "id": 2, "label": "WAF_CLOUDFLARE", "type": "system", "layer": "external", 
            "description": "Edge Application Firewall.", 
            "recommendation": "Tune WAF rules for GraphQL introspection protection.",
            "vendor": "Cloudflare", "version": "Enterprise_v2", "rule_count": 84, "last_updated": "2026-05-13T00:00:00Z",
            "confidence": "HIGH", "date_discovered": "2026-05-13T10:05:00Z", "remediation_effort": "LOW", "remediation_time": 2
        },
        { 
            "id": 3, "label": "WORKFLOW_RECON", "type": "workflow", "layer": "external", 
            "description": "Automated Reconnaissance Pipeline.", 
            "recommendation": "Rotate recon API keys periodically.",
            "confidence": "HIGH", "date_discovered": "2026-05-13T10:10:00Z", "remediation_effort": "LOW", "remediation_time": 1
        },
        { 
            "id": 4, "label": "IDS_SNORT", "type": "system", "layer": "external", 
            "description": "Intrusion Detection System.", 
            "recommendation": "Update signature database for latest CVEs.",
            "vendor": "Cisco", "version": "3.1.50", "rule_count": 24000, "last_updated": "2026-05-12T12:00:00Z",
            "confidence": "MEDIUM", "date_discovered": "2026-05-13T10:15:00Z", "remediation_effort": "LOW", "remediation_time": 4
        },
        
        // TARGET ASSETS
        { 
            "id": 5, "label": "api.corporate.com", "type": "url_root", "layer": "target", 
            "description": "Production API Gateway.", 
            "recommendation": "Enforce strict rate limiting.",
            "http_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "response_time_ms": 85, "status_code": 200, "requires_auth": true, "auth_type": "JWT", "content_type": "JSON", "exposed_data_types": ["PII", "Financial"],
            "confidence": "HIGH", "date_discovered": "2026-05-13T10:20:00Z"
        },
        { 
            "id": 6, "label": "/graphql", "type": "endpoint_graphql", "layer": "target", 
            "description": "Unified Data Endpoint.", 
            "recommendation": "Disable introspection in production.",
            "http_methods": ["POST"], "response_time_ms": 210, "status_code": 200, "requires_auth": false, "auth_type": "None", "content_type": "GraphQL", "exposed_data_types": ["Schema", "Internal Metadata"],
            "found_in": "api.corporate.com", "confidence": "HIGH", "date_discovered": "2026-05-13T10:25:00Z"
        },
        { 
            "id": 7, "label": "/admin/dashboard", "type": "endpoint_admin", "layer": "target", 
            "description": "Internal Admin Interface.", 
            "recommendation": "Enforce Multi-Factor Authentication (MFA).",
            "http_methods": ["GET"], "response_time_ms": 45, "status_code": 401, "requires_auth": true, "auth_type": "Session Cookie", "content_type": "HTML", "exposed_data_types": ["Admin Metadata"],
            "found_in": "api.corporate.com", "confidence": "HIGH", "date_discovered": "2026-05-13T10:30:00Z"
        },
        { 
            "id": 8, "label": "/rest/user/profile", "type": "endpoint_rest", "layer": "target", 
            "description": "User Profile Management.", 
            "recommendation": "Validate user session fidelity.",
            "http_methods": ["GET", "POST"], "response_time_ms": 120, "status_code": 200, "requires_auth": true, "auth_type": "Bearer", "content_type": "JSON", "exposed_data_types": ["PII", "Credentials"],
            "found_in": "api.corporate.com", "confidence": "HIGH", "date_discovered": "2026-05-13T10:35:00Z"
        },
        { 
            "id": 9, "label": "/ftp/backup", "type": "endpoint_sensitive", "layer": "target", 
            "description": "Unprotected Backup Storage.", 
            "recommendation": "Secure directory listing and encrypt backups.",
            "http_methods": ["GET"], "response_time_ms": 500, "status_code": 200, "requires_auth": false, "auth_type": "None", "content_type": "Binary", "exposed_data_types": ["Backups", "Config Files", "Secrets"],
            "found_in": "dev.internal.corp", "confidence": "HIGH", "date_discovered": "2026-05-13T10:40:00Z"
        },
        { 
            "id": 10, "label": "/oauth/token", "type": "endpoint_auth", "layer": "target", 
            "description": "Identity Provider Endpoint.", 
            "recommendation": "Rotate RSA signing keys.",
            "http_methods": ["POST"], "response_time_ms": 300, "status_code": 200, "requires_auth": false, "auth_type": "Basic", "content_type": "JSON", "exposed_data_types": ["Access Tokens"],
            "found_in": "api.corporate.com", "confidence": "HIGH", "date_discovered": "2026-05-13T10:45:00Z"
        },
        { 
            "id": 11, "label": "dev.internal.corp", "type": "url_root", "layer": "target", 
            "description": "Development Staging Server.", 
            "recommendation": "Isolate from production network.",
            "http_methods": ["GET", "POST"], "response_time_ms": 45, "status_code": 200, "requires_auth": false, "auth_type": "None", "content_type": "HTML", "exposed_data_types": ["Source Code", "Internal Paths"],
            "confidence": "HIGH", "date_discovered": "2026-05-13T10:50:00Z"
        },
        
        // INTELLIGENCE / SECRETS
        { 
            "id": 12, "label": "AWS_PROD_KEY", "type": "secret_aws", "layer": "intel", "severity": "critical", "risk": "critical", 
            "description": "Compromised AWS Access Key.", 
            "recommendation": "Revoke IAM user and rotate keys.",
            "exposure_location": "/ftp/backup/config.json", "exposure_method": "Hardcoded", "privilege_level": "Admin", "rotation_required": true, "rotation_days": 30, "is_active": true,
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:00:00Z", "remediation_effort": "HIGH", "remediation_time": 4, "affected_assets": ["AWS Account: 123456789012"]
        },
        { 
            "id": 13, "label": "JWT_SECRET", "type": "secret_jwt", "layer": "intel", "severity": "high", "risk": "high", 
            "description": "Hardcoded JWT HMAC Secret.", 
            "recommendation": "Move to HashiCorp Vault.",
            "exposure_location": "/rest/user/profile", "exposure_method": "Source Map", "privilege_level": "Write", "rotation_required": true, "rotation_days": 90, "is_active": true,
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:05:00Z", "remediation_effort": "MEDIUM", "remediation_time": 8, "affected_assets": ["api.corporate.com"]
        },
        { 
            "id": 14, "label": "DB_CREDENTIALS", "type": "secret_db", "layer": "intel", "severity": "high", "risk": "high", 
            "description": "Production Database Password.", 
            "recommendation": "Implement DB user rotation.",
            "exposure_location": "/ftp/backup/db_dump.sql", "exposure_method": "Logs", "privilege_level": "Admin", "rotation_required": true, "rotation_days": 30, "is_active": true,
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:10:00Z", "remediation_effort": "MEDIUM", "remediation_time": 4, "affected_assets": ["PostgreSQL Prod Cluster"]
        },
        { 
            "id": 15, "label": "SLACK_WEBHOOK", "type": "secret_token", "layer": "intel", "severity": "medium", "risk": "medium", 
            "description": "Exposed Slack Incoming Webhook.", 
            "recommendation": "Deactivate webhook URL.",
            "exposure_location": "api.corporate.com JS bundle", "exposure_method": "Source Map", "privilege_level": "Write", "rotation_required": false, "is_active": true,
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:15:00Z", "remediation_effort": "LOW", "remediation_time": 1, "affected_assets": ["Slack Workspace: Corp-Dev"]
        },
        { 
            "id": 16, "label": "SSH_PRIVATE_KEY", "type": "secret_ssh", "layer": "intel", "severity": "critical", "risk": "critical", 
            "description": "Root SSH Key for Dev Server.", 
            "recommendation": "Cycle SSH keys and enforce passphrase.",
            "exposure_location": "/ftp/backup/.ssh/id_rsa", "exposure_method": "Hardcoded", "privilege_level": "Root", "rotation_required": true, "rotation_days": 90, "is_active": true,
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:20:00Z", "remediation_effort": "MEDIUM", "remediation_time": 2, "affected_assets": ["dev.internal.corp"]
        },
        { 
            "id": 17, "label": "STRIPE_KEY", "type": "secret_payment", "layer": "intel", "severity": "high", "risk": "high", 
            "description": "Stripe Live API Key.", 
            "recommendation": "Restrict key permissions to specific IPs.",
            "exposure_location": "/rest/user/profile logs", "exposure_method": "Logs", "privilege_level": "Admin", "rotation_required": true, "rotation_days": 30, "is_active": true,
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:25:00Z", "remediation_effort": "LOW", "remediation_time": 1, "affected_assets": ["Stripe Prod Account"]
        },
        { 
            "id": 18, "label": "GITHUB_TOKEN", "type": "secret_token", "layer": "intel", "severity": "high", "risk": "high", 
            "description": "Personal Access Token with Repo Access.", 
            "recommendation": "Revoke and use fine-grained tokens.",
            "exposure_location": "dev.internal.corp .env", "exposure_method": "Environment File", "privilege_level": "Admin", "rotation_required": true, "rotation_days": 30, "is_active": true,
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:30:00Z", "remediation_effort": "LOW", "remediation_time": 1, "affected_assets": ["GitHub Org: Hellhound-Org"]
        },
        { 
            "id": 19, "label": "DOCKER_CONFIG", "type": "secret_token", "layer": "intel", "severity": "medium", "risk": "medium", 
            "description": "Registry Authentication Token.", 
            "recommendation": "Use short-lived auth tokens.",
            "exposure_location": "dev.internal.corp logs", "exposure_method": "Logs", "privilege_level": "Read", "rotation_required": true, "rotation_days": 30, "is_active": true,
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:35:00Z", "remediation_effort": "LOW", "remediation_time": 1, "affected_assets": ["Docker Hub: hellhound-repo"]
        },
        
        // VULNERABILITIES
        { 
            "id": 20, "label": "LOG4J_RCE", "type": "vuln_log4j", "layer": "vulnerabilities", "severity": "critical", "risk": "critical", 
            "cwe": "CWE-94", "cvss_score": "10.0", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "cve_id": "CVE-2021-44228",
            "epss_score": 0.974, "epss_percentile": 99.8, "known_weapons": true, "exploit_available": true, "exploit_db_id": "EDB-50421", "owasp_category": "A03:2021-Injection", "exploit_complexity": "LOW", "privileges_required": "NONE", "user_interaction": "NONE",
            "description": "RCE via JNDI injection in dev server.", 
            "recommendation": "Update Log4j to 2.17.1+ and set formatMsgNoLookups=true.",
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:40:00Z", "remediation_effort": "MEDIUM", "remediation_time": 4, "affected_assets": ["dev.internal.corp"]
        },
        { 
            "id": 21, "label": "SQL_INJECTION", "type": "vuln_sqli", "layer": "vulnerabilities", "severity": "critical", "risk": "critical", 
            "cwe": "CWE-89", "cvss_score": "9.8", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cve_id": "CVE-2023-1234",
            "epss_score": 0.85, "epss_percentile": 92.5, "known_weapons": false, "exploit_available": true, "owasp_category": "A03:2021-Injection", "exploit_complexity": "LOW", "privileges_required": "NONE", "user_interaction": "NONE",
            "description": "Unfiltered input in search parameter.", 
            "recommendation": "Use parameterized queries.",
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:45:00Z", "remediation_effort": "MEDIUM", "remediation_time": 8, "affected_assets": ["api.corporate.com"]
        },
        { 
            "id": 22, "label": "IDOR_USER_DATA", "type": "vuln_idor", "layer": "vulnerabilities", "severity": "high", "risk": "high", 
            "cwe": "CWE-639", "cvss_score": "7.5", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "owasp_category": "A01:2021-Broken Access Control", "exploit_complexity": "LOW", "privileges_required": "LOW", "user_interaction": "NONE",
            "description": "Can access any user profile via ID manipulation.", 
            "recommendation": "Implement attribute-based access control.",
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:50:00Z", "remediation_effort": "MEDIUM", "remediation_time": 12, "affected_assets": ["api.corporate.com"]
        },
        { 
            "id": 23, "label": "XSS_STORED", "type": "vuln_xss", "layer": "vulnerabilities", "severity": "medium", "risk": "medium", 
            "cwe": "CWE-79", "cvss_score": "5.4", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N", "owasp_category": "A03:2021-Injection", "exploit_complexity": "MEDIUM", "privileges_required": "LOW", "user_interaction": "REQUIRED",
            "description": "Stored XSS in user comments section.", 
            "recommendation": "Sanitize HTML input and use CSP.",
            "confidence": "HIGH", "date_discovered": "2026-05-13T11:55:00Z", "remediation_effort": "LOW", "remediation_time": 4, "affected_assets": ["api.corporate.com"]
        },
        { 
            "id": 24, "label": "BAC_ADMIN_PANEL", "type": "vuln_broken_access", "layer": "vulnerabilities", "severity": "high", "risk": "high", 
            "cwe": "CWE-285", "cvss_score": "8.1", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "owasp_category": "A01:2021-Broken Access Control", "exploit_complexity": "LOW", "privileges_required": "NONE", "user_interaction": "NONE",
            "description": "Admin dashboard accessible without proper role check.", 
            "recommendation": "Validate user role on every request.",
            "confidence": "HIGH", "date_discovered": "2026-05-13T12:00:00Z", "remediation_effort": "MEDIUM", "remediation_time": 6, "affected_assets": ["api.corporate.com"]
        },
        { 
            "id": 25, "label": "GRAPHQL_INTRO", "type": "vuln_graphql", "layer": "vulnerabilities", "severity": "medium", "risk": "medium", 
            "cwe": "CWE-200", "cvss_score": "5.0", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "owasp_category": "A01:2021-Broken Access Control", "exploit_complexity": "LOW", "privileges_required": "NONE", "user_interaction": "NONE",
            "description": "Introspection enabled, leaking schema details.", 
            "recommendation": "Disable introspection in production.",
            "confidence": "HIGH", "date_discovered": "2026-05-13T12:05:00Z", "remediation_effort": "LOW", "remediation_time": 1, "affected_assets": ["api.corporate.com"]
        },
        { 
            "id": 26, "label": "SSRF_METADATA", "type": "vuln_ssrf", "layer": "vulnerabilities", "severity": "high", "risk": "high", 
            "cwe": "CWE-918", "cvss_score": "8.3", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "owasp_category": "A10:2021-Server-Side Request Forgery", "exploit_complexity": "LOW", "privileges_required": "NONE", "user_interaction": "NONE",
            "description": "Can reach cloud metadata service via webhook proxy.", 
            "recommendation": "Validate destination URLs and block internal IPs.",
            "confidence": "HIGH", "date_discovered": "2026-05-13T12:10:00Z", "remediation_effort": "MEDIUM", "remediation_time": 8, "affected_assets": ["dev.internal.corp"]
        },
        { 
            "id": 27, "label": "OPEN_REDIRECT", "type": "vuln_open_redirect", "layer": "vulnerabilities", "severity": "low", "risk": "low", 
            "cwe": "CWE-601", "cvss_score": "3.5", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "owasp_category": "A03:2021-Injection", "exploit_complexity": "LOW", "privileges_required": "NONE", "user_interaction": "REQUIRED",
            "description": "Unvalidated redirect in logout parameter.", 
            "recommendation": "Use a whitelist of allowed domains.",
            "confidence": "HIGH", "date_discovered": "2026-05-13T12:15:00Z", "remediation_effort": "LOW", "remediation_time": 2, "affected_assets": ["api.corporate.com"]
        },
        { 
            "id": 28, "label": "JWT_NONE_ALGO", "type": "vuln_broken_access", "layer": "vulnerabilities", "severity": "high", "risk": "high", 
            "cwe": "CWE-287", "cvss_score": "7.8", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "owasp_category": "A07:2021-Identification and Authentication Failures", "exploit_complexity": "LOW", "privileges_required": "NONE", "user_interaction": "NONE",
            "description": "JWT accepting 'none' algorithm for auth bypass.", 
            "recommendation": "Enforce specific signing algorithms.",
            "confidence": "HIGH", "date_discovered": "2026-05-13T12:20:00Z", "remediation_effort": "MEDIUM", "remediation_time": 4, "affected_assets": ["api.corporate.com"]
        },
        { 
            "id": 29, "label": "S3_BUCKET_PUBLIC", "type": "vuln_broken_access", "layer": "vulnerabilities", "severity": "high", "risk": "high", 
            "cwe": "CWE-284", "cvss_score": "7.2", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "owasp_category": "A01:2021-Broken Access Control", "exploit_complexity": "LOW", "privileges_required": "NONE", "user_interaction": "NONE",
            "description": "Publicly readable backup bucket.", 
            "recommendation": "Restrict S3 bucket permissions.",
            "confidence": "HIGH", "date_discovered": "2026-05-13T12:25:00Z", "remediation_effort": "LOW", "remediation_time": 1, "affected_assets": ["S3 Bucket: corp-prod-backups"]
        },
        
        // TECHNOLOGY
        { 
            "id": 30, "label": "NODEJS_EXPRESS", "type": "tech_backend", "layer": "target", 
            "description": "Core application runtime.",
            "version": "16.14.0", "latest_version": "20.11.0", "end_of_life": "2023-09-11", "vulnerable_version": true, "known_cves": ["CVE-2023-1234"], "deprecated": true,
            "confidence": "HIGH", "date_discovered": "2026-05-13T12:30:00Z"
        },
        { 
            "id": 31, "label": "REACT_FRONTEND", "type": "tech_frontend", "layer": "target", 
            "description": "Client-side SPA framework.",
            "version": "17.0.2", "latest_version": "18.2.0", "vulnerable_version": false, "deprecated": false,
            "confidence": "HIGH", "date_discovered": "2026-05-13T12:35:00Z"
        },
        { 
            "id": 32, "label": "POSTGRESQL", "type": "tech_database", "layer": "target", 
            "description": "Primary relational database.",
            "version": "13.8", "latest_version": "16.1", "vulnerable_version": false, "deprecated": false,
            "confidence": "HIGH", "date_discovered": "2026-05-13T12:40:00Z"
        },
        { 
            "id": 33, "label": "DOCKER_CONTAINER", "type": "tech_container", "layer": "target", 
            "description": "Microservice isolation layer.",
            "version": "20.10.12", "latest_version": "24.0.7", "vulnerable_version": false, "deprecated": false,
            "confidence": "HIGH", "date_discovered": "2026-05-13T12:45:00Z"
        },
        { 
            "id": 34, "label": "CLOUDFRONT_CDN", "type": "tech_cdn", "layer": "target", 
            "description": "Content delivery and caching.",
            "version": "Managed", "confidence": "HIGH", "date_discovered": "2026-05-13T12:50:00Z"
        },
        
        // ATTACK CHAINS
        { 
            "id": 35, "label": "CHAIN_PRIV_ESC", "type": "attack_chain", "layer": "post_exploit", "severity": "high", 
            "impact": "Full takeover of dev server environment.",
            "kill_chain_phase": "Exploitation", "prerequisites": ["LOG4J_RCE", "SSH_PRIVATE_KEY"], "estimated_time": "30 minutes", "detection_score": 45, "mitre_techniques": ["T1068", "T1078"],
            "confidence": "HIGH", "date_discovered": "2026-05-13T13:00:00Z"
        },
        { 
            "id": 36, "label": "CHAIN_DATA_EXFIL", "type": "attack_chain", "layer": "post_exploit", "severity": "critical", 
            "impact": "Exporting production database via leaked AWS keys.",
            "kill_chain_phase": "Actions", "prerequisites": ["AWS_PROD_KEY", "DB_CREDENTIALS"], "estimated_time": "2 hours", "detection_score": 15, "mitre_techniques": ["T1020", "T1537"],
            "confidence": "HIGH", "date_discovered": "2026-05-13T13:05:00Z"
        },
        { 
            "id": 37, "label": "CHAIN_LATERAL_MOVE", "type": "attack_chain", "layer": "post_exploit", "severity": "high", 
            "impact": "Pivoting from dev server to production gateway.",
            "kill_chain_phase": "Installation", "prerequisites": ["SSH_PRIVATE_KEY", "SSRF_METADATA"], "estimated_time": "1 hour", "detection_score": 30, "mitre_techniques": ["T1021", "T1190"],
            "confidence": "HIGH", "date_discovered": "2026-05-13T13:10:00Z"
        },
        { 
            "id": 38, "label": "CHAIN_PERSISTENCE", "type": "attack_chain", "layer": "post_exploit", "severity": "high", 
            "impact": "Maintaining access via SSH key injection.",
            "kill_chain_phase": "Installation", "prerequisites": ["BAC_ADMIN_PANEL", "SSH_PRIVATE_KEY"], "estimated_time": "15 minutes", "detection_score": 20, "mitre_techniques": ["T1098", "T1133"],
            "confidence": "HIGH", "date_discovered": "2026-05-13T13:15:00Z"
        },
        { 
            "id": 39, "label": "CHAIN_ACC_TAKEOVER", "type": "attack_chain", "layer": "post_exploit", "severity": "critical", 
            "impact": "Bypassing auth via JWT manipulation to hijack admins.",
            "kill_chain_phase": "Exploitation", "prerequisites": ["JWT_NONE_ALGO", "IDOR_USER_DATA"], "estimated_time": "10 minutes", "detection_score": 60, "mitre_techniques": ["T1550", "T1078"],
            "confidence": "HIGH", "date_discovered": "2026-05-13T13:20:00Z"
        }
    ],
    "edges": [
        { "from": 0, "to": 1 }, { "from": 0, "to": 2 }, { "from": 0, "to": 3 }, { "from": 0, "to": 4 },
        { "from": 1, "to": 5 }, { "from": 2, "to": 5 }, { "from": 3, "to": 5 }, { "from": 4, "to": 11 }, { "from": 1, "to": 11 },
        { "from": 5, "to": 6 }, { "from": 5, "to": 7 }, { "from": 5, "to": 8 }, { "from": 5, "to": 10 }, { "from": 11, "to": 9 },
        { "from": 6, "to": 13 }, { "from": 8, "to": 13 }, { "from": 9, "to": 12 }, { "from": 9, "to": 14 }, { "from": 9, "to": 16 }, 
        { "from": 5, "to": 15 }, { "from": 11, "to": 18 }, { "from": 11, "to": 19 }, { "from": 8, "to": 17 },
        { "from": 6, "to": 25 }, { "from": 7, "to": 24 }, { "from": 8, "to": 22 }, { "from": 10, "to": 28 }, 
        { "from": 5, "to": 23 }, { "from": 11, "to": 20 }, { "from": 11, "to": 26 }, { "from": 5, "to": 21 }, 
        { "from": 5, "to": 27 }, { "from": 12, "to": 29 }, { "from": 13, "to": 28 }, { "from": 14, "to": 21 },
        { "from": 20, "to": 35 }, { "from": 21, "to": 36 }, { "from": 22, "to": 39 }, { "from": 24, "to": 38 }, 
        { "from": 26, "to": 37 }, { "from": 28, "to": 39 }, { "from": 16, "to": 37 }, { "from": 12, "to": 36 },
        { "from": 37, "to": 11 }, { "from": 35, "to": 7 }, { "from": 39, "to": 7 }, { "from": 36, "to": 1 },
        { "from": 30, "to": 5 }, { "from": 31, "to": 5 }, { "from": 32, "to": 14 }, { "from": 33, "to": 19 }, { "from": 34, "to": 2 },
        { "from": 5, "to": 30 }, { "from": 11, "to": 33 }, { "from": 14, "to": 32 }, { "from": 10, "to": 31 }
    ]
};
function convertToCytoFormat(json) {
    const elements = [];
    (json.nodes || []).forEach(n => {
        elements.push({
            data: {
                id: String(n.id),
                label: n.label,
                type: n.type || n.layer || 'default',
                color: n.color,
                metadata: n.metadata || {},
                // copy all top-level fields too
                description: n.metadata?.description || n.description || '',
                severity: n.metadata?.severity || n.severity || '',
                risk: n.metadata?.risk || n.risk || '',
                cvss: n.metadata?.cvss || n.cvss_score || '',
                cwe: n.metadata?.cwe || n.cwe || '',
                version: n.metadata?.version || n.version || '',
                layer: n.layer || ''
            }
        });
    });
    (json.edges || []).forEach((e, i) => {
        elements.push({
            data: {
                id: `e_${i}`,
                source: String(e.from),
                target: String(e.to),
                label: e.label || '',
                edgeType: e.label || ''
            }
        });
    });
    return elements;
}

const TYPE_COLORS = {
    'module': '#ff2244',
    'info': '#4488ff',
    'instruction': '#00ffff',
    'url': '#22c55e',
    'parameter': '#eab308',
    'secret': '#ec4899',
    'vulnerability': '#ef4444',
    'technology': '#a855f7',
    'attack_chain': '#f97316'
};

function hideNodeInfo() {
    const panel = document.getElementById('graphNodeInfo');
    if (panel) panel.style.display = 'none';
}

function showNodeInfo(data) {
    const panel = document.getElementById('graphNodeInfo');
    const label = document.getElementById('infoLabel');
    const icon = document.getElementById('infoIcon');
    const desc = document.getElementById('infoDesc');
    const meta = document.getElementById('infoMeta');

    if (!panel) return;

    icon.innerHTML = `<span class="material-symbols-outlined text-[32px]" style="color:${TYPE_COLORS[data.type] || '#ff2244'}">${data.icon || 'circle'}</span>`;
    label.innerText = data.label || 'NODE_DETAILS';
    label.style.color = TYPE_COLORS[data.type] || '#ff2244';
    desc.innerText = data.description || 'No additional metadata available for this node.';
    
    // Build meta items
    let metaHtml = `
        <div class="info-row">
            <span class="info-label">Type</span>
            <span class="info-value" style="color:${TYPE_COLORS[data.type]}">${data.type.toUpperCase()}</span>
        </div>
    `;

    if (data.severity) {
        const sevColor = data.severity === 'critical' ? 'bg-red-600' : data.severity === 'high' ? 'bg-red-500' : data.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500';
        metaHtml += `
            <div class="info-row">
                <span class="info-label">Severity</span>
                <span class="severity-badge ${sevColor}">${data.severity}</span>
            </div>
        `;
    }

    if (data.risk) {
        const riskColor = data.risk === 'critical' ? 'text-red-500' : data.risk === 'high' ? 'text-orange-500' : 'text-yellow-500';
        metaHtml += `
            <div class="info-row">
                <span class="info-label">Risk</span>
                <span class="info-value ${riskColor}">${data.risk.toUpperCase()}</span>
            </div>
        `;
    }

    if (data.cwe) {
        metaHtml += `
            <div class="info-row">
                <span class="info-label">CWE</span>
                <span class="info-value text-primary">${data.cwe}</span>
            </div>
        `;
    }

    if (data.cvss_score) {
        metaHtml += `
            <div class="info-row">
                <span class="info-label">CVSS</span>
                <span class="info-value">${data.cvss_score}</span>
            </div>
        `;
    }

    if (data.version) {
        metaHtml += `
            <div class="info-row">
                <span class="info-label">Version</span>
                <span class="info-value">${data.version}</span>
            </div>
        `;
    }

    if (data.recommendation) {
        metaHtml += `
            <div class="mt-4 pt-4 border-t border-white/10">
                <span class="font-label-surgical text-[8px] text-white/40 uppercase tracking-widest block mb-2">Surgical Recommendation</span>
                <p class="font-data-mono text-[10px] text-primary italic">${data.recommendation}</p>
            </div>
        `;
    }

    meta.innerHTML = metaHtml;
    panel.style.display = 'block';
}



function getNodeIcon(type) {
    const icons = {
        'url_root': 'hub', 'url': 'language', 'endpoint_rest': 'api', 'endpoint_graphql': 'settings_input_component',
        'endpoint_admin': 'admin_panel_settings', 'endpoint_sensitive': 'folder_shared', 'endpoint_websocket': 'electrical_services',
        'secret_aws': 'cloud', 'secret_jwt': 'key', 'secret_db': 'storage', 'secret': 'lock',
        'vuln_idor': 'error', 'vuln_sqli': 'colorize', 'vuln_bac': 'door_open', 'vulnerability': 'warning',
        'tech_backend': 'terminal', 'technology': 'settings',
        'attack_chain': 'bolt', 'engine': 'local_fire_department', 'workflow': 'sync_alt',
        'parameter': 'list', 'module': 'extension', 'instruction': 'assignment', 'system': 'dns'
    };
    return icons[type] || 'circle';
}

function getNodeColor(type, data) {
    if (data && data.color) return data.color;
    const map = {
        'url_root': '#00b4d8', 'url': '#00b4d8',
        'endpoint_rest': '#48cae4', 'endpoint_graphql': '#90e0ef',
        'endpoint_admin': '#e63946', 'endpoint_sensitive': '#f4a261',
        'endpoint_websocket': '#0077b6',
        'secret_aws': '#f4a261', 'secret_jwt': '#e76f51', 'secret_db': '#f4a261', 'secret': '#ec4899',
        'vuln_idor': '#dc2626', 'vuln_sqli': '#ef4444', 'vuln_bac': '#ef4444', 'vulnerability': '#ff2244',
        'tech_backend': '#2a9d8f', 'technology': '#a855f7',
        'attack_chain': '#9b5de5',
        'engine': '#ffffff', 'workflow': '#00b4d8',
        'parameter': '#eab308', 'module': '#ff2244',
        'instruction': '#ffc107', 'system': '#6c757d'
    };
    return map[type] || '#aaaaaa';
}

function getCytoStylesheet() {
    return [
        {
            selector: 'node',
            style: {
                'background-color': (ele) => getNodeColor(ele.data('type'), ele.data()),
                'width': (ele) => ele.data('layer') === 'core' ? 24 : 8,
                'height': (ele) => ele.data('layer') === 'core' ? 24 : 8,
                'label': '', 
                'opacity': 0.8,
                'overlay-opacity': 0,
                'transition-property': 'width, height, background-color, opacity',
                'transition-duration': '0.15s',
                'shadow-blur': (ele) => ele.data('layer') === 'core' ? 25 : 10,
                'shadow-color': (ele) => getNodeColor(ele.data('type'), ele.data()),
                'shadow-opacity': 0.8
            }
        },
        {
            selector: 'node.hovered, node.highlighted',
            style: {
                'label': 'data(label)',
                'width': (ele) => ele.data('layer') === 'core' ? 32 : 16,
                'height': (ele) => ele.data('layer') === 'core' ? 32 : 16,
                'opacity': 1,
                'color': '#ffffff',
                'font-size': 10,
                'font-family': 'Space Grotesk, monospace',
                'text-margin-y': 4,
                'text-valign': 'bottom',
                'text-halign': 'center',
                'text-outline-width': 2,
                'text-outline-color': '#000000',
                'z-index': 999,
                'shadow-blur': 25,
                'shadow-color': (ele) => getNodeColor(ele.data('type'), ele.data()),
                'shadow-opacity': 1
            }
        },
        {
            selector: 'edge',
            style: {
                'width': 0.8,
                'line-color': 'rgba(255,255,255,0.08)',
                'curve-style': 'haystack',
                'overlay-opacity': 0,
                'opacity': 0.4
            }
        },
        {
            selector: 'edge.highlighted',
            style: {
                'width': 2,
                'line-color': '#ffffff',
                'opacity': 0.8,
                'z-index': 500
            }
        },
        {
            selector: 'node.faded',
            style: { 'opacity': 0.05 }
        },
        {
            selector: 'edge.flowing',
            style: {
                'line-style': 'dashed',
                'line-dash-pattern': [6, 3],
                'line-dash-offset': 'data(offset)'
            }
        }
    ];
}

function getCytoLayout(name) {
    const layouts = {
        'cose': { name: 'cose', animate: true, nodeOverlap: 20, componentSpacing: 100, nodeRepulsion: 4000, edgeElasticity: 100, nestingFactor: 5 },
        'circle': { name: 'circle', animate: true, spacingFactor: 0.8 },
        'grid': { name: 'grid', animate: true, rows: 3 },
        'breadthfirst': { name: 'breadthfirst', animate: true, directed: true, padding: 30 },
        'concentric': { 
            name: 'concentric', 
            animate: true,
            concentric: function(node) {
                const layer = node.data('layer') || '';
                if (layer.includes('vulnerabilities') || layer.includes('core')) return 10;
                if (layer.includes('intel')) return 7;
                if (layer.includes('recon') || layer.includes('target')) return 4;
                return 1;
            },
            levelWidth: () => 1
        },
        'sphere': {
            name: 'preset',
            animate: true,
            animationDuration: 1000,
            positions: function(node) {
                const layer = node.data('layer') || '';
                let r = 300;
                if (layer.includes('vulnerabilities') || layer.includes('core')) r = 50;
                else if (layer.includes('intel')) r = 150;
                else if (layer.includes('recon') || layer.includes('target')) r = 250;
                
                const id = parseInt(node.id()) || 0;
                const theta = (id * 137.5) * (Math.PI / 180); // Fibonacci spiral
                const phi = Math.acos(1 - 2 * (id % 50) / 50);
                
                // 3D to 2D projection (simple sphere mapping)
                return {
                    x: r * Math.sin(phi) * Math.cos(theta),
                    y: r * Math.sin(phi) * Math.sin(theta)
                };
            }
        }
    };
    return layouts[name] || layouts['cose'];
}
let edgeAnimFrame = null;
let rotationAngle = 0;
let mouseX = 0;
let mouseY = 0;

function initAttackGraph() {
    const container = document.getElementById('attackGraph');
    if (!container) return;

    // Clean up old instance
    if (obsidianGraph) {
        obsidianGraph._destructor(); 
        obsidianGraph = null;
    }
    
    if (typeof ForceGraph3D === 'undefined') {
        console.error('ForceGraph3D not loaded');
        container.innerHTML = '<div class="h-full flex items-center justify-center text-primary font-data-mono">ERR: NEURAL_ENGINE_NOT_LOADED</div>';
        return;
    }

    const gData = {
        nodes: SAMPLE_ATTACK_GRAPH.nodes.map(n => ({ ...n })),
        links: SAMPLE_ATTACK_GRAPH.edges.map(e => ({ source: e.from, target: e.to }))
    };

    container.innerHTML = '';
    try {
        obsidianGraph = ForceGraph3D()(container)
        .backgroundColor('#0a0a0f')
        .graphData(gData)
        .showNavInfo(false)
        .nodeRelSize(4)
        .nodeOpacity(0.9)
        .linkOpacity(0.3)
        .linkColor(() => 'rgba(100, 150, 255, 0.3)')
        .linkCurvature(0.2)
        .linkWidth(0.5)
        .nodeThreeObject(node => {
            const size = node.severity === 'critical' ? 6 : (node.severity === 'high' ? 5 : 4);
            const color = getNodeColor(node.type, node);
            
            const geometry = new THREE.SphereGeometry(size);
            const material = new THREE.MeshStandardMaterial({ 
                color: color,
                emissive: color,
                emissiveIntensity: node.severity === 'critical' ? 2 : 0.5,
                transparent: true,
                opacity: 0.9
            });
            return new THREE.Mesh(geometry, material);
        })
        .onNodeHover((node, prevNode) => {
            if (prevNode) {
                prevNode.__threeObj.scale.set(1, 1, 1);
                prevNode.__threeObj.material.emissiveIntensity = prevNode.severity === 'critical' ? 2 : 0.5;
            }
            if (node) {
                node.__threeObj.scale.set(1.5, 1.5, 1.5);
                node.__threeObj.material.emissiveIntensity = 5;
                
                // Show tooltip logic (minimal)
                const tooltip = document.createElement('div');
                tooltip.className = 'obsidian-tooltip';
                tooltip.innerHTML = `
                    <div class="flex items-center gap-2">
                        <span class="material-symbols-outlined text-[12px]" style="color:${getNodeColor(node.type, node)}">${getNodeIcon(node.type)}</span>
                        <span class="font-label-surgical text-[10px] tracking-widest text-white uppercase">${node.label}</span>
                    </div>
                `;
                // 3d-force-graph has built-in nodeLabel, but user wants custom
            }
            
            // Edge highlighting
            obsidianGraph.linkDirectionalParticles(node ? 2 : 0);
            obsidianGraph.linkDirectionalParticleWidth(1);
        })
        .onNodeClick(node => {
            showNodeInfo({
                label: node.label,
                type: node.type,
                icon: getNodeIcon(node.type),
                description: node.description,
                severity: node.severity,
                risk: node.risk,
                cwe: node.cwe,
                cvss_score: node.cvss_score,
                version: node.version,
                recommendation: node.recommendation
            });
            
            // Aim at node
            const distance = 100;
            const distRatio = 1 + distance/Math.hypot(node.x, node.y, node.z);
            obsidianGraph.cameraPosition(
                { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
                node,
                1000
            );
        })
        .onBackgroundClick(() => {
            hideNodeInfo();
        });

    // Physics setup
    obsidianGraph.d3Force('charge').strength(-150);
    obsidianGraph.d3Force('link').distance(80);
    obsidianGraph.d3Force('center').strength(0.1);

    // Initial camera
    obsidianGraph.cameraPosition({ x: 400, y: 200, z: 600 });

    // Window resize
    window.addEventListener('resize', () => {
        if (obsidianGraph) {
            obsidianGraph.width(container.clientWidth);
            obsidianGraph.height(container.clientHeight);
        }
    });

    if (typeof pushActivity === 'function') pushActivity('Neural Attack Graph: Obsidian Engine Active', 'info');
    } catch (err) {
        console.error('Obsidian Graph Initialization Error:', err);
        container.innerHTML = `<div class="h-full flex items-center justify-center text-primary font-data-mono">ERR: NEURAL_INIT_FAIL [${err.message}]</div>`;
    }
}

function toggleGraphPhysics() {
    isPhysicsEnabled = !isPhysicsEnabled;
    const btn = document.getElementById('togglePhysicsBtn');
    if (isPhysicsEnabled) {
        obsidianGraph.resumeAnimation();
        btn.classList.add('text-primary');
        btn.querySelector('span').innerText = 'motion_sensor_active';
    } else {
        obsidianGraph.pauseAnimation();
        btn.classList.remove('text-primary');
        btn.querySelector('span').innerText = 'motion_sensor_idle';
    }
}

function resetGraphView() {
    if (obsidianGraph) {
        obsidianGraph.cameraPosition({ x: 400, y: 200, z: 600 }, { x: 0, y: 0, z: 0 }, 1000);
    }
}

// Cleanup legacy functions if they exist in this chunk range
function startGraphAnimations() { return; }

function renderAttackGraph(data) {
    if (!obsidianGraph) {
        initAttackGraph();
        return;
    }
    const gData = {
        nodes: data.nodes.map(n => ({ ...n })),
        links: data.edges.map(e => ({ source: e.from, target: e.to }))
    };
    obsidianGraph.graphData(gData);
    
    const badge = document.getElementById('graphStatusBadge');
    if (badge) badge.innerText = 'LIVE_NEURAL_MAP // SYNCED';
    if (typeof pushActivity === 'function') pushActivity('Obsidian Attack Graph synchronized with live data', 'info');
}

ipcRenderer.on('graph-data', (event, data) => {
    renderAttackGraph(data);
});

// Periodic graph refresh
setInterval(() => {
    if (document.getElementById('dashboard').classList.contains('hidden')) return;
    ipcRenderer.send('get-attack-graph');
}, 30000);


// Strip ANSI escape codes from console output
function stripAnsi(str) {
    return str ? str.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '').replace(/\033\[[0-9;]*[a-zA-Z]/g, '') : '';
}

function initializeNeuralHandshake() {
    const settings = JSON.parse(localStorage.getItem('hh_global_settings') || '{}');
    const provider = (settings.ai_provider || '').toLowerCase();
    const isLocal = provider.includes('local') || provider === 'ollama' || provider === '';
    const key = isLocal ? 'local' : (settings.ai_key || '');

    setAIStatus('connecting', 'Connecting to NEURAL CORE...');

    // Send ONLY the AI handshake — no sync-settings overlap for AI
    ipcRenderer.send('ai-handshake', key);

    // Update buttons
    const btns = document.querySelectorAll('[onclick="initializeNeuralHandshake()"], [onclick="syncAICore()"]');
    btns.forEach(btn => {
        btn.classList.add('animate-pulse');
        btn.textContent = 'CONNECTING...';
        btn.disabled = true;
    });
}

function syncAICore() {
    // Collect from UI
    const provider = document.getElementById('ai_provider').value;
    const key = document.getElementById('ai_key').value;
    const isLocal = provider === 'LOCAL' || provider === 'LOCAL_SLM';

    // Save to local storage
    const settings = JSON.parse(localStorage.getItem('hh_global_settings') || '{}');
    settings.ai_provider = provider;
    settings.ai_key = key;
    localStorage.setItem('hh_global_settings', JSON.stringify(settings));

    setAIStatus('connecting', 'Activating Hellhound...');

    // Send ONE command: activate hellhound for local, setg ai <key> for cloud
    const aiKey = isLocal ? 'local' : key;
    ipcRenderer.send('ai-handshake', aiKey);

    // Update buttons
    const btns = document.querySelectorAll('[onclick="initializeNeuralHandshake()"], [onclick="syncAICore()"]');
    btns.forEach(btn => {
        btn.classList.add('animate-pulse');
        btn.textContent = 'ACTIVATING...';
        btn.disabled = true;
    });
}

// Show AI connection status in both the settings panel and the chatbox
function setAIStatus(state, message) {
    // Update settings panel status
    const panel = document.getElementById('aiStatusPanel');
    if (panel) {
        panel.classList.remove('hidden');
        const dot = panel.querySelector('.status-dot');
        const label = panel.querySelector('.status-label');
        if (dot) dot.className = `status-dot w-2 h-2 rounded-full ${state === 'ok' ? 'bg-primary' : state === 'connecting' ? 'bg-yellow-500 animate-pulse' : 'bg-red-500'}`;
        if (label) label.innerText = message;
    }

    // Update chatbox Neural Status dot (dot-only, no text)
    const neuralDot = document.querySelector('#neuralStatus div');
    if (neuralDot) {
        if (state === 'ok') {
            neuralDot.className = 'w-3 h-3 rounded-full bg-green-400 shadow-[0_0_14px_rgba(74,222,128,0.9)]';
        } else if (state === 'connecting') {
            neuralDot.className = 'w-3 h-3 rounded-full bg-yellow-400 shadow-[0_0_14px_rgba(250,204,21,0.8)] animate-pulse';
        } else {
            neuralDot.className = 'w-3 h-3 rounded-full bg-red-500 shadow-[0_0_12px_rgba(255,0,0,0.8)]';
        }
    }

    // Re-enable send button
    const sendBtn = document.querySelector('[onclick="sendAI()"]');
    if (sendBtn) {
        sendBtn.disabled = false;
        sendBtn.classList.remove('opacity-30', 'pointer-events-none');
    }
}

// ai-response handler updates status too
ipcRenderer.on('ai-response', (event, data) => {
    aiThinking = false;
    
    // Remove all thinking indicators
    document.querySelectorAll('[id^="ai-thinking-"]').forEach(el => el.remove());
    
    const rawText = (data && data.trim()) ? data.trim() : 'No response. Check AI provider in Settings.';
    const cleanText = stripAnsi(rawText);

    // Detect AI status from ANSI-stripped console output
    const isOnline = cleanText.includes('ONLINE') || 
                     cleanText.includes('CONNECTED') || 
                     cleanText.includes('Hellhound is activated') ||
                     cleanText.includes('Intelligence Connected');

    if (isOnline) {
        setAIStatus('ok', 'Hellhound activated — AI engine online');
        const btns = document.querySelectorAll('[onclick="initializeNeuralHandshake()"], [onclick="syncAICore()"]');
        btns.forEach(btn => {
            btn.classList.remove('animate-pulse');
            btn.textContent = 'ACTIVATE HELLHOUND';
            btn.disabled = false;
        });
    } else {
        // Only set error if it's explicitly offline or failed
        if (cleanText.includes('not configured') || cleanText.includes('setg ai') || cleanText.includes('OFFLINE') || cleanText.includes('Failed')) {
            setAIStatus('error', cleanText.split('\n')[0]);
            const btns = document.querySelectorAll('[onclick="initializeNeuralHandshake()"], [onclick="syncAICore()"]');
            btns.forEach(btn => {
                btn.classList.remove('animate-pulse');
                btn.textContent = 'ACTIVATE HELLHOUND';
                btn.disabled = false;
            });
        }
    }

    // Only suppress handshake/options dumps — not real AI responses
    // The 'options' command output always contains these exact structural markers together
    const isStatusDump = cleanText.includes('GLOBAL CONFIGURATION') || 
                         cleanText.includes('Global options:') ||
                         cleanText.includes('Current Setting') ||
                         cleanText.includes('AI INTELLIGENCE') ||
                         cleanText.includes('ask') && cleanText.includes('analyze') && cleanText.includes('howl') ||
                         (cleanText.includes('TARGET') && cleanText.includes('AI engine:'));

    if (isOnline && isStatusDump) {
        appendHellhoundMessage('hellhound', 'HELLHOUND READY TO HUNT');
    } else if (!isStatusDump && cleanText.trim().length > 0) {
        appendHellhoundMessage('hellhound', cleanText);
    }
    const btn = document.querySelector('[onclick="sendAI()"]');
    if (btn) {
        btn.disabled = false;
        btn.classList.remove('opacity-30', 'pointer-events-none');
    }
});

ipcRenderer.on('howl-data', (event, data) => {
    const output = document.getElementById('howlOutput');
    if (!output) return;

    // Filter noise
    let clean = data
        .replace(/HELLHOUND is thINKING/gi, '')
        .replace(/HELLHOUND IS THINKING/gi, '')
        .replace(/⡀|⡄|⡆|⡇|⣇|⣧|⣷|⣿/g, '')
        .trim();

    output.innerHTML = `<pre class="font-data-mono text-[13px] text-white/90 whitespace-pre-wrap leading-relaxed select-text">${clean}</pre>`;
    output.scrollTop = 0;
    pushActivity('Tactical HOWL intelligence received', 'intel');
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

    const clean = stripAnsi(output || '');
    const isOnline = clean.includes('ONLINE') || clean.includes('CONNECTED');
    const isNotConfigured = clean.includes('NOT CONNECTED') || clean.includes('OFFLINE');

    dot.className = `w-2 h-2 rounded-full mt-1 flex-shrink-0 ${isOnline ? 'bg-green-500' : isNotConfigured ? 'bg-red-500' : 'bg-yellow-500'}`;
    
    // Update the main neural status too
    if (isOnline) setAIStatus('ok', 'Hellhound activated — AI engine online');
    else if (isNotConfigured) setAIStatus('error', 'AI not connected');

    // Show the AI line from options output
    const lines = clean.split('\n');
    const aiLine = lines.find(l => l.includes('AI') && l.includes('INTELLIGENCE')) || 
                   lines.find(l => l.includes('ai ') && l.includes('AI engine'));
    msg.textContent = aiLine ? aiLine.trim() : clean.substring(0, 200);
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
    lastLootMap = lootMap;
    renderLootList(lootMap);
    renderLootCenter(lootMap);
    updateDashboard(lootMap);
    // Refresh graph and intel whenever loot changes
    ipcRenderer.send('get-attack-graph');
    if (!document.getElementById('intel').classList.contains('hidden')) refreshIntel();

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

function toggleDashboardView(view, el) {
    // This function is now deprecated as Attack Graph has moved to its own section.
    // Preserving a minimal version to avoid reference errors, but the UI tabs have been removed.
    console.log("Dashboard view toggled to:", view);
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

function renderLootCenter(lootMap) {
    const grid = document.getElementById('lootGrid');
    const empty = document.getElementById('lootEmpty');
    if (!grid) return;

    const keys = Object.keys(lootMap);
    if (keys.length === 0) {
        grid.classList.add('hidden');
        empty.classList.remove('hidden');
        return;
    }

    grid.classList.remove('hidden');
    grid.classList.add('grid');
    empty.classList.add('hidden');
    grid.innerHTML = '';

    keys.forEach(key => {
        const lines = lootMap[key];
        const card = document.createElement('div');
        card.className = 'loot-card p-6 flex flex-col';
        
        const title = document.createElement('h3');
        title.className = 'font-label-surgical text-[10px] text-primary font-bold uppercase tracking-[0.3em] mb-4 border-b border-primary/20 pb-3';
        title.textContent = key.split('/').pop().toUpperCase();
        
        const content = document.createElement('div');
        content.className = 'flex-1 overflow-y-auto custom-scrollbar max-h-[300px] pr-2';
        
        lines.forEach(line => {
            const item = document.createElement('div');
            item.className = 'loot-item-text';
            item.textContent = line;
            content.appendChild(item);
        });

        card.appendChild(title);
        card.appendChild(content);
        grid.appendChild(card);
    });
}

function updateDashboard(lootMap) {
    const totalFindings = Object.values(lootMap).reduce((s, l) => s + l.length, 0);
    const targetCount = Object.keys(lootMap).length;

    const tStats = document.getElementById('tacticalStats');
    if (tStats) {
        tStats.innerHTML = `
            <div class="stat-card p-4 border border-white/5 bg-white/2 bg-glow-blue">
                <div class="text-[10px] text-white/40 uppercase tracking-tighter">Total Intel</div>
                <div class="text-2xl font-black text-white">${totalFindings}</div>
            </div>
            <div class="stat-card p-4 border border-white/5 bg-white/2 bg-glow-red">
                <div class="text-[10px] text-white/40 uppercase tracking-tighter">Active Nodes</div>
                <div class="text-2xl font-black text-white">${targetCount}</div>
            </div>
        `;
    }
}

// Engine status dot updater
function setEngineDot(engine, state) {
    const id = engine === 'ops' ? 'opsEngineDot' : 'intelEngineDot';
    const dot = document.getElementById(id);
    if (!dot) return;
    
    // SURGICAL: Use the CSS classes defined for green/yellow/red states
    dot.classList.remove('connected', 'busy', 'error');
    if (state === 'online') dot.classList.add('connected');
    else if (state === 'busy') dot.classList.add('busy');
    else dot.classList.add('error');
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