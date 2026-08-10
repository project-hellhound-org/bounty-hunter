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
        const flexPanels = ['arsenal', 'ops', 'intel', 'loot', 'repro', 'graph', 'repeater', 'decaffeinator', 'killbook', 'strikecast', 'payloadloom', 'tokenstalker', 'greyzone', 'killchainloom', 'ghostproof'];
        target.classList.add(flexPanels.includes(id) ? 'flex' : 'block');
    }
    
    // Manage HTTP Repeater active state
    if (id === 'repeater') {
        initRepeater();
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

    // Callbacks for manual efficiency modules
    if (id === 'killbook') {
        renderKillbookTimeline();
    }
    if (id === 'payloadloom') {
        syncPayloadLoomFindings();
    }
    if (id === 'greyzone') {
        syncGreyZoneTable();
    }
    if (id === 'ghostproof') {
        renderGhostProofSuite();
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
const SPIDER_DEPENDENT_MODULES = ['Hydra', 'CORSbuster', 'SurfaceAuditor', 'SourceAuditor'];

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

if (reproPanel) {
    reproPanel.addEventListener('click', () => {
        const input = document.getElementById('reproInput');
        if (input) input.focus();
    });
}

let isMoving = false, isResizing = false, resizeDir = '';
let startX, startY, startW, startH, startL, startT;

reproHeader.onmousedown = (e) => {
    isMoving = true;
    startX = e.clientX; startY = e.clientY;
    startL = reproPanel.offsetLeft; startT = reproPanel.offsetTop;
    
    // Explicitly lock coordinates BEFORE clearing anchors to prevent layout jumping
    reproPanel.style.left = startL + 'px';
    reproPanel.style.top = startT + 'px';
    reproPanel.style.bottom = 'auto';
    reproPanel.style.right = 'auto';
    
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
        isResizing = true; resizeDir = handle.dataset.dir;
        startX = e.clientX; startY = e.clientY;
        startW = reproPanel.offsetWidth; startH = reproPanel.offsetHeight;
        startL = reproPanel.offsetLeft;  startT = reproPanel.offsetTop;
        
        // Explicitly lock coordinates BEFORE clearing anchors
        reproPanel.style.left = startL + 'px';
        reproPanel.style.top = startT + 'px';
        reproPanel.style.bottom = 'auto';
        reproPanel.style.right = 'auto';
        
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

function toggleRepro() {
    reproPanel.classList.toggle('hidden');
    if(!reproPanel.classList.contains('hidden')) {
        document.getElementById('reproCommandLine').classList.remove('hidden');
        updatePrompt();
        document.getElementById('reproInput').focus();
    }
}

const os = require('os');
const HOME_DIR = os.homedir();
let currentDir = PROJECT_ROOT;

const cmdHistory = [];
let historyIndex = -1;

function focusAndSetCursorAtEnd(input) {
    input.focus();
    const len = input.value.length;
    input.setSelectionRange(len, len);
}

function handleTabComplete(input) {
    const value = input.value;
    const lastSpace = value.lastIndexOf(' ');
    const lastWord = lastSpace === -1 ? value : value.substring(lastSpace + 1);
    
    let targetDir = currentDir;
    let filePrefix = lastWord;
    
    if (lastWord.includes('/')) {
        const lastSlash = lastWord.lastIndexOf('/');
        const pathPart = lastWord.substring(0, lastSlash + 1);
        filePrefix = lastWord.substring(lastSlash + 1);
        
        if (pathPart.startsWith('~')) {
            targetDir = path.resolve(HOME_DIR, pathPart.substring(2));
        } else {
            targetDir = path.resolve(targetDir, pathPart);
        }
    }
    
    try {
        if (!fs.existsSync(targetDir)) return;
        const files = fs.readdirSync(targetDir);
        const matches = files.filter(f => f.startsWith(filePrefix));
        
        if (matches.length === 1) {
            const completed = matches[0];
            const fullPath = path.join(targetDir, completed);
            const isDir = fs.statSync(fullPath).isDirectory();
            const replacement = completed + (isDir ? '/' : ' ');
            
            const before = lastSpace === -1 ? '' : value.substring(0, lastSpace + 1);
            const pathPart = lastWord.includes('/') ? lastWord.substring(0, lastWord.lastIndexOf('/') + 1) : '';
            
            input.value = before + pathPart + replacement;
            focusAndSetCursorAtEnd(input);
        } else if (matches.length > 1) {
            // Find the longest common prefix
            let commonPrefix = filePrefix;
            let idx = filePrefix.length;
            let ok = true;
            while (ok) {
                if (matches[0].length <= idx) break;
                const char = matches[0][idx];
                for (let i = 1; i < matches.length; i++) {
                    if (matches[i].length <= idx || matches[i][idx] !== char) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    commonPrefix += char;
                    idx++;
                }
            }
            
            if (commonPrefix.length > filePrefix.length) {
                const before = lastSpace === -1 ? '' : value.substring(0, lastSpace + 1);
                const pathPart = lastWord.includes('/') ? lastWord.substring(0, lastWord.lastIndexOf('/') + 1) : '';
                input.value = before + pathPart + commonPrefix;
                focusAndSetCursorAtEnd(input);
            } else {
                const pre = document.querySelector('pre.panel-repro-pre');
                if (pre) {
                    const prompt = document.getElementById('reproPrompt').textContent;
                    pre.textContent += prompt + value + '\n' + matches.join('   ') + '\n';
                    const output = document.getElementById('reproOutput');
                    if (output) output.scrollTop = output.scrollHeight;
                }
            }
        }
    } catch (_) {}
}

function handleArrowUp(input) {
    if (cmdHistory.length === 0) return;
    if (historyIndex < cmdHistory.length - 1) {
        historyIndex++;
        input.value = cmdHistory[cmdHistory.length - 1 - historyIndex];
        focusAndSetCursorAtEnd(input);
    }
}

function handleArrowDown(input) {
    if (historyIndex > 0) {
        historyIndex--;
        input.value = cmdHistory[cmdHistory.length - 1 - historyIndex];
        focusAndSetCursorAtEnd(input);
    } else if (historyIndex === 0) {
        historyIndex = -1;
        input.value = '';
        focusAndSetCursorAtEnd(input);
    }
}

function updatePrompt() {
    const promptEl = document.getElementById('reproPrompt');
    if (!promptEl) return;
    let displayDir = currentDir;
    if (currentDir.startsWith(PROJECT_ROOT)) {
        const rel = path.relative(PROJECT_ROOT, currentDir);
        displayDir = rel ? `./${rel}` : '.';
    } else if (currentDir.startsWith(HOME_DIR)) {
        const rel = path.relative(HOME_DIR, currentDir);
        displayDir = rel ? `~/${rel}` : '~';
    }
    promptEl.textContent = `hellhound@pentest:${displayDir}$ `;
}

function printOutput(text) {
    const output = document.getElementById('reproOutput');
    if (!output) return;
    let pre = output.querySelector('pre.panel-repro-pre');
    if (!pre) {
        pre = document.createElement('pre');
        pre.className = 'panel-repro-pre font-data-mono text-[13px] text-white/90 whitespace-pre-wrap break-all w-full select-text';
        output.insertBefore(pre, document.getElementById('reproCommandLine'));
    }

    const escapeHtml = (str) => {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    };

    const promptRegex = /(hellhound@pentest:[^$#\n]*[$#])(.*)/;
    const lines = text.split('\n');
    let htmlContent = '';
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const match = line.match(promptRegex);
        if (match) {
            htmlContent += `<span class="text-green-400 font-bold">${escapeHtml(match[1])}</span>${escapeHtml(match[2])}`;
        } else {
            htmlContent += escapeHtml(line);
        }
        if (i < lines.length - 1) {
            htmlContent += '\n';
        }
    }

    const temp = document.createElement('span');
    temp.innerHTML = htmlContent;
    while (temp.firstChild) {
        pre.appendChild(temp.firstChild);
    }
    output.scrollTop = output.scrollHeight;
}

ipcRenderer.on('repro-out', (event, text) => {
    printOutput(text);
});

ipcRenderer.on('repro-done', (event) => {
    document.getElementById('reproCommandLine').classList.remove('hidden');
    const input = document.getElementById('reproInput');
    if (input) {
        input.value = '';
        input.style.height = '24px';
        input.focus();
    }
});

function handleRepro(event) {
    const input = document.getElementById('reproInput');
    if (!input) return;
    
    if (event.key === 'c' && event.ctrlKey) {
        event.preventDefault();
        const pre = document.querySelector('pre.panel-repro-pre');
        const promptText = document.getElementById('reproPrompt').textContent;
        if (pre) {
            printOutput(promptText + input.value + '^C\n');
        }
        input.value = '';
        input.style.height = '24px';
        const output = document.getElementById('reproOutput');
        if (output) output.scrollTop = output.scrollHeight;
        return;
    }

    if (event.key === 'Tab') {
        event.preventDefault();
        handleTabComplete(input);
        return;
    }
    
    if (event.key === 'ArrowUp') {
        event.preventDefault();
        handleArrowUp(input);
        return;
    }
    
    if (event.key === 'ArrowDown') {
        event.preventDefault();
        handleArrowDown(input);
        return;
    }
    
    if (event.key === 'Enter') {
        if (event.shiftKey) {
            // Let default newline insertion happen
            return;
        }
        event.preventDefault();
        const fullCmd = input.value;
        const cmd = fullCmd.trim();
        const promptText = document.getElementById('reproPrompt').textContent;
        
        printOutput(promptText + fullCmd + '\n');
        input.value = '';
        input.style.height = '24px';
        
        if (!cmd) return;
        
        cmdHistory.push(fullCmd);
        historyIndex = -1;
        
        const parts = cmd.split(/\s+/);
        const exe = parts[0];
        
        if (exe === 'clear') {
            const pre = document.querySelector('pre.panel-repro-pre');
            if (pre) pre.textContent = '';
            return;
        }
        
        if (exe === 'help') {
            printOutput(`Available commands:
  cd [dir]    Change directory
  ls [dir]    List files and directories
  cat [file]  Print file contents (supports JSON beauty formatting)
  pwd         Print working directory
  clear       Clear the screen
  curl [args] Execute a curl request
  help        Show this help menu\n`);
            return;
        }
        
        if (exe === 'pwd') {
            printOutput(currentDir + '\n');
            return;
        }
        
        if (exe === 'cd') {
            const target = parts.slice(1).join(' ').trim();
            let targetPath = HOME_DIR;
            if (target === '~') {
                targetPath = HOME_DIR;
            } else if (target) {
                if (target.startsWith('~')) {
                    targetPath = path.resolve(HOME_DIR, target.substring(1).replace(/^[/\\]+/, ''));
                } else {
                    targetPath = path.resolve(currentDir, target);
                }
            } else {
                targetPath = PROJECT_ROOT;
            }
            
            try {
                if (!fs.existsSync(targetPath)) {
                    printOutput(`cd: ${target}: No such file or directory\n`);
                } else if (!fs.statSync(targetPath).isDirectory()) {
                    printOutput(`cd: ${target}: Not a directory\n`);
                } else {
                    currentDir = targetPath;
                    updatePrompt();
                }
            } catch (e) {
                printOutput(`cd: ${target}: Error: ${e.message}\n`);
            }
            return;
        }
        
        if (exe === 'ls') {
            const target = parts.slice(1).join(' ').trim();
            let targetPath = currentDir;
            if (target) {
                if (target.startsWith('~')) {
                    targetPath = path.resolve(HOME_DIR, target.substring(1).replace(/^[/\\]+/, ''));
                } else {
                    targetPath = path.resolve(currentDir, target);
                }
            }
            
            try {
                if (!fs.existsSync(targetPath)) {
                    printOutput(`ls: cannot access '${target}': No such file or directory\n`);
                    return;
                }
                if (!fs.statSync(targetPath).isDirectory()) {
                    printOutput(`${target}\n`);
                    return;
                }
                const entries = fs.readdirSync(targetPath);
                if (entries.length === 0) return;
                
                const formatted = entries.map(entry => {
                    const fullPath = path.join(targetPath, entry);
                    try {
                        if (fs.statSync(fullPath).isDirectory()) {
                            return entry + '/';
                        }
                    } catch (_) {}
                    return entry;
                });
                
                printOutput(formatted.join('   ') + '\n');
            } catch (e) {
                printOutput(`ls: error: ${e.message}\n`);
            }
            return;
        }
        
        if (exe === 'cat') {
            const target = parts.slice(1).join(' ').trim();
            if (!target) {
                printOutput(`cat: missing file operand\n`);
                return;
            }
            let targetPath;
            if (target.startsWith('~')) {
                targetPath = path.resolve(HOME_DIR, target.substring(1).replace(/^[/\\]+/, ''));
            } else {
                targetPath = path.resolve(currentDir, target);
            }
            
            try {
                if (!fs.existsSync(targetPath)) {
                    printOutput(`cat: ${target}: No such file or directory\n`);
                    return;
                }
                if (fs.statSync(targetPath).isDirectory()) {
                    printOutput(`cat: ${target}: Is a directory\n`);
                    return;
                }
                const content = fs.readFileSync(targetPath, 'utf8');
                if (targetPath.endsWith('.json')) {
                    try {
                        const parsed = JSON.parse(content);
                        printOutput(JSON.stringify(parsed, null, 2) + '\n');
                    } catch (_) {
                        printOutput(content + '\n');
                    }
                } else {
                    printOutput(content + '\n');
                }
            } catch (e) {
                printOutput(`cat: ${target}: Error: ${e.message}\n`);
            }
            return;
        }
        
        if (exe === 'curl') {
            document.getElementById('reproCommandLine').classList.add('hidden');
            ipcRenderer.send('exec-repro', { command: cmd, cwd: currentDir });
            return;
        }
        
        printOutput(`bash: ${exe}: command execution restricted to safe navigation (cd, ls, cat, pwd, clear, help) or curl.\n`);
    }
}

// Repro shell — plain bash for curl/pentest commands (kept for PoC replay in Repro Center)
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
    // If Threat Map is active, feed real events to the map animation
    if (typeof handleRealTelemetryEvent === 'function') {
        handleRealTelemetryEvent(line, severity);
    }

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
    
    const btn = document.getElementById('reproFireBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="material-symbols-outlined text-[16px] animate-spin">refresh</span> REPLAYING...`;
    }

    const terminal = document.getElementById('reproTerminal');
    if (terminal) {
        terminal.innerHTML += `\n<div class="text-green-500 font-bold mt-4 mb-2 uppercase tracking-[0.2em] animate-pulse">› INITIATING REPLAY...</div>`;
    }
    
    // Spawn an isolated process to run the command directly
    const proc = spawn('/bin/bash', ['-c', activePoCCmd], { env: process.env, cwd: PROJECT_ROOT });
    
    proc.stdout.on('data', (data) => {
        appendRepro(data.toString());
    });
    
    proc.stderr.on('data', (data) => {
        appendRepro(data.toString(), true);
    });
    
    proc.on('close', (code) => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<span class="material-symbols-outlined text-[18px]">replay</span> INITIATE_REPLAY`;
        }
        appendRepro(`\n[Process completed with exit code ${code}]\n`);
        pushActivity(`PoC replay completed (exit ${code})`, code === 0 ? 'ok' : 'warn');
    });
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

    const isUser = role !== 'hellhound';
    
    const bubble = document.createElement('div');
    bubble.className = `chat-bubble animate-fade-in group mb-6 flex flex-col w-full ${isUser ? 'items-end' : 'items-start'}`;
    
    const roleLabel = role === 'hellhound' ? 'HELLHOUND' : 'YOU';
    const labelColor = role === 'hellhound' ? 'text-primary/60' : 'text-blue-400/60';
    const timeStr = new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});

    bubble.innerHTML = `
        <div class="flex items-center gap-3 mb-1 ${isUser ? 'flex-row-reverse' : ''}">
            <div class="font-label-surgical text-[9px] ${labelColor} uppercase tracking-[0.2em] font-bold">${roleLabel}</div>
            <div class="text-[8px] text-white/10 font-data-mono opacity-0 group-hover:opacity-100 transition-opacity uppercase">${timeStr}</div>
        </div>
        <div class="relative group/content max-w-[85%]">
            <div class="chat-text-container p-4 overflow-hidden ${isUser ? 'bg-blue-500/10 border border-blue-500/20 rounded-t-2xl rounded-bl-2xl rounded-br-sm' : 'bg-white/5 border border-white/10 rounded-t-2xl rounded-br-2xl rounded-bl-sm'} shadow-lg backdrop-blur-sm">
                <pre class="font-data-mono text-[13px] text-white/90 whitespace-pre-wrap leading-relaxed select-text font-sans">${cleanText}</pre>
            </div>
            <button onclick="copyMessage(this)" class="absolute ${isUser ? '-left-10' : '-right-10'} top-1/2 -translate-y-1/2 opacity-0 group-hover/content:opacity-100 text-white/20 hover:text-white/60 transition-all p-1.5 bg-black/40 rounded-full border border-white/10 backdrop-blur-sm z-10" title="Copy Message">
                <span class="material-symbols-outlined text-[14px]">content_copy</span>
            </button>
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
    
    const reproInput = document.getElementById('reproInput');
    if (reproInput) {
        reproInput.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = this.scrollHeight + 'px';
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

    // Action Buttons
    let actionsHtml = `<div class="mt-4 pt-4 border-t border-white/10 flex flex-col gap-2">`;
    let hasActions = false;

    if (data.type === 'url' || data.type === 'endpoint_rest' || data.type === 'endpoint_admin' || data.type === 'endpoint_sensitive' || data.type === 'vulnerability' || data.type === 'vuln_idor' || data.type === 'vuln_sqli' || data.type === 'vuln_bac') {
        let nodeUrl = data.label;
        if (!nodeUrl.startsWith('http://') && !nodeUrl.startsWith('https://')) {
            nodeUrl = 'http://' + nodeUrl;
        }
        actionsHtml += `
            <button onclick="graphLoadToRepeater('${nodeUrl}')" class="w-full py-2 bg-primary text-background font-label-surgical text-[9px] font-bold uppercase tracking-widest hover:brightness-110 transition-all rounded">
                ⚡ Load to Repeater
            </button>
        `;
        hasActions = true;
    }

    if ((data.label && data.label.toLowerCase().includes('.js')) || data.type === 'technology') {
        actionsHtml += `
            <button onclick="graphSendToDeCaff('${data.label}')" class="w-full py-2 border border-[#00ffc4]/40 bg-[#00ffc4]/10 text-[#00ffc4] font-label-surgical text-[9px] font-bold uppercase tracking-widest hover:bg-[#00ffc4]/20 transition-all rounded">
                ☕ Send to De-Caffeinator
            </button>
        `;
        hasActions = true;
    }

    actionsHtml += `</div>`;
    if (hasActions) {
        metaHtml += actionsHtml;
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

let currentGraphMode = 'sample';

function setGraphMode(mode) {
    if (mode === 'live') {
        const checkTarget = activeTarget || '';
        const isNotEngaged = !checkTarget || checkTarget === 'NO_TARGET_ENGAGED' || checkTarget === 'NO TARGET' || checkTarget === 'NO TARGET ENGAGED';
        if (isNotEngaged) {
            alert('Live graph requires an active target to be engaged. Engaging a target generates telemetry.');
            return;
        }
    }
    currentGraphMode = mode;
    const sampleBtn = document.getElementById('graphModeSample');
    const liveBtn = document.getElementById('graphModeLive');
    if (sampleBtn && liveBtn) {
        if (mode === 'sample') {
            sampleBtn.className = 'px-4 py-2 font-label-surgical text-[10px] tracking-widest uppercase bg-primary text-background font-bold transition-all';
            liveBtn.className = 'px-4 py-2 font-label-surgical text-[10px] tracking-widest uppercase text-white/40 hover:text-white transition-all';
        } else {
            liveBtn.className = 'px-4 py-2 font-label-surgical text-[10px] tracking-widest uppercase bg-primary text-background font-bold transition-all';
            sampleBtn.className = 'px-4 py-2 font-label-surgical text-[10px] tracking-widest uppercase text-white/40 hover:text-white transition-all';
        }
    }
    initAttackGraph();
}

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

    let gData;
    if (currentGraphMode === 'live') {
        gData = { nodes: [], links: [] };
        ipcRenderer.send('get-attack-graph');
    } else {
        gData = {
            nodes: SAMPLE_ATTACK_GRAPH.nodes.map(n => ({ ...n })),
            links: SAMPLE_ATTACK_GRAPH.edges.map(e => ({ source: e.from, target: e.to }))
        };
        const badge = document.getElementById('graphStatusBadge');
        if (badge) badge.innerText = 'SAMPLE_MAP // STANDBY';
    }

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
            try {
                if (prevNode && prevNode.__threeObj) {
                    if (prevNode.__threeObj.scale) prevNode.__threeObj.scale.set(1, 1, 1);
                    if (prevNode.__threeObj.material) {
                        prevNode.__threeObj.material.emissiveIntensity = prevNode.severity === 'critical' ? 2 : 0.5;
                    }
                }
                if (node && node.__threeObj) {
                    if (node.__threeObj.scale) node.__threeObj.scale.set(1.5, 1.5, 1.5);
                    if (node.__threeObj.material) {
                        node.__threeObj.material.emissiveIntensity = 5;
                    }
                    
                    // Show tooltip logic (minimal)
                    const tooltip = document.createElement('div');
                    tooltip.className = 'obsidian-tooltip';
                    tooltip.innerHTML = `
                        <div class="flex items-center gap-2">
                            <span class="material-symbols-outlined text-[12px]" style="color:${getNodeColor(node.type, node)}">${getNodeIcon(node.type)}</span>
                            <span class="font-label-surgical text-[10px] tracking-widest text-white uppercase">${node.label}</span>
                        </div>
                    `;
                }
            } catch (err) {
                console.error("Error in onNodeHover:", err);
            }
            
            // Edge highlighting
            try {
                if (obsidianGraph) {
                    obsidianGraph.linkDirectionalParticles(node ? 2 : 0);
                    obsidianGraph.linkDirectionalParticleWidth(1);
                }
            } catch (_) {}
        })
        .onNodeClick(node => {
            try {
                if (!node) return;
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
                
                // Aim at node safely without camera positioning crashes
                const x = node.x || 0;
                const y = node.y || 0;
                const z = node.z || 0;
                const hypot = Math.hypot(x, y, z);
                if (hypot > 0 && obsidianGraph) {
                    const distance = 100;
                    const distRatio = 1 + distance / hypot;
                    obsidianGraph.cameraPosition(
                        { x: x * distRatio, y: y * distRatio, z: z * distRatio },
                        node,
                        1000
                    );
                }
            } catch (err) {
                console.error("Error in onNodeClick:", err);
            }
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
    if (currentGraphMode !== 'live') return;
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
    if (currentGraphMode === 'live') {
        ipcRenderer.send('get-attack-graph');
    }
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

    // Send ONE payload: activate hellhound for local, setg ai <key> & setg ai_provider for cloud
    const aiKey = isLocal ? 'local' : key;
    ipcRenderer.send('ai-handshake', { provider: provider, key: aiKey });

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

function fireConsoleRepro() {
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
    const btn = document.getElementById('reproAllBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="material-symbols-outlined text-[12px] animate-spin">refresh</span> REPLAYING...`;
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
    const btn = document.getElementById('reproAllBtn');
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = `Replay_All`;
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

    let proxyUrlStr = proxy;
    if (!proxyUrlStr.includes('://')) {
        proxyUrlStr = 'http://' + proxyUrlStr;
    }
    
    let url;
    try {
        url = new URL(proxyUrlStr);
    } catch (e) {
        dot.className = 'w-2 h-2 rounded-full bg-red-500';
        label.textContent = 'BAD URL';
        return;
    }

    const proxyHost = url.hostname;
    const proxyPort = parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80);

    // Verify conflicts: If proxy host/port matches the target application host/port
    let targetHost = '';
    let targetPort = null;
    if (activeTarget) {
        let targetUrlStr = activeTarget;
        if (!targetUrlStr.includes('://')) {
            targetUrlStr = 'http://' + targetUrlStr;
        }
        try {
            const tUrl = new URL(targetUrlStr);
            targetHost = tUrl.hostname;
            targetPort = parseInt(tUrl.port) || (tUrl.protocol === 'https:' ? 443 : 80);
        } catch (_) {}
    }

    if (targetHost && proxyHost === targetHost && proxyPort === targetPort) {
        dot.className = 'w-2 h-2 rounded-full bg-yellow-500 shadow-[0_0_6px_#eab308]';
        label.textContent = 'CONFLICT';
        return;
    }

    const net = require('net');
    const client = new net.Socket();
    client.setTimeout(2500);

    client.on('connect', () => {
        dot.className = 'w-2 h-2 rounded-full bg-green-500 shadow-[0_0_6px_#22c55e]';
        label.textContent = 'PROXY UP';
        client.destroy();
    });

    client.on('error', () => {
        dot.className = 'w-2 h-2 rounded-full bg-red-500';
        label.textContent = 'DOWN';
        client.destroy();
    });

    client.on('timeout', () => {
        dot.className = 'w-2 h-2 rounded-full bg-red-500';
        label.textContent = 'TIMEOUT';
        client.destroy();
    });

    try {
        client.connect(proxyPort, proxyHost);
    } catch (_) {
        dot.className = 'w-2 h-2 rounded-full bg-red-500';
        label.textContent = 'DOWN';
    }
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

function openLootDir() {
    ipcRenderer.send('open-loot-dir');
}

ipcRenderer.on('loot-data', (event, lootMap) => {
    lastLootMap = lootMap;
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
            item.className = 'loot-item-text py-2 border-b border-white/5 font-data-mono text-[10px]';
            
            let trimmed = line.trim();
            if (trimmed.startsWith('===') && trimmed.endsWith('===')) {
                // Section Header
                item.className = 'font-label-surgical text-[10px] text-[#00ffc4] uppercase tracking-wider mt-4 mb-2 pb-1 border-b border-[#00ffc4]/20';
                item.textContent = trimmed.replace(/===/g, '').trim();
            } else if (trimmed.startsWith('[CRITICAL]')) {
                item.innerHTML = `<span class="px-1.5 py-0.5 rounded text-[8px] bg-purple-500/20 text-purple-400 font-bold mr-2">CRIT</span> <span class="text-white">${trimmed.substring(10).trim()}</span>`;
            } else if (trimmed.startsWith('[HIGH]')) {
                item.innerHTML = `<span class="px-1.5 py-0.5 rounded text-[8px] bg-red-500/20 text-red-400 font-bold mr-2">HIGH</span> <span class="text-white">${trimmed.substring(6).trim()}</span>`;
            } else if (trimmed.startsWith('[MEDIUM]')) {
                item.innerHTML = `<span class="px-1.5 py-0.5 rounded text-[8px] bg-yellow-500/20 text-yellow-400 font-bold mr-2">MED</span> <span class="text-white">${trimmed.substring(8).trim()}</span>`;
            } else if (trimmed.startsWith('[LOW]')) {
                item.innerHTML = `<span class="px-1.5 py-0.5 rounded text-[8px] bg-white/10 text-white/50 font-bold mr-2">LOW</span> <span class="text-white/70">${trimmed.substring(5).trim()}</span>`;
            } else if (trimmed.startsWith('[INFO]')) {
                item.innerHTML = `<span class="px-1.5 py-0.5 rounded text-[8px] bg-blue-500/10 text-blue-400 font-bold mr-2">INFO</span> <span class="text-white/60">${trimmed.substring(6).trim()}</span>`;
            } else if (trimmed.startsWith('Method:') || trimmed.startsWith('Payload:')) {
                const parts = trimmed.split('|');
                let html = '';
                parts.forEach(p => {
                    const sub = p.trim().split(':');
                    if (sub.length >= 2) {
                        const lbl = sub[0].trim();
                        const val = sub.slice(1).join(':').trim();
                        html += `<span class="text-[#00ffc4] font-bold mr-1">${lbl}:</span><span class="text-white/80 mr-4 font-bold">${val}</span> `;
                    } else {
                        html += `<span class="text-white/80">${p}</span>`;
                    }
                });
                item.innerHTML = html;
            } else if (trimmed.startsWith('Parameter:') || trimmed.startsWith('Evidence:') || trimmed.startsWith('PoC:') || trimmed.startsWith('Secret:') || trimmed.startsWith('URL:') || trimmed.startsWith('Vulnerable:')) {
                const colonIdx = trimmed.indexOf(':');
                if (colonIdx !== -1) {
                    const label = trimmed.substring(0, colonIdx).trim();
                    const val = trimmed.substring(colonIdx + 1).trim();
                    let valColor = 'text-white/80';
                    let labelColor = 'text-[#00ffc4] font-bold';
                    if (label === 'PoC') { valColor = 'text-yellow-300 font-bold select-all'; labelColor = 'text-primary font-bold'; }
                    if (label === 'Secret') { valColor = 'text-cyan-300 font-bold select-all'; labelColor = 'text-primary font-bold'; }
                    if (label === 'Parameter') { valColor = 'text-purple-300 font-bold'; labelColor = 'text-primary font-bold'; }
                    if (label === 'Vulnerable') { valColor = 'text-red-400 font-bold'; labelColor = 'text-primary font-bold'; }
                    item.innerHTML = `<span class="${labelColor} mr-2">${label}:</span><span class="${valColor}">${val}</span>`;
                } else {
                    item.textContent = line;
                }
            } else if (trimmed.startsWith('↳')) {
                item.innerHTML = `<span class="text-[#00ffc4] mr-2">↳</span><span class="text-white/80">${trimmed.substring(1).trim()}</span>`;
            } else {
                item.textContent = line;
            }
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

// ── HTTP REPEATER SYSTEM ─────────────────────────────────────────────
let repeaterTabs = [];
let activeRepeaterTabId = null;
let currentResponseView = 'raw';
let trafficHistory = [];

function initRepeater() {
    if (repeaterTabs.length === 0) {
        addNewRepeaterTab();
    } else {
        renderRepeaterTabs();
        loadActiveTabIntoWorkspace();
    }
    renderTrafficHistory();
}

function addNewRepeaterTab(method = 'GET', url = 'http://127.0.0.1:5000/', rawReq = '') {
    const tabId = 'tab_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5);
    if (!rawReq) {
        rawReq = `${method} / HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nUser-Agent: Hellhound-Repeater/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
    }
    const newTab = {
        id: tabId,
        name: `Req #${repeaterTabs.length + 1}`,
        method: method,
        url: url,
        rawRequest: rawReq,
        response: null
    };
    repeaterTabs.push(newTab);
    activeRepeaterTabId = tabId;
    renderRepeaterTabs();
    loadActiveTabIntoWorkspace();
}

function closeRepeaterTab(tabId, event) {
    if (event) event.stopPropagation();
    const index = repeaterTabs.findIndex(t => t.id === tabId);
    if (index === -1) return;
    
    repeaterTabs.splice(index, 1);
    if (activeRepeaterTabId === tabId) {
        if (repeaterTabs.length > 0) {
            activeRepeaterTabId = repeaterTabs[Math.max(0, index - 1)].id;
        } else {
            activeRepeaterTabId = null;
        }
    }
    renderRepeaterTabs();
    if (activeRepeaterTabId) {
        loadActiveTabIntoWorkspace();
    } else {
        clearRepeaterWorkspace();
    }
}

function selectRepeaterTab(tabId) {
    saveActiveTabFromWorkspace();
    activeRepeaterTabId = tabId;
    renderRepeaterTabs();
    loadActiveTabIntoWorkspace();
}

function saveActiveTabFromWorkspace() {
    if (!activeRepeaterTabId) return;
    const tab = repeaterTabs.find(t => t.id === activeRepeaterTabId);
    if (!tab) return;
    
    const methodEl = document.getElementById('repeaterMethod');
    const targetEl = document.getElementById('repeaterTarget');
    const rawReqEl = document.getElementById('repeaterRawRequest');
    
    if (methodEl) tab.method = methodEl.value;
    if (targetEl) tab.url = targetEl.value;
    if (rawReqEl) tab.rawRequest = rawReqEl.value;
}

function renderRepeaterTabs() {
    const container = document.getElementById('repeaterTabsHeader');
    if (!container) return;
    
    container.innerHTML = repeaterTabs.map(tab => {
        const isActive = tab.id === activeRepeaterTabId;
        const activeClass = isActive 
            ? 'bg-primary/20 border border-primary/40 text-primary font-bold shadow-[inset_0_0_8px_rgba(255,34,68,0.15)]' 
            : 'bg-white/5 border border-white/5 text-white/50 hover:text-white hover:bg-white/10';
        return `
            <div onclick="selectRepeaterTab('${tab.id}')" 
                class="flex items-center gap-2 px-3 py-1.5 rounded cursor-pointer transition-all text-[10px] font-data-mono uppercase tracking-wider ${activeClass}">
                <span>${tab.method}</span>
                <span class="max-w-[80px] truncate">${tab.name}</span>
                <span onclick="closeRepeaterTab('${tab.id}', event)" class="material-symbols-outlined text-[12px] hover:text-red-500 transition-colors ml-1">close</span>
            </div>
        `;
    }).join('');
}

function loadActiveTabIntoWorkspace() {
    if (!activeRepeaterTabId) return;
    const tab = repeaterTabs.find(t => t.id === activeRepeaterTabId);
    if (!tab) return;
    
    const methodEl = document.getElementById('repeaterMethod');
    const targetEl = document.getElementById('repeaterTarget');
    const rawReqEl = document.getElementById('repeaterRawRequest');
    
    if (methodEl) methodEl.value = tab.method;
    if (targetEl) targetEl.value = tab.url;
    if (rawReqEl) rawReqEl.value = tab.rawRequest;
    
    renderResponseViewer(tab.response);
}

function clearRepeaterWorkspace() {
    const methodEl = document.getElementById('repeaterMethod');
    const targetEl = document.getElementById('repeaterTarget');
    const rawReqEl = document.getElementById('repeaterRawRequest');
    
    if (methodEl) methodEl.value = 'GET';
    if (targetEl) targetEl.value = '';
    if (rawReqEl) rawReqEl.value = '';
    
    renderResponseViewer(null);
}

function parseRawRequest(rawStr) {
    const parts = rawStr.split(/\r?\n\r?\n/);
    const headerLines = parts[0].split(/\r?\n/);
    const body = parts.slice(1).join('\n\n');
    
    const requestLine = headerLines[0].split(' ');
    const method = requestLine[0] || 'GET';
    const path = requestLine[1] || '/';
    
    const headers = {};
    for (let i = 1; i < headerLines.length; i++) {
        const line = headerLines[i];
        const colonIdx = line.indexOf(':');
        if (colonIdx !== -1) {
            const key = line.substring(0, colonIdx).trim().toLowerCase();
            const val = line.substring(colonIdx + 1).trim();
            headers[key] = val;
        }
    }
    
    return { method, path, headers, body };
}

function sendRawHttpRequest(protocol, hostname, port, rawRequest, proxy, callback) {
    const net = require('net');
    const tls = require('tls');
    
    let proxyHost = null;
    let proxyPort = null;
    if (proxy) {
        let proxyUrlStr = proxy;
        if (!proxyUrlStr.includes('://')) proxyUrlStr = 'http://' + proxyUrlStr;
        try {
            const pUrl = new URL(proxyUrlStr);
            proxyHost = pUrl.hostname;
            proxyPort = parseInt(pUrl.port) || 8080;
        } catch(e) {}
    }
    
    const startTime = Date.now();
    let socket;
    
    function handleConnectedSocket(establishedSocket) {
        let responseBuffer = Buffer.alloc(0);
        let headerParsed = false;
        let contentLength = -1;
        let isChunked = false;
        let headerEndIndex = -1;
        
        establishedSocket.on('data', (chunk) => {
            responseBuffer = Buffer.concat([responseBuffer, chunk]);
            
            if (!headerParsed) {
                headerEndIndex = responseBuffer.indexOf('\r\n\r\n');
                if (headerEndIndex !== -1) {
                    headerParsed = true;
                    const headerStr = responseBuffer.slice(0, headerEndIndex).toString('utf8');
                    
                    const clMatch = headerStr.match(/content-length:\s*(\d+)/i);
                    if (clMatch) {
                        contentLength = parseInt(clMatch[1], 10);
                    }
                    
                    if (/transfer-encoding:\s*chunked/i.test(headerStr)) {
                        isChunked = true;
                    }
                }
            }
            
            if (headerParsed) {
                const bodyBytesReceived = responseBuffer.length - (headerEndIndex + 4);
                if (contentLength !== -1 && bodyBytesReceived >= contentLength) {
                    establishedSocket.end();
                } else if (isChunked) {
                    // Check if chunked body ends with 0\r\n\r\n
                    if (responseBuffer.slice(-5).toString() === '0\r\n\r\n' || 
                        responseBuffer.indexOf('\r\n0\r\n\r\n') !== -1) {
                        establishedSocket.end();
                    }
                }
            }
        });
        
        establishedSocket.on('end', () => {
            callback(null, responseBuffer, Date.now() - startTime);
        });
        
        establishedSocket.on('error', (err) => {
            if (responseBuffer.length > 0) {
                callback(null, responseBuffer, Date.now() - startTime);
            } else {
                callback(err);
            }
        });
        
        // Write request payload
        establishedSocket.write(rawRequest);
    }
    
    if (proxyHost && proxyPort) {
        // Route via Proxy
        const conn = net.connect(proxyPort, proxyHost);
        let connectBuffer = '';
        
        conn.on('connect', () => {
            if (protocol === 'https:') {
                // HTTPS CONNECT Tunneling
                conn.write(`CONNECT ${hostname}:${port} HTTP/1.1\r\nHost: ${hostname}:${port}\r\n\r\n`);
            } else {
                // HTTP Absolute Path Request
                let modifiedRequest = rawRequest;
                const reqStr = rawRequest.toString('utf8');
                const firstLineEnd = reqStr.indexOf('\r\n');
                if (firstLineEnd !== -1) {
                    const firstLine = reqStr.substring(0, firstLineEnd);
                    const parts = firstLine.split(' ');
                    if (parts.length >= 2 && !parts[1].startsWith('http')) {
                        parts[1] = `http://${hostname}:${port}${parts[1]}`;
                        modifiedRequest = Buffer.concat([
                            Buffer.from(parts.join(' ')),
                            rawRequest.slice(firstLineEnd)
                        ]);
                    }
                }
                handleConnectedSocket(conn);
            }
        });
        
        conn.on('data', (chunk) => {
            if (protocol === 'https:' && !socket) {
                connectBuffer += chunk.toString('utf8');
                if (connectBuffer.includes('\r\n\r\n')) {
                    if (connectBuffer.startsWith('HTTP/1.1 200') || connectBuffer.startsWith('HTTP/1.0 200')) {
                        // CONNECT Established! Now wrap in TLS.
                        socket = tls.connect({
                            socket: conn,
                            servername: hostname,
                            rejectUnauthorized: false
                        }, () => {
                            handleConnectedSocket(socket);
                        });
                        socket.on('error', (err) => callback(err));
                    } else {
                        callback(new Error(`Proxy CONNECT failed:\n${connectBuffer}`));
                        conn.end();
                    }
                }
            }
        });
        
        conn.on('error', (err) => {
            callback(err);
        });
        
    } else {
        // Direct Connection
        if (protocol === 'https:') {
            const secureSocket = tls.connect({
                host: hostname,
                port: port,
                servername: hostname,
                rejectUnauthorized: false
            }, () => {
                handleConnectedSocket(secureSocket);
            });
            secureSocket.on('error', (err) => callback(err));
        } else {
            const plainSocket = net.connect(port, hostname, () => {
                handleConnectedSocket(plainSocket);
            });
            plainSocket.on('error', (err) => callback(err));
        }
    }
}

function parseRawResponse(responseBuffer) {
    const boundary = responseBuffer.indexOf('\r\n\r\n');
    let rawHeaders = '';
    let bodyBuffer = Buffer.alloc(0);
    if (boundary !== -1) {
        rawHeaders = responseBuffer.slice(0, boundary).toString('utf8');
        bodyBuffer = responseBuffer.slice(boundary + 4);
    } else {
        rawHeaders = responseBuffer.toString('utf8');
    }
    
    const lines = rawHeaders.split('\r\n');
    const statusLine = lines[0] || 'HTTP/1.1 0 ERROR';
    const statusParts = statusLine.split(' ');
    const statusCode = parseInt(statusParts[1], 10) || 0;
    const statusText = statusParts.slice(2).join(' ') || '';
    
    const headersList = lines.slice(1).filter(l => l.trim());
    const headersStr = headersList.join('\n');
    
    return {
        statusCode,
        statusText,
        headers: headersStr,
        body: bodyBuffer.toString('utf8'),
        raw: responseBuffer.toString('utf8')
    };
}

function sendActiveRepeater() {
    if (!activeRepeaterTabId) return;
    saveActiveTabFromWorkspace();
    
    const tab = repeaterTabs.find(t => t.id === activeRepeaterTabId);
    if (!tab) return;
    
    const sendBtn = document.getElementById('repeaterSendBtn');
    if (sendBtn) {
        sendBtn.disabled = true;
        sendBtn.classList.add('opacity-50', 'pointer-events-none');
    }
    
    const metaContainer = document.getElementById('repeaterResponseMeta');
    const viewer = document.getElementById('repeaterResponseViewer');
    if (metaContainer) metaContainer.innerHTML = '';
    if (viewer) viewer.innerHTML = `<div class="text-primary animate-pulse text-[10px] text-center font-data-mono py-16">FORWARDING PAYLOAD THROUGH HELLHOUND REPRO ENGINE...</div>`;
    
    const parsedReq = parseRawRequest(tab.rawRequest);
    const reqMethod = parsedReq.method;
    const reqPath = parsedReq.path;
    const reqHeaders = parsedReq.headers;
    const reqBody = parsedReq.body;
    
    let targetUrlStr = tab.url || reqHeaders['host'] || reqHeaders['Host'];
    if (!targetUrlStr) {
        if (metaContainer) metaContainer.innerHTML = `<span class="text-red-500 font-label-surgical text-[9px]">ERROR: NO TARGET URL</span>`;
        if (viewer) viewer.innerHTML = `<div class="text-red-500 text-[10px] font-data-mono py-16">Please specify a target URL or Host header.</div>`;
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.classList.remove('opacity-50', 'pointer-events-none');
        }
        return;
    }
    
    if (!/^https?:\/\//i.test(targetUrlStr)) {
        targetUrlStr = 'http://' + targetUrlStr;
    }
    
    try {
        const targetUrl = new URL(targetUrlStr);
        let targetHostname = targetUrl.hostname;
        let targetPort = targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80);
        
        // Retrieve settings for proxy & WAF bypass
        const settings = JSON.parse(localStorage.getItem('hh_global_settings') || '{}');
        const proxy = settings.proxy_mode === 'ALL' ? settings.proxy : null;
        
        // Prepare request text
        // Ensure Host header is set
        let reqPayloadStr = `${reqMethod} ${reqPath} HTTP/1.1\r\n`;
        const headerLines = [];
        let hasHost = false;
        for (const [k, v] of Object.entries(reqHeaders)) {
            if (k.toLowerCase() === 'host') {
                headerLines.push(`${k}: ${targetUrl.host}`);
                hasHost = true;
            } else {
                headerLines.push(`${k}: ${v}`);
            }
        }
        if (!hasHost) {
            headerLines.push(`Host: ${targetUrl.host}`);
        }
        
        // Inject WAF spoofing headers if option is enabled
        if (settings.wafbypass === 'true' || settings.wafbypass === true) {
            const bypassHeaders = {
                'X-Forwarded-For': '127.0.0.1',
                'X-Originating-IP': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Remote-Addr': '127.0.0.1',
                'X-Client-IP': '127.0.0.1',
                'Client-IP': '127.0.0.1',
                'X-Real-IP': '127.0.0.1'
            };
            for (const [hk, hv] of Object.entries(bypassHeaders)) {
                let found = false;
                for (const k of Object.keys(reqHeaders)) {
                    if (k.toLowerCase() === hk.toLowerCase()) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    headerLines.push(`${hk}: ${hv}`);
                }
            }
        }
        
        // If content-length is not set and there is a body, set it
        let hasContentLength = false;
        for (const [k, v] of Object.entries(reqHeaders)) {
            if (k.toLowerCase() === 'content-length') hasContentLength = true;
        }
        if (reqBody && !hasContentLength) {
            headerLines.push(`Content-Length: ${Buffer.byteLength(reqBody)}`);
        }
        
        reqPayloadStr += headerLines.join('\r\n') + '\r\n\r\n';
        if (reqBody) {
            reqPayloadStr += reqBody;
        }
        
        const rawReqBuffer = Buffer.from(reqPayloadStr, 'utf8');
        const startTime = Date.now();
        
        // Latency-based auto-throttling
        const currentLatency = window.lastRecordedLatency || 0;
        let delayMs = 0;
        if (currentLatency > 800) {
            delayMs = Math.min(2000, currentLatency - 400);
            if (typeof pushActivity === 'function') {
                pushActivity(`High latency detected (${currentLatency}ms). Auto-throttling: delaying request by ${delayMs}ms`, 'warning');
            }
        }
        
        setTimeout(() => {
            sendRawHttpRequest(targetUrl.protocol, targetHostname, targetPort, rawReqBuffer, proxy, (err, responseBuffer, latency) => {
                if (err) {
                    tab.response = {
                        statusCode: 0,
                        statusText: 'ERR_CONNECTION',
                        latency: Date.now() - startTime,
                        size: 0,
                        raw: `HELLHOUND COMPILER ERROR:\nConnection failed.\n\n${err.message}`,
                        headers: `Error: ${err.message}`,
                        body: err.message
                    };
                    if (activeRepeaterTabId === tab.id) {
                        renderResponseViewer(tab.response);
                    }
                    if (sendBtn) {
                        sendBtn.disabled = false;
                        sendBtn.classList.remove('opacity-50', 'pointer-events-none');
                    }
                    return;
                }
                
                // Track latency globally
                window.lastRecordedLatency = latency;
                
                const parsedResp = parseRawResponse(responseBuffer);
                
                // WAF Fingerprinting
                let wafDetected = "SAFE";
                let wafColor = "text-green-400";
                let wafIcon = "shield";
                
                const responseTextLower = parsedResp.raw.toLowerCase();
                if (responseTextLower.includes('cloudflare') || parsedResp.headers.toLowerCase().includes('cf-ray')) {
                    wafDetected = "CLOUDFLARE";
                    wafColor = "text-orange-500 animate-pulse";
                    wafIcon = "shield_with_heart";
                } else if (responseTextLower.includes('aws-waf') || responseTextLower.includes('awswaf')) {
                    wafDetected = "AWS WAF";
                    wafColor = "text-red-500 animate-pulse";
                    wafIcon = "shield_with_heart";
                } else if (responseTextLower.includes('akamai')) {
                    wafDetected = "AKAMAI";
                    wafColor = "text-yellow-500 animate-pulse";
                    wafIcon = "shield_with_heart";
                } else if (responseTextLower.includes('imperva') || responseTextLower.includes('incapsula')) {
                    wafDetected = "IMPERVA";
                    wafColor = "text-purple-500 animate-pulse";
                    wafIcon = "shield_with_heart";
                } else if (responseTextLower.includes('modsecurity') || responseTextLower.includes('mod_security')) {
                    wafDetected = "MODSECURITY";
                    wafColor = "text-blue-400 animate-pulse";
                    wafIcon = "shield_with_heart";
                }
                
                const wafLabel = document.getElementById('wafStatusLabel');
                const wafIconEl = document.getElementById('wafStatusIcon');
                if (wafLabel && wafIconEl) {
                    wafLabel.innerText = `WAF: ${wafDetected}`;
                    wafLabel.className = `font-label-surgical text-[8px] uppercase tracking-widest ${wafColor}`;
                    wafIconEl.innerText = wafIcon;
                    wafIconEl.className = `material-symbols-outlined text-[12px] ${wafColor}`;
                }
                
                const heartbeatLabel = document.getElementById('heartbeatLabel');
                if (heartbeatLabel) {
                    heartbeatLabel.innerText = `LATENCY: ${latency} MS`;
                    if (latency > 1000) {
                        heartbeatLabel.className = `font-label-surgical text-[8px] uppercase tracking-widest font-bold text-red-500`;
                    } else if (latency > 500) {
                        heartbeatLabel.className = `font-label-surgical text-[8px] uppercase tracking-widest font-bold text-yellow-500`;
                    } else {
                        heartbeatLabel.className = `font-label-surgical text-[8px] uppercase tracking-widest font-bold text-primary`;
                    }
                }
                
                tab.response = {
                    statusCode: parsedResp.statusCode,
                    statusText: parsedResp.statusText,
                    latency: latency,
                    size: responseBuffer.length,
                    raw: parsedResp.raw,
                    headers: parsedResp.headers,
                    body: parsedResp.body
                };
                
                addTrafficHistoryItem({
                    time: new Date().toLocaleTimeString('en-GB', { hour12: false }),
                    method: reqMethod,
                    url: targetUrlStr.replace(/\/$/, '') + reqPath,
                    status: parsedResp.statusCode,
                    latency: latency,
                    rawRequest: tab.rawRequest
                });
                
                if (activeRepeaterTabId === tab.id) {
                    renderResponseViewer(tab.response);
                }
                
                if (sendBtn) {
                    sendBtn.disabled = false;
                    sendBtn.classList.remove('opacity-50', 'pointer-events-none');
                }
            });
        }, delayMs);
        
    } catch (e) {
        if (metaContainer) metaContainer.innerHTML = `<span class="text-red-500 font-label-surgical text-[9px]">BAD TARGET URL</span>`;
        if (viewer) viewer.innerHTML = `<div class="text-red-500 text-[10px] font-data-mono py-16">URL Parse Error: ${e.message}</div>`;
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.classList.remove('opacity-50', 'pointer-events-none');
        }
    }
}

function setResponseView(view) {
    currentResponseView = view;
    ['raw', 'headers', 'body'].forEach(v => {
        const btn = document.getElementById(`respTab-${v}`);
        if (btn) {
            if (v === view) {
                btn.className = 'px-3 py-1 text-white border-b-2 border-primary font-bold';
            } else {
                btn.className = 'px-3 py-1 text-white/40 hover:text-white transition-colors';
            }
        }
    });
    
    if (activeRepeaterTabId) {
        const tab = repeaterTabs.find(t => t.id === activeRepeaterTabId);
        if (tab) {
            renderResponseViewer(tab.response);
        }
    }
}

function renderResponseViewer(response) {
    const metaContainer = document.getElementById('repeaterResponseMeta');
    const viewer = document.getElementById('repeaterResponseViewer');
    if (!metaContainer || !viewer) return;
    
    if (!response) {
        metaContainer.innerHTML = '';
        viewer.innerHTML = `<div class="text-white/20 italic text-[10px] text-center font-data-mono py-16">Send request to retrieve telemetry response stream</div>`;
        return;
    }
    
    let statusColor = 'text-green-400 border-green-500/20 bg-green-500/5';
    if (response.statusCode >= 400 && response.statusCode < 500) {
        statusColor = 'text-yellow-400 border-yellow-500/20 bg-yellow-500/5';
    } else if (response.statusCode >= 500 || response.statusCode === 0) {
        statusColor = 'text-red-400 border-red-500/20 bg-red-500/5';
    }
    
    metaContainer.innerHTML = `
        <span class="px-2 py-0.5 border rounded font-data-mono text-[9px] ${statusColor}">${response.statusCode} ${response.statusText}</span>
        <span class="px-2 py-0.5 border border-white/10 bg-white/5 rounded font-data-mono text-[9px] text-white/50">${response.latency} ms</span>
        <span class="px-2 py-0.5 border border-white/10 bg-white/5 rounded font-data-mono text-[9px] text-white/50">${(response.size / 1024).toFixed(2)} KB</span>
    `;
    
    function escapeHTML(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    
    let contentToRender = '';
    if (currentResponseView === 'raw') {
        const boundary = response.raw.indexOf('\r\n\r\n');
        if (boundary !== -1) {
            const headers = response.raw.substring(0, boundary);
            const body = response.raw.substring(boundary + 4);
            contentToRender = `<span style="color: #00ffc4; font-weight: 500;">${escapeHTML(headers)}</span>\n\n<span style="color: rgba(255,255,255,0.7);">${escapeHTML(body)}</span>`;
        } else {
            contentToRender = `<span style="color: rgba(255,255,255,0.7);">${escapeHTML(response.raw)}</span>`;
        }
    } else if (currentResponseView === 'headers') {
        contentToRender = `<span style="color: #00ffc4; font-weight: 500;">${escapeHTML(response.headers)}</span>`;
    } else if (currentResponseView === 'body') {
        contentToRender = `<span style="color: rgba(255,255,255,0.7);">${escapeHTML(response.body)}</span>`;
    }
    
    viewer.innerHTML = contentToRender;
}

function addTrafficHistoryItem(item) {
    trafficHistory.unshift(item);
    if (trafficHistory.length > 50) {
        trafficHistory.pop();
    }
    renderTrafficHistory();
}

function renderTrafficHistory() {
    const container = document.getElementById('trafficHistoryList');
    if (!container) return;
    
    const searchVal = (document.getElementById('trafficSearch')?.value || '').toLowerCase();
    const filtered = trafficHistory.filter(item => {
        return item.method.toLowerCase().includes(searchVal) || 
               item.url.toLowerCase().includes(searchVal) ||
               String(item.status).includes(searchVal);
    });
    
    if (filtered.length === 0) {
        container.innerHTML = `<div class="text-white/30 italic text-[10px] text-center font-data-mono py-8">No traffic intercepted yet. Runs/strikes will stream here.</div>`;
        return;
    }
    
    container.innerHTML = filtered.map((item, idx) => {
        let statusColor = 'text-green-400';
        if (item.status >= 400 && item.status < 500) statusColor = 'text-yellow-400';
        else if (item.status >= 500 || item.status === 0) statusColor = 'text-red-400';
        
        return `
            <div onclick="loadTrafficItemToRepeater(${idx})" 
                class="group border border-white/5 bg-white/[0.01] hover:bg-white/[0.03] hover:border-primary/30 p-3 rounded cursor-pointer transition-all flex flex-col gap-1">
                <div class="flex justify-between items-center text-[8px] text-white/30 font-data-mono">
                    <span>${item.time} // ${item.latency}ms</span>
                    <span class="font-bold ${statusColor}">${item.status}</span>
                </div>
                <div class="text-[10px] text-white/80 font-data-mono font-bold flex items-center gap-2 truncate">
                    <span class="text-primary font-bold text-[9px] group-hover:scale-105 transition-transform">${item.method}</span>
                    <span class="truncate flex-1">${item.url}</span>
                </div>
            </div>
        `;
    }).join('');
}

function loadTrafficItemToRepeater(idx) {
    const item = trafficHistory[idx];
    if (!item) return;
    addNewRepeaterTab(item.method, item.url, item.rawRequest);
}

function filterTrafficHistory() {
    renderTrafficHistory();
}

function handleRealTelemetryEvent(line, severity) {
    let method = 'GET';
    let urlStr = '';
    let status = 200;
    
    if (line.includes('curl ')) {
        const urlMatch = line.match(/https?:\/\/[^\s'"]+/);
        if (urlMatch) urlStr = urlMatch[0];
        
        const methodMatch = line.match(/-X\s+([A-Z]+)/);
        if (methodMatch) method = methodMatch[1];
        else if (line.includes('--data') || line.includes('-d ')) method = 'POST';
    } else {
        const parts = line.split(' ');
        if (parts.length >= 2) {
            const possibleMethod = parts[0].toUpperCase();
            if (['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].includes(possibleMethod)) {
                method = possibleMethod;
                const urlMatch = line.match(/https?:\/\/[^\s]+/);
                if (urlMatch) urlStr = urlMatch[0].replace(/-$/, '').trim();
            }
        }
        
        const statusMatch = line.match(/\b([2-5]\d\d)\b/);
        if (statusMatch) status = parseInt(statusMatch[1]);
    }
    
    if (!urlStr) return;
    
    let rawRequest = `${method} ${new URL(urlStr).pathname} HTTP/1.1\r\nHost: ${new URL(urlStr).host}\r\nUser-Agent: Hellhound-Repeater/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
    
    addTrafficHistoryItem({
        time: new Date().toLocaleTimeString('en-GB', { hour12: false }),
        method: method,
        url: urlStr,
        status: status,
        latency: 120,
        rawRequest: rawRequest
    });
}

// ── DE-CAFFEINATOR JS AST SANDBOX LOGIC ─────────────────────────────

function deobfuscateScript() {
    const input = document.getElementById('decafInput').value;
    if (!input.trim()) {
        alert("Please paste some script contents into the Source Script Input pane.");
        return;
    }
    
    // Basic Javascript Beautifier engine
    let beautified = '';
    let indentLevel = 0;
    const tabString = '    ';
    
    // Remove formatting/minification loosely
    let clean = input
        .replace(/\r/g, '')
        .replace(/;\s*/g, ';\n')
        .replace(/\{\s*/g, '{\n')
        .replace(/\}\s*/g, '\n}\n')
        .replace(/\n\s*\n/g, '\n');
        
    const lines = clean.split('\n');
    for (let line of lines) {
        line = line.trim();
        if (!line) continue;
        
        if (line.includes('}')) {
            indentLevel = Math.max(0, indentLevel - 1);
        }
        
        beautified += tabString.repeat(indentLevel) + line + '\n';
        
        if (line.includes('{')) {
            indentLevel++;
        }
    }
    
    document.getElementById('decafBeautified').value = beautified;
    if (typeof pushActivity === 'function') pushActivity('De-Caffeinator: Beautification compiled.', 'success');
}

function mineScript() {
    const input = document.getElementById('decafInput').value;
    if (!input.trim()) {
        alert("Please paste some script contents to mine.");
        return;
    }
    
    const list = document.getElementById('decafEntitiesList');
    list.innerHTML = '';
    
    const results = [];
    
    // Regex for secrets and endpoints
    const regexes = {
        'API Path': /"(\/[a-zA-Z0-9_\-\/]+)"|'(\/[a-zA-Z0-9_\-\/]+)'/g,
        'AWS Secret Key': /([^a-zA-Z0-9\/+])[a-zA-Z0-9\/+]{40}(?=[^a-zA-Z0-9\/+])/g,
        'Generic API Key': /(?:key|api_key|token|auth|secret|pwd|passwd|password)\s*[:=]\s*["']([a-zA-Z0-9_\-\+=]{16,})["']/gi,
        'JWT Token': /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
        'Internal Domain/IP': /(?:https?:\/\/)?(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:\/[a-zA-Z0-9_\-\/]+)*/g
    };
    
    for (const [category, regex] of Object.entries(regexes)) {
        let match;
        // reset regex state
        regex.lastIndex = 0;
        const matchesSeen = new Set();
        while ((match = regex.exec(input)) !== null) {
            const matchedValue = (match[1] || match[2] || match[0]).trim();
            if (matchedValue && !matchesSeen.has(matchedValue) && matchedValue.length < 200) {
                matchesSeen.add(matchedValue);
                results.push({ category, value: matchedValue });
            }
        }
    }
    
    if (results.length === 0) {
        list.innerHTML = `<div class="text-white/20 italic text-center py-8">No sensitive entities or endpoints detected in the source.</div>`;
        return;
    }
    
    results.forEach(res => {
        const item = document.createElement('div');
        item.className = 'flex items-center justify-between p-2 border-b border-white/5 hover:bg-white/5 transition-colors';
        
        let actions = '';
        if (res.category === 'API Path' || res.category === 'Internal Domain/IP') {
            actions = `
                <button onclick="loadEndpointToRepeater('${res.value}')" class="px-2 py-1 bg-primary text-background font-label-surgical text-[8px] font-bold uppercase tracking-widest hover:brightness-110 transition-all rounded shadow">
                    Load Repeater
                </button>
            `;
        } else {
            actions = `
                <button onclick="copyToClipboard('${res.value}')" class="px-2 py-1 bg-[#00ffc4]/20 border border-[#00ffc4]/30 text-[#00ffc4] font-label-surgical text-[8px] font-bold uppercase tracking-widest hover:bg-[#00ffc4]/30 transition-all rounded">
                    Copy Key
                </button>
            `;
        }
        
        item.innerHTML = `
            <div class="flex flex-col gap-1 min-w-0 flex-1 mr-4">
                <span class="text-white/30 text-[8px] uppercase tracking-wider">${res.category}</span>
                <span class="text-white font-data-mono truncate select-all text-[9px]">${res.value}</span>
            </div>
            <div class="flex-shrink-0">
                ${actions}
            </div>
        `;
        list.appendChild(item);
    });
    
    if (typeof pushActivity === 'function') pushActivity(`De-Caffeinator: Extracted ${results.length} entities from script.`, 'success');
}

function loadEndpointToRepeater(val) {
    let targetUrl = val;
    // Build valid URL if path only
    if (val.startsWith('/')) {
        const activeTargetVal = document.getElementById('headerTarget').innerText;
        if (activeTargetVal && activeTargetVal !== 'NO_TARGET_ENGAGED' && activeTargetVal !== 'NO TARGET' && activeTargetVal !== 'NO TARGET ENGAGED') {
            targetUrl = activeTargetVal.replace(/\/$/, '') + val;
        } else {
            targetUrl = 'http://localhost' + val;
        }
    }
    
    try {
        const parsed = new URL(targetUrl);
        const host = parsed.host;
        const path = parsed.pathname + parsed.search;
        const rawRequest = `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Hellhound-Repeater/1.0\r\nConnection: close\r\n\r\n`;
        
        showSection('repeater', document.querySelector('[onclick*="showSection(\'repeater\'"]'));
        document.getElementById('repeaterTarget').value = targetUrl;
        document.getElementById('repeaterMethod').value = 'GET';
        document.getElementById('repeaterRawRequest').value = rawRequest;
        
        if (typeof pushActivity === 'function') pushActivity(`Loaded mined endpoint to Repeater: ${targetUrl}`, 'success');
    } catch (e) {
        showSection('repeater', document.querySelector('[onclick*="showSection(\'repeater\'"]'));
        document.getElementById('repeaterTarget').value = targetUrl;
        document.getElementById('repeaterRawRequest').value = `GET ${val} HTTP/1.1\r\nHost: target\r\nUser-Agent: Hellhound-Repeater/1.0\r\nConnection: close\r\n\r\n`;
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text);
    if (typeof pushActivity === 'function') pushActivity('Copied credential key to clipboard.', 'success');
}

// ── TOKEN FORGE CRYPTOGRAPHIC SANDBOX LOGIC ─────────────────────────

function tokenForgeAction(action) {
    const input = document.getElementById('tokenForgeInput').value;
    const outputEl = document.getElementById('tokenForgeOutput');
    
    if (action === 'inject') {
        const outVal = outputEl.value;
        if (!outVal) {
            alert("No Forge output value available to inject.");
            return;
        }
        
        const reqTextarea = document.getElementById('repeaterRawRequest');
        const start = reqTextarea.selectionStart;
        const end = reqTextarea.selectionEnd;
        const text = reqTextarea.value;
        
        reqTextarea.value = text.substring(0, start) + outVal + text.substring(end);
        reqTextarea.focus();
        reqTextarea.selectionStart = start;
        reqTextarea.selectionEnd = start + outVal.length;
        
        if (typeof pushActivity === 'function') pushActivity("Token Forge: Injected token to active editor cursor location", "success");
        return;
    }
    
    if (!input.trim()) {
        alert("Please specify some input data in the Token Forge Input pane.");
        return;
    }
    
    let result = '';
    
    try {
        if (action === 'base64_encode') {
            result = Buffer.from(input, 'utf8').toString('base64');
        } else if (action === 'base64_decode') {
            result = Buffer.from(input, 'base64').toString('utf8');
        } else if (action === 'jwt_alg_none') {
            const parts = input.split('.');
            if (parts.length >= 2) {
                let header = {};
                try {
                    header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf8'));
                } catch(e) {}
                header.alg = 'none';
                
                const newHeaderB64 = Buffer.from(JSON.stringify(header), 'utf8')
                    .toString('base64')
                    .replace(/=/g, '')
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_');
                    
                const payloadB64 = parts[1].replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
                result = `${newHeaderB64}.${payloadB64}.`;
            } else {
                let payloadStr = input;
                try {
                    JSON.parse(input);
                } catch (e) {
                    payloadStr = JSON.stringify({ user: input, role: 'admin' });
                }
                const header = { alg: 'none', typ: 'JWT' };
                const headerB64 = Buffer.from(JSON.stringify(header), 'utf8').toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
                const payloadB64 = Buffer.from(payloadStr, 'utf8').toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
                result = `${headerB64}.${payloadB64}.`;
            }
        }
    } catch (e) {
        result = `ERROR: ${e.message}`;
    }
    
    outputEl.value = result;
    if (typeof pushActivity === 'function') pushActivity(`Token Forge: Executed ${action} action.`, 'success');
}

// ── ATTACK GRAPH TRANSITION HOOKS ────────────────────────────────────

function graphLoadToRepeater(url) {
    try {
        let cleanUrl = url;
        if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
            cleanUrl = 'http://' + cleanUrl;
        }
        const parsed = new URL(cleanUrl);
        const host = parsed.host;
        const path = parsed.pathname + parsed.search;
        const rawRequest = `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Hellhound-Repeater/1.0\r\nConnection: close\r\n\r\n`;
        
        showSection('repeater', document.querySelector('[onclick*="showSection(\'repeater\'"]'));
        document.getElementById('repeaterTarget').value = cleanUrl;
        document.getElementById('repeaterMethod').value = 'GET';
        document.getElementById('repeaterRawRequest').value = rawRequest;
        
        if (typeof pushActivity === 'function') pushActivity(`Loaded Attack Graph node URL to Repeater: ${cleanUrl}`, 'success');
    } catch (e) {
        showSection('repeater', document.querySelector('[onclick*="showSection(\'repeater\'"]'));
        document.getElementById('repeaterTarget').value = url;
        document.getElementById('repeaterRawRequest').value = `GET / HTTP/1.1\r\nHost: ${url}\r\nUser-Agent: Hellhound-Repeater/1.0\r\nConnection: close\r\n\r\n`;
    }
}

function graphSendToDeCaff(label) {
    showSection('decaffeinator', document.querySelector('[onclick*="showSection(\'decaffeinator\'"]'));
    document.getElementById('decafInput').value = `// Fetching script endpoint: ${label}\n// Paste actual script contents or run mining below if endpoint contains target content.\n\nfunction main() {\n  console.log("Analyzing remote endpoint ${label}");\n}`;
    if (typeof pushActivity === 'function') pushActivity(`Sent Script endpoint to De-Caffeinator: ${label}`, 'success');
}

// ── COOKIE FORGE & REPEATER TRANSMIT LOGIC ─────────────────────────────
function getCryptoModule() {
    try {
        return require('crypto');
    } catch (e) {
        console.error("Crypto not available:", e);
        return null;
    }
}

function base64url(source) {
    let encoded = Buffer.from(source).toString('base64');
    return encoded.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
        str += '=';
    }
    return Buffer.from(str, 'base64').toString('utf8');
}

function cookieForgeAction(action) {
    const type = document.getElementById('cookieForgeType').value;
    const input = document.getElementById('cookieForgeInput').value.trim();
    const secret = document.getElementById('cookieForgeSecret').value;
    const outputArea = document.getElementById('cookieForgeOutput');
    const headerArea = document.getElementById('cookieForgeHeader');
    const payloadArea = document.getElementById('cookieForgePayload');

    if (action === 'decode') {
        if (!input) {
            alert('Please paste a raw token to decode.');
            return;
        }
        try {
            if (type === 'jwt') {
                const parts = input.split('.');
                if (parts.length < 2) {
                    throw new Error('Invalid JWT format (needs at least header and payload parts)');
                }
                const headerDec = base64urlDecode(parts[0]);
                const payloadDec = base64urlDecode(parts[1]);
                
                headerArea.value = JSON.stringify(JSON.parse(headerDec), null, 2);
                payloadArea.value = JSON.stringify(JSON.parse(payloadDec), null, 2);
                
                if (typeof pushActivity === 'function') pushActivity('Successfully parsed and loaded JWT structure', 'success');
            } else if (type === 'base64') {
                const decoded = Buffer.from(input, 'base64').toString('utf8');
                headerArea.value = '';
                try {
                    payloadArea.value = JSON.stringify(JSON.parse(decoded), null, 2);
                } catch (_) {
                    payloadArea.value = decoded;
                }
                if (typeof pushActivity === 'function') pushActivity('Decoded Base64 cookie payload', 'success');
            } else if (type === 'hex') {
                const decoded = Buffer.from(input, 'hex').toString('utf8');
                headerArea.value = '';
                try {
                    payloadArea.value = JSON.stringify(JSON.parse(decoded), null, 2);
                } catch (_) {
                    payloadArea.value = decoded;
                }
                if (typeof pushActivity === 'function') pushActivity('Decoded Hex cookie payload', 'success');
            } else if (type === 'url') {
                const decoded = decodeURIComponent(input);
                headerArea.value = '';
                try {
                    payloadArea.value = JSON.stringify(JSON.parse(decoded), null, 2);
                } catch (_) {
                    payloadArea.value = decoded;
                }
                if (typeof pushActivity === 'function') pushActivity('Decoded URL cookie payload', 'success');
            }
        } catch (e) {
            alert('Error decoding: ' + e.message);
            if (typeof pushActivity === 'function') pushActivity('Cookie Forge decode error: ' + e.message, 'warning');
        }
    } else if (action === 'forge') {
        try {
            if (type === 'jwt') {
                const rawHeader = headerArea.value.trim() || '{"alg":"HS256","typ":"JWT"}';
                const rawPayload = payloadArea.value.trim();
                if (!rawPayload) {
                    throw new Error('Payload cannot be empty');
                }
                
                const parsedHeader = JSON.parse(rawHeader);
                const parsedPayload = JSON.parse(rawPayload);
                
                const headerB64 = base64url(JSON.stringify(parsedHeader));
                const payloadB64 = base64url(JSON.stringify(parsedPayload));
                
                const tokenStr = `${headerB64}.${payloadB64}`;
                const alg = (parsedHeader.alg || '').toUpperCase();
                
                if (alg === 'NONE') {
                    outputArea.value = tokenStr + '.';
                } else if (alg === 'HS256') {
                    const crypto = getCryptoModule();
                    if (!crypto) {
                        throw new Error('HMAC signature requires Node crypto library');
                    }
                    const hmac = crypto.createHmac('sha256', secret || '');
                    hmac.update(tokenStr);
                    const sigB64 = hmac.digest('base64')
                        .replace(/=/g, '')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_');
                    outputArea.value = `${tokenStr}.${sigB64}`;
                } else {
                    throw new Error('Algorithm ' + alg + ' not supported. Use HS256 or None.');
                }
                if (typeof pushActivity === 'function') pushActivity('Forged JWT session token', 'success');
            } else if (type === 'base64') {
                const content = payloadArea.value;
                const encoded = Buffer.from(content).toString('base64');
                outputArea.value = encoded;
                if (typeof pushActivity === 'function') pushActivity('Forged Base64 cookie', 'success');
            } else if (type === 'hex') {
                const content = payloadArea.value;
                const encoded = Buffer.from(content).toString('hex');
                outputArea.value = encoded;
                if (typeof pushActivity === 'function') pushActivity('Forged Hex cookie', 'success');
            } else if (type === 'url') {
                const content = payloadArea.value;
                const encoded = encodeURIComponent(content);
                outputArea.value = encoded;
                if (typeof pushActivity === 'function') pushActivity('Forged URL-encoded cookie', 'success');
            }
        } catch (e) {
            alert('Error forging: ' + e.message);
            if (typeof pushActivity === 'function') pushActivity('Cookie Forge compile error: ' + e.message, 'warning');
        }
    }
}

function cookieForgePreset(preset) {
    const typeSel = document.getElementById('cookieForgeType');
    const secretInput = document.getElementById('cookieForgeSecret');
    const headerArea = document.getElementById('cookieForgeHeader');
    const payloadArea = document.getElementById('cookieForgePayload');
    const outputArea = document.getElementById('cookieForgeOutput');

    if (preset === 'jwt_none') {
        typeSel.value = 'jwt';
        headerArea.value = JSON.stringify({ alg: "none", typ: "JWT" }, null, 2);
        payloadArea.value = JSON.stringify({ user: "admin", role: "administrator", exp: Math.floor(Date.now() / 1000) + 3600 }, null, 2);
        secretInput.value = '';
        cookieForgeAction('forge');
    } else if (preset === 'jwt_jwks_bypass') {
        typeSel.value = 'jwt';
        headerArea.value = JSON.stringify({ alg: "HS256", jku: "http://127.0.0.1:5000/.well-known/jwks.json", kid: "key-id-1" }, null, 2);
        payloadArea.value = JSON.stringify({ user: "admin", role: "administrator" }, null, 2);
        secretInput.value = 'secret';
        cookieForgeAction('forge');
    } else if (preset === 'b64_admin') {
        typeSel.value = 'base64';
        headerArea.value = '';
        payloadArea.value = JSON.stringify({ logged_in: true, username: "admin", admin: true, privileges: "super" }, null, 2);
        cookieForgeAction('forge');
    } else if (preset === 'send_repeater') {
        const forgedValue = outputArea.value.trim();
        if (!forgedValue) {
            alert('No forged token found. Click Forge first!');
            return;
        }
        
        showSection('repeater', document.querySelector('[onclick*="showSection(\'repeater\'"]'));
        
        const rawReqTextarea = document.getElementById('repeaterRawRequest');
        let currentReq = rawReqTextarea.value || `GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n`;
        
        const lines = currentReq.split('\n');
        let hasCookie = false;
        const newLines = lines.map(line => {
            if (line.toLowerCase().startsWith('cookie:')) {
                hasCookie = true;
                return `Cookie: session=${forgedValue}`;
            }
            return line;
        });
        
        if (!hasCookie) {
            const emptyIdx = newLines.findIndex(l => l.trim() === '');
            if (emptyIdx !== -1) {
                newLines.splice(emptyIdx, 0, `Cookie: session=${forgedValue}`);
            } else {
                newLines.push(`Cookie: session=${forgedValue}`);
            }
        }
        
        rawReqTextarea.value = newLines.join('\n');
        if (typeof pushActivity === 'function') pushActivity('Exported forged token to HTTP Repeater cookie headers', 'success');
    }
}

function copyForgeOutput() {
    const outputArea = document.getElementById('cookieForgeOutput');
    if (!outputArea.value) return;
    navigator.clipboard.writeText(outputArea.value);
    if (typeof pushActivity === 'function') pushActivity('Copied forged cookie token to clipboard', 'info');
}

function transmitToRepro() {
    if (!activeRepeaterTabId) return;
    const tab = repeaterTabs.find(t => t.id === activeRepeaterTabId);
    if (!tab) return;
    
    const parsedReq = parseRawRequest(tab.rawRequest);
    const reqMethod = parsedReq.method;
    const reqPath = parsedReq.path;
    const reqHeaders = parsedReq.headers;
    const reqBody = parsedReq.body;
    
    let targetUrlStr = tab.url || reqHeaders['host'] || reqHeaders['Host'] || '';
    if (!targetUrlStr) {
        alert('Please specify a target URL or Host header first.');
        return;
    }
    
    if (!/^https?:\/\//i.test(targetUrlStr)) {
        targetUrlStr = 'http://' + targetUrlStr;
    }
    
    let curlCmd = `curl -X ${reqMethod}`;
    for (const [k, v] of Object.entries(reqHeaders)) {
        if (k.toLowerCase() === 'host') continue;
        curlCmd += ` -H "${k}: ${v.replace(/"/g, '\\"')}"`;
    }
    if (reqBody) {
        curlCmd += ` -d "${reqBody.replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`;
    }
    
    try {
        const urlObj = new URL(targetUrlStr);
        const fullUrl = urlObj.origin + reqPath;
        curlCmd += ` "${fullUrl}"`;
    } catch (_) {
        curlCmd += ` "${targetUrlStr}${reqPath}"`;
    }
    
    const reproPanel = document.getElementById('reproPanel');
    if (reproPanel && reproPanel.classList.contains('hidden')) {
        toggleRepro();
    }
    
    const reproInput = document.getElementById('reproInput');
    if (reproInput) {
        reproInput.value = curlCmd;
        reproInput.focus();
        if (typeof pushActivity === 'function') {
            pushActivity('Transmitted Repeater request to Repro Shell as curl command', 'info');
        }
    }
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
    
    // Initialize F2 hotkey and manual efficiency panels
    initManualEfficiencyModules();
};

// ── MANUAL EFFICIENCY WORKBENCHES (KILLBOOK, STRIKE CAST, PAYLOAD LOOM, TOKEN STALKER, GREY ZONE, KILLCHAIN LOOM, GHOST PROOF) ──

// local storage states
let killbookDb = [];
let strikeCastHistory = [];
let tokenStalkerHistory = [];
let greyZoneStatus = {}; // maps ID -> { status, notes }
let killchainSteps = [];
let ghostProofCases = [];

let activeScreenshotPath = '';
let currentStrikeCastResponse = null;
let selectedLoomFinding = null;
let selectedStalkerTokenIndex = null;
let selectedGhostCaseIndex = null;

function initManualEfficiencyModules() {
    // Add global F2 listener
    window.addEventListener('keydown', (e) => {
        if (e.key === 'F2') {
            e.preventDefault();
            triggerEvidenceCapture();
        }
    });

    // Handle incoming screenshot from main process
    ipcRenderer.on('window-screenshot-response', (event, response) => {
        if (response.error) {
            alert('Screenshot capture failed: ' + response.error);
            return;
        }
        
        activeScreenshotPath = response.path;
        
        const previewContainer = document.getElementById('killbookShotPreviewContainer');
        if (previewContainer) {
            previewContainer.classList.remove('hidden');
        }
        
        const previewImg = document.getElementById('killbookShotPreview');
        if (previewImg) {
            previewImg.src = `file://${response.path}`;
        }
        
        const pathText = document.getElementById('killbookShotPathText');
        if (pathText) {
            pathText.innerText = path.basename(response.path);
        }

        const targetVal = document.getElementById('killbookTargetVal');
        if (targetVal) {
            targetVal.innerText = activeTarget || 'NO ACTIVE TARGET';
        }

        const panelVal = document.getElementById('killbookPanelVal');
        if (panelVal) {
            // Find currently active content area panel
            let activePanelName = 'Unknown Panel';
            document.querySelectorAll('.content-area').forEach(sec => {
                if (!sec.classList.contains('hidden')) {
                    const h2 = sec.querySelector('h2');
                    activePanelName = h2 ? h2.innerText.split('//')[0].trim() : sec.id.toUpperCase();
                }
            });
            panelVal.innerText = activePanelName;
        }

        const noteVal = document.getElementById('killbookNoteVal');
        if (noteVal) {
            noteVal.value = window.getSelection().toString().trim();
        }

        // Reset check boxes
        document.querySelectorAll('input[name="killbookTag"]').forEach(cb => cb.checked = false);

        const modal = document.getElementById('killbookCaptureModal');
        if (modal) {
            modal.classList.remove('hidden');
        }
    });

    // Notion Editor input / slash command listener
    const notionEditor = document.getElementById('killbookNotionEditor');
    if (notionEditor) {
        notionEditor.addEventListener('keydown', handleNotionEditorInput);
        notionEditor.addEventListener('input', saveActiveNotionNote);
    }
    
    const notionTitle = document.getElementById('killbookNotionTitle');
    if (notionTitle) {
        notionTitle.addEventListener('input', () => {
            if (activeKillbookEntryId) {
                const entry = killbookDb.find(e => e.id === activeKillbookEntryId);
                if (entry) {
                    entry.title = notionTitle.value;
                    const cardTitle = document.getElementById(`timeline_title_${activeKillbookEntryId}`);
                    if (cardTitle) {
                        cardTitle.innerText = notionTitle.value || 'Untitled Note';
                    }
                }
            }
        });
    }

    // Close slash menu when clicking outside
    window.addEventListener('click', (e) => {
        const slashMenu = document.getElementById('killbookSlashMenu');
        if (slashMenu && !e.target.closest('#killbookSlashMenu') && !e.target.closest('#killbookNotionEditor')) {
            slashMenu.classList.add('hidden');
        }
    });

    // Populate initial Killchain step
    addKillchainStep();
}

function triggerEvidenceCapture() {
    ipcRenderer.send('window-screenshot');
}

function openManualNoteModal() {
    activeScreenshotPath = null;
    
    const previewContainer = document.getElementById('killbookShotPreviewContainer');
    if (previewContainer) {
        previewContainer.classList.add('hidden');
    }
    
    const targetVal = document.getElementById('killbookTargetVal');
    if (targetVal) {
        targetVal.innerText = activeTarget || 'NO ACTIVE TARGET';
    }

    const panelVal = document.getElementById('killbookPanelVal');
    if (panelVal) {
        let activePanelName = 'Unknown Panel';
        document.querySelectorAll('.content-area').forEach(sec => {
            if (!sec.classList.contains('hidden')) {
                const h2 = sec.querySelector('h2');
                activePanelName = h2 ? h2.innerText.split('//')[0].trim() : sec.id.toUpperCase();
            }
        });
        panelVal.innerText = activePanelName;
    }

    const noteVal = document.getElementById('killbookNoteVal');
    if (noteVal) {
        noteVal.value = '';
    }

    // Reset checkboxes
    document.querySelectorAll('input[name="killbookTag"]').forEach(cb => cb.checked = false);

    const modal = document.getElementById('killbookCaptureModal');
    if (modal) {
        modal.classList.remove('hidden');
    }
}

function closeKillbookModal() {
    const modal = document.getElementById('killbookCaptureModal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

function saveKillbookEvidence() {
    const note = document.getElementById('killbookNoteVal').value;
    const target = document.getElementById('killbookTargetVal').innerText;
    const panel = document.getElementById('killbookPanelVal').innerText;
    const tags = [];
    document.querySelectorAll('input[name="killbookTag"]:checked').forEach(cb => {
        tags.push(cb.value);
    });

    const titleText = activeScreenshotPath ? `Screenshot - ${panel}` : `Note - ${panel}`;
    const noteHtml = `<p>${note.replace(/\n/g, '<br>') || 'Empty note content'}</p>`;

    const evidence = {
        id: 'ev_' + Date.now(),
        title: titleText,
        timestamp: new Date().toISOString(),
        target: target,
        panel: panel,
        screenshot: activeScreenshotPath,
        note: noteHtml,
        tags: tags
    };

    killbookDb.unshift(evidence);
    closeKillbookModal();
    renderKillbookTimeline();
    
    // Auto-select the newly added note in the editor workspace
    viewKillbookDetail(evidence);
    
    activeScreenshotPath = null;
    pushActivity('Evidence captured to Killbook', 'success');
}

function createNewKillbookNote() {
    const newNote = {
        id: 'ev_' + Date.now(),
        title: 'New Note',
        timestamp: new Date().toISOString(),
        target: activeTarget || 'NO ACTIVE TARGET',
        panel: 'Killbook',
        screenshot: null,
        note: '<p>Type "/" for commands or just start typing...</p>',
        tags: []
    };
    killbookDb.unshift(newNote);
    activeKillbookEntryId = newNote.id;
    renderKillbookTimeline();
    
    // Focus the editor immediately and highlight text to overwrite
    const editor = document.getElementById('killbookNotionEditor');
    if (editor) {
        editor.focus();
        const range = document.createRange();
        range.selectNodeContents(editor);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
    }
}

function renderKillbookTimeline() {
    const list = document.getElementById('killbookTimelineList');
    list.innerHTML = '';
    
    if (killbookDb.length === 0) {
        // Initialize default note if empty so there is always a workspace note to write in
        const defaultNote = {
            id: 'ev_' + Date.now(),
            title: 'Pentest Session Notes',
            timestamp: new Date().toISOString(),
            target: activeTarget || 'NO ACTIVE TARGET',
            panel: 'Killbook',
            screenshot: null,
            note: '<p>Type "/" for commands or just start typing notes here...</p>',
            tags: []
        };
        killbookDb.push(defaultNote);
    }

    if (!activeKillbookEntryId && killbookDb.length > 0) {
        activeKillbookEntryId = killbookDb[0].id;
    }

    killbookDb.forEach(ev => {
        const div = document.createElement('div');
        div.className = `p-4 bg-white/5 border border-white/10 rounded cursor-pointer hover:bg-white/10 transition-all space-y-2 ${activeKillbookEntryId === ev.id ? 'border-primary bg-primary/5' : ''}`;
        
        const tagSpans = ev.tags.map(t => `<span class="px-1.5 py-0.5 border border-primary/30 text-primary text-[7px] uppercase font-bold rounded">${t}</span>`).join(' ');
        
        div.innerHTML = `
            <div class="flex justify-between items-center text-[8px] text-white/40">
                <div class="flex items-center gap-1.5 text-white/40">
                    <span>${ev.timestamp.split('T')[1].substring(0, 8)} // ${ev.panel}</span>
                    ${ev.screenshot ? `<span class="material-symbols-outlined text-[10px] text-primary" title="Screenshot Attached">photo_library</span>` : ''}
                </div>
                <span class="text-primary font-bold uppercase truncate max-w-[100px]">${ev.target}</span>
            </div>
            <div id="timeline_title_${ev.id}" class="font-bold text-[10px] text-white truncate">${ev.title || 'Untitled Note'}</div>
            <p id="timeline_preview_${ev.id}" class="text-[9px] text-white/55 line-clamp-1">${ev.note ? ev.note.replace(/<[^>]*>/g, '').substring(0, 50) : '[No descriptive text notes]'}</p>
            <div class="flex justify-between items-center pt-2 border-t border-white/5">
                <span class="text-[8px] text-white/30 truncate max-w-[150px]">${ev.screenshot ? path.basename(ev.screenshot) : 'No Image'}</span>
                <div class="flex gap-1">${tagSpans}</div>
            </div>
        `;
        div.onclick = () => viewKillbookDetail(ev);
        list.appendChild(div);
    });

    const activeNote = killbookDb.find(e => e.id === activeKillbookEntryId) || killbookDb[0];
    if (activeNote) {
        viewKillbookDetail(activeNote);
    }
}

function viewKillbookDetail(ev) {
    activeKillbookEntryId = ev.id;
    
    // Highlight correct timeline item
    document.querySelectorAll('#killbookTimelineList > div').forEach((child, index) => {
        const targetEntry = killbookDb[index];
        if (targetEntry && targetEntry.id === ev.id) {
            child.classList.add('border-primary', 'bg-primary/5');
        } else {
            child.classList.remove('border-primary', 'bg-primary/5');
        }
    });

    // Hide static view panel, show Notion workspace
    const detailViewer = document.getElementById('killbookDetailViewer');
    if (detailViewer) detailViewer.classList.add('hidden');
    
    const workspace = document.getElementById('killbookWorkspace');
    if (workspace) workspace.classList.remove('hidden');
    
    const titleInput = document.getElementById('killbookNotionTitle');
    if (titleInput && document.activeElement !== titleInput) {
        titleInput.value = ev.title || '';
    }
    
    const metaSpan = document.getElementById('killbookNotionMeta');
    if (metaSpan) {
        metaSpan.innerText = `Target: ${ev.target} // Panel: ${ev.panel}`;
    }
    
    const dateSpan = document.getElementById('killbookNotionDate');
    if (dateSpan) {
        dateSpan.innerText = new Date(ev.timestamp).toLocaleString();
    }
    
    const editor = document.getElementById('killbookNotionEditor');
    if (editor && document.activeElement !== editor) {
        editor.innerHTML = ev.note || '<p><br></p>';
    }
    
    const bundleBtn = document.getElementById('killbookBundleBtn');
    if (bundleBtn) {
        if (ev.screenshot) {
            bundleBtn.classList.remove('hidden');
            bundleBtn.onclick = () => openKillbookLightbox(ev.screenshot);
        } else {
            bundleBtn.classList.add('hidden');
        }
    }
    
    const tagsContainer = document.getElementById('killbookTagsContainer');
    if (tagsContainer) {
        tagsContainer.innerHTML = ev.tags.map(t => `<span class="px-2 py-0.5 border border-primary text-primary text-[8px] uppercase font-bold rounded">${t}</span>`).join(' ');
    }
}

function clearKillbook() {
    if (confirm('Are you sure you want to clear the Killbook evidence? This will not delete saved images on disk.')) {
        killbookDb = [];
        activeKillbookEntryId = null;
        renderKillbookTimeline();
        
        const detailViewer = document.getElementById('killbookDetailViewer');
        if (detailViewer) {
            detailViewer.classList.remove('hidden');
            detailViewer.innerHTML = 'Select an entry from the timeline to open the Notion-style workspace.';
        }
        
        const workspace = document.getElementById('killbookWorkspace');
        if (workspace) workspace.classList.add('hidden');
        
        pushActivity('Killbook evidence database purged', 'info');
    }
}

// Notion-style slash commands and rich formatting helpers
function handleNotionEditorInput(e) {
    const editor = document.getElementById('killbookNotionEditor');
    
    // Track cursor text context
    const selection = window.getSelection();
    if (!selection.rangeCount) return;
    
    const range = selection.getRangeAt(0);
    const node = range.startContainer;
    
    let blockNode = node;
    while (blockNode && blockNode.parentNode !== editor) {
        blockNode = blockNode.parentNode;
    }
    
    if (!blockNode) return;
    
    const blockText = blockNode.textContent || '';
    
    // Slash commands checking
    if (blockText.endsWith('/h1 ')) {
        e.preventDefault();
        transformCurrentBlock(blockNode, 'h1');
    } else if (blockText.endsWith('/h2 ')) {
        e.preventDefault();
        transformCurrentBlock(blockNode, 'h2');
    } else if (blockText.endsWith('/h3 ')) {
        e.preventDefault();
        transformCurrentBlock(blockNode, 'h3');
    } else if (blockText.endsWith('/bullet ')) {
        e.preventDefault();
        transformCurrentBlock(blockNode, 'bullet');
    } else if (blockText.endsWith('/code ')) {
        e.preventDefault();
        transformCurrentBlock(blockNode, 'code');
    } else if (blockText.endsWith('/quote ')) {
        e.preventDefault();
        transformCurrentBlock(blockNode, 'quote');
    }
    
    // Pop up list if user ends line with /
    const slashMenu = document.getElementById('killbookSlashMenu');
    if (blockText.endsWith('/')) {
        positionSlashMenu(range, slashMenu);
    } else {
        if (slashMenu) slashMenu.classList.add('hidden');
    }
    
    saveActiveNotionNote();
}

function transformCurrentBlock(blockNode, type) {
    let cleanText = blockNode.textContent.replace(/\/h1\s*|\/h2\s*|\/h3\s*|\/bullet\s*|\/code\s*|\/quote\s*/gi, '').trim();
    if (cleanText === '') cleanText = ' ';
    
    let newElement;
    if (type === 'h1') {
        newElement = document.createElement('h1');
        newElement.textContent = cleanText;
    } else if (type === 'h2') {
        newElement = document.createElement('h2');
        newElement.textContent = cleanText;
    } else if (type === 'h3') {
        newElement = document.createElement('h3');
        newElement.textContent = cleanText;
    } else if (type === 'bullet') {
        newElement = document.createElement('ul');
        const li = document.createElement('li');
        li.textContent = cleanText;
        newElement.appendChild(li);
    } else if (type === 'code') {
        newElement = document.createElement('pre');
        newElement.textContent = cleanText;
    } else if (type === 'quote') {
        newElement = document.createElement('blockquote');
        newElement.textContent = cleanText;
    } else {
        newElement = document.createElement('div');
        newElement.textContent = cleanText;
    }
    
    blockNode.parentNode.replaceChild(newElement, blockNode);
    
    // Set focus inside the new element
    const selection = window.getSelection();
    const range = document.createRange();
    
    if (newElement.firstChild && newElement.firstChild.nodeType === Node.ELEMENT_NODE) {
        range.selectNodeContents(newElement.firstChild);
    } else {
        range.selectNodeContents(newElement);
    }
    
    range.collapse(false);
    selection.removeAllRanges();
    selection.addRange(range);
    
    const slashMenu = document.getElementById('killbookSlashMenu');
    if (slashMenu) slashMenu.classList.add('hidden');
    
    saveActiveNotionNote();
}

function insertNotionBlock(type) {
    const editor = document.getElementById('killbookNotionEditor');
    editor.focus();
    
    const selection = window.getSelection();
    if (!selection.rangeCount) return;
    
    const range = selection.getRangeAt(0);
    const node = range.startContainer;
    
    let blockNode = node;
    while (blockNode && blockNode.parentNode !== editor) {
        blockNode = blockNode.parentNode;
    }
    
    if (!blockNode) {
        const p = document.createElement('p');
        p.textContent = '/';
        editor.appendChild(p);
        blockNode = p;
    }
    
    transformCurrentBlock(blockNode, type);
}

function positionSlashMenu(range, menu) {
    if (!menu) return;
    
    const rect = range.getBoundingClientRect();
    const editor = document.getElementById('killbookNotionEditor');
    const editorRect = editor.getBoundingClientRect();
    
    const top = rect.bottom - editorRect.top + editor.scrollTop + 8;
    const left = rect.left - editorRect.left;
    
    menu.style.top = `${top}px`;
    menu.style.left = `${left}px`;
    menu.classList.remove('hidden');
}

function saveActiveNotionNote() {
    if (activeKillbookEntryId) {
        const entry = killbookDb.find(e => e.id === activeKillbookEntryId);
        if (entry) {
            entry.note = document.getElementById('killbookNotionEditor').innerHTML;
        }
    }
}

function openKillbookLightbox(screenshotPath) {
    const lightbox = document.getElementById('killbookLightboxModal');
    const img = document.getElementById('killbookLightboxImage');
    const pathText = document.getElementById('killbookLightboxPath');
    
    if (lightbox && img) {
        img.src = `file://${screenshotPath}`;
        if (pathText) {
            pathText.innerText = `Path: ${screenshotPath}`;
        }
        lightbox.classList.remove('hidden');
    }
}

function closeKillbookLightbox() {
    const lightbox = document.getElementById('killbookLightboxModal');
    if (lightbox) {
        lightbox.classList.add('hidden');
    }
}

function htmlToMarkdown(html) {
    if (!html) return '';
    let md = html;
    md = md.replace(/<h1>([\s\S]*?)<\/h1>/gi, '# $1\n');
    md = md.replace(/<h2>([\s\S]*?)<\/h2>/gi, '## $1\n');
    md = md.replace(/<h3>([\s\S]*?)<\/h3>/gi, '### $1\n');
    md = md.replace(/<blockquote>([\s\S]*?)<\/blockquote>/gi, '> $1\n');
    md = md.replace(/<pre>([\s\S]*?)<\/pre>/gi, '```text\n$1\n```\n');
    md = md.replace(/<ul>([\s\S]*?)<\/ul>/gi, '$1');
    md = md.replace(/<li>([\s\S]*?)<\/li>/gi, '- $1\n');
    md = md.replace(/<p>([\s\S]*?)<\/p>/gi, '$1\n');
    md = md.replace(/<div>([\s\S]*?)<\/div>/gi, '$1\n');
    md = md.replace(/<br\s*\/?>/gi, '\n');
    md = md.replace(/<[^>]*>/g, '');
    
    // Clean up empty lines or duplicate spaces
    md = md.split('\n').map(line => line.trim()).filter((line, i, arr) => {
        return line !== '' || (i > 0 && arr[i-1] !== '');
    }).join('\n');
    
    const txt = document.createElement('textarea');
    txt.innerHTML = md;
    return txt.value.trim();
}

function exportKillbookReport() {
    if (killbookDb.length === 0) {
        alert('Killbook database is empty. No findings to export.');
        return;
    }

    let report = `# HELLHOUND VULNERABILITY PENTEST REPORT\n`;
    report += `Generated: ${new Date().toLocaleString()}\n`;
    report += `Target: ${activeTarget || 'Multiple Targets'}\n\n`;
    report += `---\n\n`;

    killbookDb.forEach(ev => {
        report += `### [${ev.panel}] Finding - ${ev.id}\n`;
        report += `- **Timestamp:** ${ev.timestamp}\n`;
        report += `- **Active Host:** ${ev.target}\n`;
        report += `- **Tags:** ${ev.tags.join(', ') || 'None'}\n\n`;
        
        const markdownNotes = htmlToMarkdown(ev.note);
        report += `#### Findings Notes\n${markdownNotes || 'No notes description provided.'}\n\n`;
        
        if (ev.screenshot) {
            report += `#### Captured Evidence\n![Evidence Screenshot](file://${ev.screenshot})\n\n`;
        }
        report += `---\n\n`;
    });

    ipcRenderer.send('export-session', {
        filename: `Killbook_Report_${Date.now()}.md`,
        content: report
    });
    pushActivity('Pushed Killbook evidence to Markdown report', 'success');
}

// ── STRIKE CAST CONTROLLER ──
function executeStrikeCast() {
    const input = document.getElementById('strikeCastInput').value.trim();
    if (!input) return;

    const headersArea = document.getElementById('strikeCastHeaders');
    const bodyArea = document.getElementById('strikeCastBody');

    headersArea.innerText = 'Routing native requests...';
    bodyArea.innerText = 'Blasting TCP payload packet streams...';

    // Parse command line
    let method = 'GET';
    let url = '';
    let body = '';
    const headers = {};

    const methodMatch = input.match(/^(GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH|TRACE)\b/i);
    let restOfLine = input;
    if (methodMatch) {
        method = methodMatch[1].toUpperCase();
        restOfLine = input.substring(methodMatch[0].length).trim();
    }

    // Extract -H headers
    const headerRegex = /-H\s+['"]([^'"]+)['"]/g;
    let match;
    const headerLines = [];
    while ((match = headerRegex.exec(input)) !== null) {
        headerLines.push(match[1]);
    }
    // Remove headers from parse URL line
    restOfLine = restOfLine.replace(/-H\s+['"]([^'"]+)['"]/g, '').trim();

    // Extract -d body
    const bodyMatch = restOfLine.match(/-d\s+['"]([^'"]+)['"]/);
    if (bodyMatch) {
        body = bodyMatch[1];
        restOfLine = restOfLine.replace(/-d\s+['"]([^'"]+)['"]/, '').trim();
    } else {
        const bodyMatchNoQuote = restOfLine.match(/-d\s+(\S+)/);
        if (bodyMatchNoQuote) {
            body = bodyMatchNoQuote[1];
            restOfLine = restOfLine.replace(/-d\s+(\S+)/, '').trim();
        }
    }

    // URL is whatever is left
    url = restOfLine.trim().split(/\s+/)[0];
    // Remove trailing quotes if URL was wrapped
    url = url.replace(/^['"]|['"]$/g, '');

    if (!url) {
        headersArea.innerText = 'Error parsing parameters';
        bodyArea.innerText = 'Could not isolate destination target URL.';
        return;
    }

    // Append standard headers
    headerLines.forEach(line => {
        const parts = line.split(':');
        if (parts.length >= 2) {
            headers[parts[0].trim()] = parts.slice(1).join(':').trim();
        }
    });

    // Native requests engine using Node http/https
    try {
        const urlObj = new URL(url);
        const isHttps = urlObj.protocol === 'https:';
        const client = isHttps ? require('https') : require('http');

        const requestOptions = {
            method: method,
            hostname: urlObj.hostname,
            port: urlObj.port || (isHttps ? 443 : 80),
            path: urlObj.pathname + urlObj.search,
            headers: headers
        };

        if (body) {
            requestOptions.headers['Content-Length'] = Buffer.byteLength(body);
        }

        const req = client.request(requestOptions, (res) => {
            let resBody = '';
            
            res.on('data', (chunk) => { resBody += chunk; });
            
            res.on('end', () => {
                let responseHeadersText = `HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage}\n`;
                for (const [k, v] of Object.entries(res.headers)) {
                    responseHeadersText += `${k}: ${v}\n`;
                }

                headersArea.innerText = responseHeadersText;
                
                try {
                    const parsed = JSON.parse(resBody);
                    bodyArea.innerText = JSON.stringify(parsed, null, 2);
                } catch (_) {
                    bodyArea.innerText = resBody;
                }

                currentStrikeCastResponse = {
                    request: {
                        method: method,
                        url: url,
                        headers: headers,
                        body: body
                    },
                    response: {
                        status: res.statusCode,
                        headers: res.headers,
                        body: resBody
                    }
                };

                // Add to history
                strikeCastHistory.unshift({
                    input: input,
                    timestamp: new Date().toISOString()
                });
            });
        });

        req.on('error', (err) => {
            headersArea.innerText = 'Connection Error';
            bodyArea.innerText = err.message;
        });

        if (body) {
            req.write(body);
        }
        req.end();

    } catch (e) {
        headersArea.innerText = 'Parsing failure';
        bodyArea.innerText = e.message;
    }
}

function sendStrikeCastToKillbook() {
    if (!currentStrikeCastResponse) {
        alert('No response loaded inside Strike Cast. Blast a target first.');
        return;
    }

    const note = `### STRIKE CAST Blast log\n` +
                 `**Command Input:** \`${document.getElementById('strikeCastInput').value}\`\n\n` +
                 `#### Request details:\n` +
                 `- **Method:** ${currentStrikeCastResponse.request.method}\n` +
                 `- **URL:** ${currentStrikeCastResponse.request.url}\n` +
                 `- **Payload:** \`${currentStrikeCastResponse.request.body || 'None'}\`\n\n` +
                 `#### Response status: ${currentStrikeCastResponse.response.status}\n` +
                 `\`\`\`json\n${currentStrikeCastResponse.response.body.substring(0, 1000)}\n\`\`\``;

    const evidence = {
        id: 'ev_' + Date.now(),
        timestamp: new Date().toISOString(),
        target: activeTarget || 'Strike Cast Host',
        panel: 'STRIKE CAST',
        screenshot: '',
        note: note,
        tags: ['PoC']
    };

    killbookDb.unshift(evidence);
    renderKillbookTimeline();
    pushActivity('Strike Cast session findings exported to Killbook', 'success');
}

function saveStrikeCastAsTestCase() {
    if (!currentStrikeCastResponse) {
        alert('Blast a target first before saving as test case!');
        return;
    }

    const namePrompt = prompt('Enter a name for this regression test case:', `Retest ${currentStrikeCastResponse.request.method} - ${currentStrikeCastResponse.request.url.substring(0,30)}`);
    if (!namePrompt) return;

    const testCase = {
        name: namePrompt,
        request: currentStrikeCastResponse.request,
        expected: {
            status: currentStrikeCastResponse.response.status,
            body: currentStrikeCastResponse.response.body
        },
        matchRule: 'status',
        matchValue: String(currentStrikeCastResponse.response.status),
        target: activeTarget || 'Default Target'
    };

    ghostProofCases.push(testCase);
    renderGhostProofSuite();
    pushActivity(`Saved Ghost Proof regression test case: ${namePrompt}`, 'success');
}

// ── PAYLOAD LOOM CONTROLLER ──
function syncPayloadLoomFindings() {
    const list = document.getElementById('payloadLoomFindingsList');
    list.innerHTML = '';

    if (!lastIntelTargets || lastIntelTargets.length === 0) {
        list.innerHTML = '<div class="text-white/20 italic text-[10px] font-data-mono">No vulnerabilities detected inside Intel Center.</div>';
        return;
    }

    lastIntelTargets.forEach(t => {
        const div = document.createElement('div');
        const isSelected = selectedLoomFinding && selectedLoomFinding.id === t.id;
        
        div.className = `p-3 bg-white/5 border border-white/10 rounded cursor-pointer hover:bg-white/10 transition-all ${isSelected ? 'border-primary' : ''}`;
        div.innerHTML = `
            <div class="flex justify-between items-center text-[8px] text-white/30">
                <span>${t.module}</span>
                <span class="text-primary font-bold uppercase">${t.severity}</span>
            </div>
            <h4 class="text-[10px] text-white uppercase font-bold mt-1">${t.type}</h4>
            <p class="text-[9px] text-white/50 truncate">${t.url}</p>
        `;
        div.onclick = () => selectLoomFinding(t, div);
        list.appendChild(div);
    });
}

function selectLoomFinding(t, element) {
    selectedLoomFinding = t;
    
    document.querySelectorAll('#payloadLoomFindingsList > div').forEach(div => {
        div.classList.remove('border-primary');
    });
    if (element) element.classList.add('border-primary');

    // Correlate parameters and construct exploit
    let method = 'GET';
    let url = t.url;
    let postData = '';
    let sessionVar = 'session=forged_admin_token';
    let csrfVar = 'csrf_token_value';

    // Parse template structures
    let compiledCurl = `curl -X ${method} '${url}' \\\n  -H 'Cookie: ${sessionVar}' \\\n  -H 'X-CSRF-Token: ${csrfVar}'`;
    if (method === 'POST') {
        compiledCurl += ` \\\n  --data '${postData}'`;
    }

    document.getElementById('payloadLoomEditor').value = compiledCurl;
    pushActivity(`Compiled exploit template for ${t.type}`, 'info');
}

function testCompiledPayload() {
    const cmd = document.getElementById('payloadLoomEditor').value;
    const outputArea = document.getElementById('payloadLoomOutput');

    outputArea.innerText = 'Executing exploit test vector...';

    // Parse curl command dynamically
    let method = 'GET';
    const methodMatch = cmd.match(/-X\s+(\S+)/);
    if (methodMatch) method = methodMatch[1].replace(/['"]/g, '').toUpperCase();

    let url = '';
    const urlMatches = cmd.match(/(?:['"])(https?:\/\/[^\s'"]+)/) || cmd.match(/(https?:\/\/[^\s'"]+)/);
    if (urlMatches) url = urlMatches[1];

    if (!url) {
        outputArea.innerText = 'Could not parse target URL from exploit template.';
        return;
    }

    const headers = {};
    const headerRegex = /-H\s+['"]([^'"]+)['"]/g;
    let match;
    while ((match = headerRegex.exec(cmd)) !== null) {
        const parts = match[1].split(':');
        if (parts.length >= 2) {
            headers[parts[0].trim()] = parts.slice(1).join(':').trim();
        }
    }

    let data = '';
    const dataMatch = cmd.match(/--data\s+['"]([^'"]+)['"]/);
    if (dataMatch) data = dataMatch[1];

    try {
        const urlObj = new URL(url);
        const isHttps = urlObj.protocol === 'https:';
        const client = isHttps ? require('https') : require('http');

        const options = {
            method: method,
            hostname: urlObj.hostname,
            port: urlObj.port || (isHttps ? 443 : 80),
            path: urlObj.pathname + urlObj.search,
            headers: headers
        };

        const req = client.request(options, (res) => {
            let resBody = '';
            res.on('data', (c) => { resBody += c; });
            res.on('end', () => {
                outputArea.innerText = `[Exploit response] Status: ${res.statusCode}\n\n${resBody.substring(0, 2000)}`;
            });
        });

        req.on('error', (err) => {
            outputArea.innerText = `Connection failed: ${err.message}`;
        });

        if (data) req.write(data);
        req.end();

    } catch (e) {
        outputArea.innerText = `Error compiling request details: ${e.message}`;
    }
}

function saveLoomExploitToKillbook() {
    const editorVal = document.getElementById('payloadLoomEditor').value;
    const outputVal = document.getElementById('payloadLoomOutput').innerText;

    if (!editorVal) {
        alert('Exploit editor is empty.');
        return;
    }

    const note = `### Compiled Exploit Vector\n` +
                 `\`\`\`shell\n${editorVal}\n\`\`\`\n\n` +
                 `#### Test Response Output:\n` +
                 `\`\`\`text\n${outputVal}\n\`\`\``;

    const evidence = {
        id: 'ev_' + Date.now(),
        timestamp: new Date().toISOString(),
        target: activeTarget || 'Loom Exploit Target',
        panel: 'PAYLOAD LOOM',
        screenshot: '',
        note: note,
        tags: ['PoC', 'Critical']
    };

    killbookDb.unshift(evidence);
    renderKillbookTimeline();
    pushActivity('Loom exploit vector compiled directly to Killbook', 'success');
}

// ── TOKEN STALKER CONTROLLER ──
function stalkTokens() {
    const text = document.getElementById('tokenStalkerInput').value;
    const list = document.getElementById('stalkerTokensGrid');
    list.innerHTML = '';

    const discovered = [];

    // JWT regex
    const jwtRegex = /\bey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g;
    let match;
    while ((match = jwtRegex.exec(text)) !== null) {
        discovered.push({ type: 'JWT', raw: match[0] });
    }

    // Base64 regex
    const b64Regex = /\b[a-zA-Z0-9+/]{40,}=*\b/g;
    while ((match = b64Regex.exec(text)) !== null) {
        discovered.push({ type: 'Base64', raw: match[0] });
    }

    // Hex strings
    const hexRegex = /\b[a-fA-F0-9]{32,64}\b/g;
    while ((match = hexRegex.exec(text)) !== null) {
        discovered.push({ type: 'Hex', raw: match[0] });
    }

    // Cookies
    const cookieRegex = /(?:cookie|set-cookie):\s*([^;\r\n]+)/gi;
    while ((match = cookieRegex.exec(text)) !== null) {
        discovered.push({ type: 'Cookie', raw: match[1] });
    }

    if (discovered.length === 0) {
        list.innerHTML = '<div class="text-white/20 italic text-[10px] font-data-mono">No structures isolated in pasted input text.</div>';
        return;
    }

    discovered.forEach((item, index) => {
        const div = document.createElement('div');
        div.className = 'p-3 bg-white/5 border border-white/10 rounded cursor-pointer hover:bg-white/10 transition-all';
        div.innerHTML = `
            <div class="flex justify-between items-center text-[8px]">
                <span class="text-[#00ffc4] uppercase font-bold">${item.type}</span>
            </div>
            <p class="font-data-mono text-[9px] text-white/70 truncate mt-1">${item.raw}</p>
        `;
        div.onclick = () => decodeStalkerToken(item, index);
        list.appendChild(div);
    });
}

function decodeStalkerToken(item, index) {
    selectedStalkerTokenIndex = index;
    const decodedArea = document.getElementById('stalkerDecoded');
    const encodedArea = document.getElementById('stalkerEncoded');

    try {
        if (item.type === 'JWT') {
            const parts = item.raw.split('.');
            const header = Buffer.from(parts[0], 'base64').toString('utf8');
            const payload = Buffer.from(parts[1], 'base64').toString('utf8');
            
            const structured = {
                header: JSON.parse(header),
                payload: JSON.parse(payload)
            };
            decodedArea.value = JSON.stringify(structured, null, 2);
        } else if (item.type === 'Base64') {
            decodedArea.value = Buffer.from(item.raw, 'base64').toString('utf8');
        } else if (item.type === 'Hex') {
            decodedArea.value = Buffer.from(item.raw, 'hex').toString('utf8');
        } else {
            decodedArea.value = item.raw;
        }
    } catch (e) {
        decodedArea.value = `Decoding failure: ${e.message}\nRaw: ${item.raw}`;
    }
    encodedArea.value = '';
}

function reencodeStalkerToken() {
    const decoded = document.getElementById('stalkerDecoded').value;
    const encodedArea = document.getElementById('stalkerEncoded');

    try {
        // Simple base64 re-encode fallback
        const base64url = (str) => Buffer.from(str).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        
        // Attempt parsing JSON
        try {
            const parsed = JSON.parse(decoded);
            if (parsed.header && parsed.payload) {
                // Construct forged JWT none
                const forgedHdr = base64url(JSON.stringify(Object.assign({}, parsed.header, { alg: 'none' })));
                const forgedPay = base64url(JSON.stringify(parsed.payload));
                encodedArea.value = `${forgedHdr}.${forgedPay}.`;
                return;
            }
        } catch (_) {}

        encodedArea.value = Buffer.from(decoded).toString('base64');
        pushActivity('Token re-encoded to output buffer', 'success');

    } catch (e) {
        encodedArea.value = 'Failed encoding: ' + e.message;
    }
}

function sendStalkerTokenToStrikeCast() {
    const val = document.getElementById('stalkerEncoded').value.trim();
    if (!val) {
        alert('Sign or Re-encode a token first!');
        return;
    }

    showSection('strikecast', document.querySelector('[onclick*="showSection(\'strikecast\'"]'));
    document.getElementById('strikeCastInput').value = `GET ${activeTarget || 'https://target.com/'} -H "Cookie: session=${val}"`;
    pushActivity('Stalker cookie injected to Strike Cast input line', 'info');
}

// ── GREY ZONE CONTROLLER ──
function syncGreyZoneTable() {
    const tbody = document.getElementById('greyZoneTableBody');
    tbody.innerHTML = '';

    const filterVal = document.getElementById('greyZoneFilter').value;

    if (!lastIntelTargets || lastIntelTargets.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="py-6 text-center text-white/20 italic">No targets cataloged inside Intel Center.</td></tr>`;
        return;
    }

    lastIntelTargets.forEach(t => {
        // Sync state map key
        if (!greyZoneStatus[t.id]) {
            greyZoneStatus[t.id] = { status: 'Not Tested', notes: '' };
        }

        const state = greyZoneStatus[t.id];

        if (filterVal === 'PENDING' && state.status !== 'Not Tested') {
            return;
        }

        const row = document.createElement('div');
        row.className = 'grid grid-cols-12 gap-4 px-6 py-4 hover:bg-white/5 items-center transition-all';
        row.innerHTML = `
            <div class="col-span-3 text-white uppercase font-bold text-[10px] truncate" title="${t.type}">${t.type}</div>
            <div class="col-span-1 text-[9px] uppercase font-bold tracking-widest text-primary">${t.severity}</div>
            <div class="col-span-3 text-white/50 truncate text-[9px]" title="${t.url}">${t.url}</div>
            <div class="col-span-2">
                <select onchange="updateGreyZoneStatus('${t.id}', this.value)" class="bg-black border border-white/10 font-label-surgical text-[9px] text-white/80 p-1.5 rounded focus:outline-none w-full">
                    <option value="Not Tested" ${state.status === 'Not Tested' ? 'selected' : ''}>Not Tested</option>
                    <option value="Tested - Exploitable" ${state.status === 'Tested - Exploitable' ? 'selected' : ''}>Tested - Exploitable</option>
                    <option value="Tested - Not Exploitable" ${state.status === 'Tested - Not Exploitable' ? 'selected' : ''}>Tested - Not Exploitable</option>
                    <option value="False Positive" ${state.status === 'False Positive' ? 'selected' : ''}>False Positive</option>
                    <option value="Needs Retest" ${state.status === 'Needs Retest' ? 'selected' : ''}>Needs Retest</option>
                </select>
            </div>
            <div class="col-span-3 flex gap-2">
                <input type="text" value="${state.notes}" onchange="updateGreyZoneNotes('${t.id}', this.value)" class="bg-black/40 border border-white/5 font-data-mono text-[9px] text-white/80 px-2 py-1 focus:outline-none rounded flex-grow" placeholder="Add validation logs...">
                <button onclick="launchPayloadLoomFromGrey('${t.id}')" class="text-[#00ffc4] hover:underline uppercase text-[8px] font-label-surgical">Loom</button>
            </div>
        `;
        tbody.appendChild(row);
    });
}

function updateGreyZoneStatus(id, val) {
    if (!greyZoneStatus[id]) greyZoneStatus[id] = { status: 'Not Tested', notes: '' };
    greyZoneStatus[id].status = val;
    pushActivity(`Vulnerability verification status updated`, 'info');
}

function updateGreyZoneNotes(id, val) {
    if (!greyZoneStatus[id]) greyZoneStatus[id] = { status: 'Not Tested', notes: '' };
    greyZoneStatus[id].notes = val;
}

function launchPayloadLoomFromGrey(id) {
    const finding = lastIntelTargets.find(t => t.id === id);
    if (!finding) return;

    showSection('payloadloom', document.querySelector('[onclick*="showSection(\'payloadloom\'"]'));
    selectLoomFinding(finding);
}

function exportGreyZoneReport() {
    let report = `# GREY ZONE - MANUAL TEST COVERAGE REPORT\n`;
    report += `Audit Date: ${new Date().toLocaleDateString()}\n`;
    report += `Scope Target: ${activeTarget || 'Hellhound Pentest Target'}\n\n`;
    report += `| Finding | Severity | Target URL | Verification Status | Verification Notes |\n`;
    report += `| --- | --- | --- | --- | --- |\n`;

    lastIntelTargets.forEach(t => {
        const state = greyZoneStatus[t.id] || { status: 'Not Tested', notes: '' };
        report += `| ${t.type} | ${t.severity} | ${t.url} | **${state.status}** | ${state.notes || 'N/A'} |\n`;
    });

    ipcRenderer.send('export-session', {
        filename: `GreyZone_Coverage_Report_${Date.now()}.md`,
        content: report
    });
    pushActivity('Pushed Grey Zone verification coverage report', 'success');
}

// ── KILLCHAIN LOOM CONTROLLER ──
function addKillchainStep() {
    const list = document.getElementById('killchainStepsList');
    const stepIndex = killchainSteps.length + 1;

    const div = document.createElement('div');
    div.className = 'p-4 bg-white/5 border border-white/10 rounded flex flex-col gap-3 relative';
    div.id = `killchainStep_${stepIndex}`;
    
    div.innerHTML = `
        <div class="flex justify-between items-center" style="flex-shrink:0;">
            <span class="font-h2-tactical text-[9px] text-[#00ffc4] uppercase tracking-wider">Step ${stepIndex}</span>
            <button onclick="removeKillchainStep(${stepIndex})" class="text-white/20 hover:text-primary transition-colors material-symbols-outlined text-[14px]">delete</button>
        </div>
        <div class="flex flex-col gap-2">
            <input type="text" class="bg-black border border-white/5 font-data-mono text-[9px] text-white px-2 py-1.5 focus:outline-none rounded w-full" placeholder="POST https://example.com/api/login" id="killchainMethodUrl_${stepIndex}">
            <textarea class="bg-black border border-white/5 font-data-mono text-[9px] text-white/80 p-2 focus:outline-none rounded w-full h-12 resize-none" placeholder="Headers (e.g. Content-Type: application/json)" id="killchainHeaders_${stepIndex}"></textarea>
            <input type="text" class="bg-black border border-white/5 font-data-mono text-[9px] text-white/80 px-2 py-1.5 focus:outline-none rounded w-full" placeholder="Request body / parameters (e.g. user=admin)" id="killchainBody_${stepIndex}">
            <input type="text" class="bg-black/60 border border-white/5 font-data-mono text-[9px] text-[#00ffc4] px-2 py-1 focus:outline-none rounded w-full" placeholder="JSON regex capture expression (e.g. token: '([^']+)')" id="killchainRegex_${stepIndex}">
        </div>
    `;

    list.appendChild(div);
    killchainSteps.push({
        index: stepIndex,
        methodUrl: '',
        headers: '',
        body: '',
        regex: ''
    });
}

function removeKillchainStep(index) {
    const el = document.getElementById(`killchainStep_${index}`);
    if (el) el.remove();
    killchainSteps = killchainSteps.filter(s => s.index !== index);
}

async function runKillchainLoom() {
    const consoleLog = document.getElementById('killchainConsole');
    consoleLog.innerHTML = '<div>Initialising orchestrator pipeline runner...</div>';

    let extractedVariables = {};

    for (let i = 0; i < killchainSteps.length; i++) {
        const step = killchainSteps[i];
        const idx = step.index;

        let rawMethodUrl = document.getElementById(`killchainMethodUrl_${idx}`).value.trim();
        let rawHeaders = document.getElementById(`killchainHeaders_${idx}`).value.trim();
        let rawBody = document.getElementById(`killchainBody_${idx}`).value.trim();
        let regexVal = document.getElementById(`killchainRegex_${idx}`).value.trim();

        if (!rawMethodUrl) {
            consoleLog.innerHTML += `<div class="text-primary mt-2">Error: Step ${idx} url is undefined. Execution aborted.</div>`;
            return;
        }

        // Apply string variable translations
        for (const [k, v] of Object.entries(extractedVariables)) {
            const pattern = new RegExp(`{${k}}`, 'g');
            rawMethodUrl = rawMethodUrl.replace(pattern, v);
            rawHeaders = rawHeaders.replace(pattern, v);
            rawBody = rawBody.replace(pattern, v);
        }

        consoleLog.innerHTML += `<div class="text-white/40 mt-3">// Executing Step ${idx}: ${rawMethodUrl}</div>`;

        let method = 'GET';
        let url = rawMethodUrl;
        const methodMatch = rawMethodUrl.match(/^(GET|POST|PUT|DELETE)\b/i);
        if (methodMatch) {
            method = methodMatch[1].toUpperCase();
            url = rawMethodUrl.substring(methodMatch[0].length).trim();
        }

        // Send HTTP request
        try {
            const res = await dispatchLoomRequest(method, url, rawHeaders, rawBody);
            consoleLog.innerHTML += `<div>Step ${idx} complete status code: <span class="text-white">${res.statusCode}</span></div>`;

            // Regex extraction
            if (regexVal) {
                const reg = new RegExp(regexVal);
                const regMatch = res.body.match(reg);
                if (regMatch && regMatch[1]) {
                    extractedVariables[`output_${idx}`] = regMatch[1];
                    consoleLog.innerHTML += `<div class="text-[#00ffc4]">Step ${idx} variable correlation extracted {output_${idx}}: ${regMatch[1]}</div>`;
                } else {
                    consoleLog.innerHTML += `<div class="text-yellow-400">Warning: Step ${idx} regex match yielded no captures.</div>`;
                }
            }
        } catch (err) {
            consoleLog.innerHTML += `<div class="text-primary mt-1">Step ${idx} Connection Error: ${err.message}</div>`;
            return;
        }
    }
    consoleLog.innerHTML += `<div class="text-[#00ffc4] font-bold mt-4">Pipeline execution successfully completed.</div>`;
}

function dispatchLoomRequest(method, url, rawHeaders, body) {
    return new Promise((resolve, reject) => {
        try {
            const urlObj = new URL(url);
            const isHttps = urlObj.protocol === 'https:';
            const client = isHttps ? require('https') : require('http');

            const headers = {};
            if (rawHeaders) {
                rawHeaders.split('\n').forEach(line => {
                    const p = line.split(':');
                    if (p.length >= 2) headers[p[0].trim()] = p.slice(1).join(':').trim();
                });
            }

            const options = {
                method: method,
                hostname: urlObj.hostname,
                port: urlObj.port || (isHttps ? 443 : 80),
                path: urlObj.pathname + urlObj.search,
                headers: headers
            };

            const req = client.request(options, (res) => {
                let data = '';
                res.on('data', (c) => data += c);
                res.on('end', () => {
                    resolve({ statusCode: res.statusCode, body: data });
                });
            });

            req.on('error', (e) => reject(e));
            if (body) req.write(body);
            req.end();
        } catch (e) {
            reject(e);
        }
    });
}

function exportKillchainToKillbook() {
    const timelineVal = document.getElementById('killchainConsole').innerText;
    if (!timelineVal || timelineVal.includes('RUN CHAIN')) {
        alert('Run the pipeline first to capture execution evidence.');
        return;
    }

    const note = `### Visual Exploit Killchain Execution logs\n` +
                 `\`\`\`text\n${timelineVal}\n\`\`\``;

    const evidence = {
        id: 'ev_' + Date.now(),
        timestamp: new Date().toISOString(),
        target: activeTarget || 'Killchain target',
        panel: 'KILLCHAIN LOOM',
        screenshot: '',
        note: note,
        tags: ['PoC']
    };

    killbookDb.unshift(evidence);
    renderKillbookTimeline();
    pushActivity('Visual exploit pipeline execution saved to Killbook', 'success');
}

// ── GHOST PROOF SUITE ──
function renderGhostProofSuite() {
    const list = document.getElementById('ghostProofCasesList');
    list.innerHTML = '';

    if (ghostProofCases.length === 0) {
        list.innerHTML = '<div class="text-white/20 italic text-[10px] font-data-mono">No regression tests saved yet. Save a case from Strike Cast.</div>';
        return;
    }

    ghostProofCases.forEach((tc, idx) => {
        const div = document.createElement('div');
        const isSelected = selectedGhostCaseIndex === idx;

        div.className = `p-4 bg-white/5 border border-white/10 rounded hover:bg-white/10 transition-all cursor-pointer ${isSelected ? 'border-primary' : ''}`;
        div.innerHTML = `
            <div class="flex justify-between items-center text-[8px] text-white/30 mb-1">
                <span>Rule: ${tc.matchRule}</span>
                <span class="text-primary font-bold truncate max-w-[100px]">${tc.target}</span>
            </div>
            <h4 class="text-[10px] text-white font-bold uppercase truncate">${tc.name}</h4>
            <p class="text-[9px] text-[#00ffc4]/80 truncate mt-1">${tc.request.method} ${tc.request.url}</p>
            <div class="flex gap-2 mt-3 pt-2 border-t border-white/5 justify-end">
                <button onclick="event.stopPropagation(); executeGhostRetest(${idx})" class="text-[#00ffc4] hover:underline uppercase text-[8px]">Retest</button>
            </div>
        `;
        div.onclick = () => selectGhostCase(idx);
        list.appendChild(div);
    });
}

function selectGhostCase(idx) {
    selectedGhostCaseIndex = idx;
    
    document.querySelectorAll('#ghostProofCasesList > div').forEach((div, i) => {
        if (i === idx) div.classList.add('border-primary');
        else div.classList.remove('border-primary');
    });

    const tc = ghostProofCases[idx];
    document.getElementById('ghostMatchRule').value = tc.matchRule;
    document.getElementById('ghostMatchValue').value = tc.matchValue;

    document.getElementById('ghostProofDiffOutput').innerText = `Active Test Case: ${tc.name}\nExpected status code: ${tc.expected.status}\nExpected assertion pattern: ${tc.matchValue}`;
}

function updateSelectedGhostCaseRule() {
    if (selectedGhostCaseIndex === null) return;
    ghostProofCases[selectedGhostCaseIndex].matchRule = document.getElementById('ghostMatchRule').value;
}

function updateSelectedGhostCaseMatchVal() {
    if (selectedGhostCaseIndex === null) return;
    ghostProofCases[selectedGhostCaseIndex].matchValue = document.getElementById('ghostMatchValue').value;
}

function executeGhostRetest(idx) {
    const tc = ghostProofCases[idx];
    const diffArea = document.getElementById('ghostProofDiffOutput');

    diffArea.innerText = `[Running Retest] Blasting request packet flow for: ${tc.name}...`;

    try {
        const urlObj = new URL(tc.request.url);
        const isHttps = urlObj.protocol === 'https:';
        const client = isHttps ? require('https') : require('http');

        const options = {
            method: tc.request.method,
            hostname: urlObj.hostname,
            port: urlObj.port || (isHttps ? 443 : 80),
            path: urlObj.pathname + urlObj.search,
            headers: tc.request.headers
        };

        const req = client.request(options, (res) => {
            let body = '';
            res.on('data', (c) => body += c);
            res.on('end', () => {
                let assertionPassed = false;
                let reason = '';

                if (tc.matchRule === 'status') {
                    assertionPassed = String(res.statusCode) === String(tc.matchValue);
                    reason = `Expected status: ${tc.matchValue}, Got: ${res.statusCode}`;
                } else if (tc.matchRule === 'contains') {
                    assertionPassed = body.includes(tc.matchValue);
                    reason = `Expected body substring: "${tc.matchValue}" in response body.`;
                } else {
                    assertionPassed = body.trim() === tc.expected.body.trim();
                    reason = `Exact body string checks.`;
                }

                if (assertionPassed) {
                    diffArea.innerHTML = `<span class="text-[#00ffc4] font-bold">✅ RETEST PASSED</span>\n\n` +
                                         `Assertion Rule: ${tc.matchRule}\n` +
                                         `Verdict detail: ${reason}\n\n` +
                                         `Response body preview:\n${body.substring(0, 1000)}`;
                } else {
                    diffArea.innerHTML = `<span class="text-primary font-bold">⚠️ RETEST FAILED - PATTERN DEVIATION</span>\n\n` +
                                         `Assertion Rule: ${tc.matchRule}\n` +
                                         `Verdict detail: ${reason}\n\n` +
                                         `Response body preview:\n${body.substring(0, 1000)}`;
                }
            });
        });

        req.on('error', (err) => {
            diffArea.innerText = `Retest execution failed: ${err.message}`;
        });

        if (tc.request.body) req.write(tc.request.body);
        req.end();

    } catch (e) {
        diffArea.innerText = `Failed to execute: ${e.message}`;
    }
}