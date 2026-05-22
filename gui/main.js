const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn, exec } = require('child_process');
const fs = require('fs');

let mainWindow;
const PROJECT_ROOT = path.join(__dirname, '..');
const LOOT_DIR = path.join(PROJECT_ROOT, 'loot');
const HISTORY_FILE = path.join(__dirname, 'target_history.json');

const VENV_BIN = path.join(process.env.HOME || '', '.hellhound-env', 'bin', 'hellhound');
function getHellhoundBin() {
    return fs.existsSync(VENV_BIN) ? VENV_BIN : 'hellhound';
}

// ── SAFE SEND ──────────────────────────────────────────────────────────────
function safeSend(channel, data) {
    try {
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send(channel, data);
        }
    } catch (_) {}
}

// ── OUTPUT FILTER ──────────────────────────────────────────────────────────
const ANSI_RE = /\x1b\[[0-9;]*[mGKHF]/g;
const BRAILLE_RE = /[\u2800-\u28FF]/;
const PROMPT_RE = /hellhound\s*([\(\[]?[^\)\]]*[\)\]]?)?\s*>\s*$/;

const ANIMATION_PHRASES = [
    'hellhound framework console is',
    'hellhound is using',
    'hellhound is thinking',
    'framework console is starting',
    'hud initializing'
];

function isAsciiArt(line) {
    const nonWord = (line.match(/[^a-zA-Z0-9 \t]/g) || []).length;
    return line.length > 10 && nonWord / line.length > 0.6;
}

function filterLine(raw) {
    let line = raw.replace(ANSI_RE, '').replace(/\r/g, '').trimEnd();
    if (!line.trim()) return null;
    if (BRAILLE_RE.test(line)) return null;
    const lower = line.toLowerCase();
    if (ANIMATION_PHRASES.some(p => lower.includes(p))) return null;
    if (isAsciiArt(line)) return null;
    if (PROMPT_RE.test(line.trim())) return null;
    return line;
}

// ── DEEP CLEANER FOR HUD ──────────────────────────────────────────────────
// Strips banners, session markers, and CLI-only artifacts
function deepCleanOutput(text) {
    if (!text) return '';
    
    let clean = text.replace(ANSI_RE, '').replace(/\r/g, '');
    
    // Kill the dog banner and large blocks of ASCII art
    clean = clean.replace(/^[ \t]*[.:#@%*=-]{10,}.*$/gm, ''); 
    clean = clean.replace(/^[ \t]*[█╗╚═║██]{10,}.*$/gm, '');
    clean = clean.replace(/.*Created by L4ZZ3RJ0D.*/gi, '');
    
    // Kill the session dividers and borders - wipe the whole line if it contains blocks
    clean = clean.replace(/^.*█{10,}.*$/gm, '');
    clean = clean.replace(/^.*─{10,}.*$/gm, '');
    clean = clean.replace(/^.*═{10,}.*$/gm, '');
    
    // Kill the options table specifically and any global options header
    clean = clean.replace(/.*Global options.*/gi, '');
    clean = clean.replace(/.*No module equipped.*/gi, '');
    clean = clean.replace(/.*Current Setting.*Required.*/gi, '');
    clean = clean.replace(/.*Name.*Required.*Description.*/gi, '');
    clean = clean.replace(/^-+ *-+ *-+.*$/gm, ''); // Table dividers like ---- ----
    clean = clean.replace(/^[ \t]*(proxy|proxy_mode|bugbounty|wafbypass|oob|ai)[ \t]+.*$/gm, ''); // Specific option names
    
    clean = clean.replace(/HELLHOUND (SESSION|STRIKE|INTEL).*/gi, '');
    clean = clean.replace(/SESSION CLOSED.*/gi, '');
    clean = clean.replace(/COMMAND SENT.*/gi, '');
    
    // Kill the framework startup noise
    clean = clean.replace(/.*HELLHOUND framework console is.*/gi, '');
    clean = clean.replace(/.*Type 'help' to view.*/gi, '');
    clean = clean.replace(/.*Type 'activate hellhound'.*/gi, '');
    clean = clean.replace(/.*hellhound >.*/g, '');
    clean = clean.replace(/.*Hellhound is activated.*/g, '');
    
    // Kill braille noise
    clean = clean.replace(BRAILLE_RE, '');
    
    // Normalize newlines (kill the huge gaps)
    clean = clean.replace(/\n{4,}/g, '\n\n');
    
    // Trim each line to remove console-centering indentation
    return clean.split('\n').map(l => l.trim()).join('\n').trim();
}

const FINDING_PATTERNS = [
    { re: /^(?:critical|crit|fatal)[:\-\s]/i, severity: 'critical' },
    { re: /^(?:high|warning|warn)[:\-\s]/i,   severity: 'high' },
    { re: /^(?:medium|med)[:\-\s]/i,          severity: 'medium' },
    { re: /^(?:low)[:\-\s]/i,                 severity: 'low' },
    { re: /\[critical\]/i,            severity: 'critical' },
    { re: /\[high\]/i,                severity: 'high'     },
    { re: /\[medium\]/i,              severity: 'medium'   },
    { re: /\[low\]/i,                 severity: 'low'      },
    { re: /\[info\]/i,                severity: 'info'     },
    { re: /\[vuln\]|\bvulnerable\b/i, severity: 'high'     },
    { re: /\[secret\]/i,              severity: 'high'     },
    { re: /\[leak\]/i,                severity: 'high'     },
    { re: /robots\.txt|sitemaps|sitemap/i, severity: 'medium' },
    { re: /comment leak|credentials? leak|extract leak/i, severity: 'high' },
    { re: /\[warn\]|\bwarning\b/i,    severity: 'medium'   },
    { re: /\[error\]|\berror\b/i,     severity: 'low'      },
    { re: /\[\*\]/,                   severity: 'info'     },
    { re: /\[>\]|\[!\]/,              severity: 'medium'   },
    { re: /https?:\/\/[^\s]+/,        severity: 'info'     },
];

function classifyLine(line) {
    for (const { re, severity } of FINDING_PATTERNS) {
        if (re.test(line)) return { line: line.trim(), severity };
    }
    const l = line;
    if (l.includes('Crawling') || l.includes('Found') || l.includes('Spider') || l.includes('http') || l.includes('URL')) return { line: l, severity: 'info' };
    if (l.includes('Checking') || l.includes('Scanning') || l.includes('Testing')) return { line: l, severity: 'medium' };

    return null;
}

// ── CONSOLE ENGINE CLASS ────────────────────────────────────────────────────
// Each engine is an independent hellhound console process with its own
// command queue. opsEngine handles strikes; intelEngine handles AI.
// They never block each other.

class ConsoleEngine {
    constructor(name, onReady, onLine, onExit) {
        this.name = name;
        this.onReady = onReady;  // () => void
        this.onLine = onLine;    // (filteredLine) => void — streaming output
        this.onExit = onExit;    // (code) => void

        this.proc = null;
        this.ready = false;
        this.queue = [];
        this.busy = false;
        this.current = null;
        this.buffer = ''; // Stream buffer for prompt detection
        this.captureBuffer = '';
        this.promptsSeen = 0;
        this.currentTarget = '';
    }

    spawn() {
        const bin = getHellhoundBin();
        this.proc = spawn(bin, ['console'], {
            env: { ...process.env, PYTHONUNBUFFERED: '1' },
            stdio: ['pipe', 'pipe', 'pipe']
        });

        this.proc.stdout.on('data', (data) => this._handleData(data));
        this.proc.stderr.on('data', (data) => {
            const filtered = filterLine(data.toString().replace(ANSI_RE, '').replace(/\r/g, '').trim());
            if (filtered && this.current?.streaming && this.onLine) {
                this.onLine(filtered);
            }
        });
        this.proc.on('close', (code) => {
            this.ready = false;
            this.proc = null;
            if (this.onExit) this.onExit(code);
        });
    }

    _handleData(data) {
        this.buffer += data.toString();
        
        // Handle streaming output for active tasks
        if (this.current?.streaming && this.onLine) {
            const lines = this.buffer.split('\n');
            this.buffer = lines.pop(); // Hold incomplete tail
            lines.forEach(l => {
                const filtered = filterLine(l.replace(ANSI_RE, '').replace(/\r/g, '').trim());
                if (filtered) this.onLine(filtered);
            });
        }

        // Dynamic prompt detection (Console Path)
        if (PROMPT_RE.test(this.buffer.trimEnd())) {
            const out = this.buffer;
            this.buffer = '';
            
            if (!this.ready) {
                this.ready = true;
                if (this.onReady) this.onReady(this.name);
                this._drain();
            }

            if (this.current) {
                this.promptsSeen++;
                if (this.promptsSeen >= this.current.promptsExpected) {
                    const task = this.current;
                    this.current = null;
                    this.busy = false;
                    this.promptsSeen = 0;
                    if (task.onDone) task.onDone(out);
                    this._drain();
                }
            }
        }
    }

    enqueue(entry) {
        if (!entry.promptsExpected) entry.promptsExpected = entry.lines.length;
        this.queue.push(entry);
        this._drain();
    }

    _drain() {
        if (this.busy || this.queue.length === 0 || !this.ready) return;
        this.busy = true;
        this.current = this.queue.shift();
        this.promptsSeen = 0;
        this.current.lines.forEach(l => this.write(l));
    }

    write(line) {
        if (this.proc && this.proc.stdin.writable) {
            this.proc.stdin.write(line + '\n');
        }
    }

    setPrey(target) {
        if (target && target !== this.currentTarget) {
            this.currentTarget = target;
            this.enqueue({ lines: [`prey ${target}`], promptsExpected: 1, streaming: false });
        }
    }

    kill() {
        if (this.proc) {
            try { this.proc.kill('SIGINT'); } catch (_) {}
        }
    }

    isReady() { return this.ready && !!this.proc; }
}

// ── DUAL ENGINE INSTANCES ──────────────────────────────────────────────────
let opsEngine = null;    // strikes, options, repro
let intelEngine = null;  // ask, analyze, howl, handshake

function spawnEngines() {
    opsEngine = new ConsoleEngine(
        'ops',
        (name) => {
            safeSend('console-ready', { engine: name });
        },
        (line) => {
            // Streaming ops output → ops feed + telemetry classifier
            safeSend('proc-out', { pid: opsEngine.proc?.pid || -1, data: line + '\n' });
            const ev = classifyLine(line);
            if (ev) safeSend('telemetry-event', ev);
        },
        (code) => {
            safeSend('proc-exit', { pid: -1, code: code || 0 });
        }
    );

    intelEngine = new ConsoleEngine(
        'intel',
        (name) => {
            safeSend('console-ready', { engine: name });
        },
        null, // intel never streams — always capture
        null
    );

    opsEngine.spawn();
    intelEngine.spawn();
}

// ── WINDOW ─────────────────────────────────────────────────────────────────
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 850,
        frame: false,
        backgroundColor: '#050508',
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
            webviewTag: true
        }
    });
    mainWindow.loadFile('app.html');
    
    // Force a micro-resize to trigger repaint on Linux compositor
    mainWindow.webContents.on('did-finish-load', () => {
        setTimeout(() => {
            if (mainWindow) {
                const [w, h] = mainWindow.getSize();
                mainWindow.setSize(w + 1, h);
                mainWindow.setSize(w, h);
            }
        }, 150);
    });

    mainWindow.on('closed', () => { mainWindow = null; });
    spawnEngines();
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('before-quit', () => {
    if (opsEngine) { try { opsEngine.write('exit'); opsEngine.kill(); } catch (_) {} }
    if (intelEngine) { try { intelEngine.write('exit'); intelEngine.kill(); } catch (_) {} }
});

// ── IPC HANDLERS ───────────────────────────────────────────────────────────

// 1. Module Discovery
ipcMain.on('get-modules', (event) => {
    const venvPython = path.join(process.env.HOME || '', '.hellhound-env', 'bin', 'python3');
    const pythonPath = fs.existsSync(venvPython) ? venvPython : 'python3';
    const bridgeScript = path.join(__dirname, 'list_modules.py');
    exec(`${pythonPath} ${bridgeScript} ${PROJECT_ROOT}`, (error, stdout) => {
        if (error) { console.error(`Discovery error: ${error}`); return; }
        try { event.reply('modules-data', JSON.parse(stdout)); }
        catch (e) { console.error('Failed to parse module JSON:', e); }
    });
});

// 2. Options preflight — each command queued separately, each waits for its own prompt
ipcMain.on('get-options', (event, { module, args }) => {
    const target = args.target || '';
    const cmds = [];
    if (target) cmds.push(`prey ${target}`);
    cmds.push(`equip ${module}`);
    Object.entries(args).forEach(([key, val]) => {
        if (key === 'target') return;
        if (val === true) cmds.push(`set ${key} true`);
        else if (val !== false && val !== '') cmds.push(`set ${key} ${val}`);
    });
    cmds.push('options');

    let accumulated = '';
    cmds.forEach((cmd, i) => {
        const isLast = i === cmds.length - 1;
        opsEngine.enqueue({
            lines: [cmd],
            promptsExpected: 1,
            streaming: false,
            onDone: isLast
                ? (out) => event.reply('options-data', { output: accumulated + (out || ''), success: true })
                : (out) => { if (out) accumulated += out + '\n'; }
        });
    });
});

// 3. Strike confirmed — module already configured by get-options
ipcMain.on('strike-confirmed', (event) => {
    event.reply('proc-started', { pid: opsEngine.proc?.pid || -1, module: 'confirmed' });
    opsEngine.enqueue({
        lines: ['strike'],
        promptsExpected: 1,
        streaming: true,
        onDone: () => {
            // After strike completes, run loot command to persist findings
            // so intelEngine can reload them via session_sync
            opsEngine.enqueue({ lines: ['loot'], promptsExpected: 1, streaming: false });
        }
    });
});

// 4. Abort
ipcMain.on('abort-strike', () => {
    opsEngine.enqueue({ lines: ['release'], promptsExpected: 1, streaming: false });
});

// 5. Kill running strike
ipcMain.on('kill-proc', () => {
    if (opsEngine) {
        opsEngine.kill();
        setTimeout(() => {
            opsEngine = new ConsoleEngine('ops',
                () => safeSend('console-ready', { engine: 'ops' }),
                (line) => {
                    safeSend('proc-out', { pid: -1, data: line + '\n' });
                    const ev = classifyLine(line);
                    if (ev) safeSend('telemetry-event', ev);
                },
                null
            );
            opsEngine.spawn();
        }, 500);
    }
});

// 6. Loot Polling — recursive scan to find nested loot files
ipcMain.on('get-loot', (event) => {
    const lootMap = {};

    function scanDir(dir, baseDir) {
        try {
            fs.readdirSync(dir).forEach(entry => {
                const fullPath = path.join(dir, entry);
                const stat = fs.statSync(fullPath);
                if (stat.isDirectory()) {
                    scanDir(fullPath, baseDir); // recurse into target subdirectories
                } else if (entry.endsWith('.json') || entry.endsWith('.txt')) {
                    try {
                        const raw = fs.readFileSync(fullPath, 'utf8').trim();
                        if (!raw) return;
                        // Use relative path as key so session log shows target/module
                        const relKey = path.relative(baseDir, fullPath);
                        let lines = [];
                        if (entry.endsWith('.json')) {
                            try {
                                const parsed = JSON.parse(raw);
                                // Flatten JSON — extract meaningful string values
                                lines = flattenJSON(parsed);
                            } catch (_) {
                                lines = raw.split('\n').filter(l => l.trim());
                            }
                        } else {
                            lines = raw.split('\n').filter(l => l.trim());
                        }
                        if (lines.length > 0) lootMap[relKey] = lines;
                    } catch (_) {}
                }
            });
        } catch (_) {}
    }

    function flattenJSON(obj, prefix = '') {
        const results = [];
        if (Array.isArray(obj)) {
            obj.forEach((item, i) => {
                if (typeof item === 'string' && item.trim()) results.push(item.trim());
                else if (typeof item === 'object' && item !== null) results.push(...flattenJSON(item, prefix));
            });
        } else if (typeof obj === 'object' && obj !== null) {
            Object.entries(obj).forEach(([k, v]) => {
                if (typeof v === 'string' && v.trim()) results.push(`${k}: ${v.trim()}`);
                else if (Array.isArray(v)) results.push(...flattenJSON(v, k));
                else if (typeof v === 'object') results.push(...flattenJSON(v, k));
            });
        }
        return results.slice(0, 200); // cap per file
    }

    if (fs.existsSync(LOOT_DIR)) {
        scanDir(LOOT_DIR, LOOT_DIR);
    }
    
    const REPORTS_DIR = path.join(PROJECT_ROOT, 'storage', 'reports');
    if (fs.existsSync(REPORTS_DIR)) {
        scanDir(REPORTS_DIR, REPORTS_DIR);
    }

    // Dynamic Live Session Sync
    const syncFile = path.join(PROJECT_ROOT, 'storage', 'sync', 'session_sync.json');
    if (fs.existsSync(syncFile)) {
        try {
            const raw = fs.readFileSync(syncFile, 'utf8');
            const data = JSON.parse(raw);
            const activeLines = [];
            
            let totalRisk = 0;
            let totalIssues = 0;
            for (const [mod, output] of Object.entries(data)) {
                if (output && typeof output === 'object') {
                    totalRisk += output.risk_score || 0;
                    const intel = output.intel || {};
                    for (const vk of ['vulnerabilities', 'findings', 'cors_vulnerabilities', 'cves', 'jwts']) {
                        if (Array.isArray(intel[vk])) totalIssues += intel[vk].length;
                    }
                }
            }
            
            activeLines.push(`Risk Score: ${totalRisk}`);
            activeLines.push(`Issues Identified: ${totalIssues}`);
            activeLines.push(``);
            
            for (const [mod, output] of Object.entries(data)) {
                if (!output || typeof output !== 'object') continue;
                const intel = output.intel || {};
                
                if (mod === 'spider') {
                    const endpoints = intel.endpoints || [];
                    const secrets = intel.secrets || [];
                    const robots = intel.robots_disallowed || [];
                    const comments = intel.comments || [];
                    const sourcemaps = intel.sourcemaps || [];
                    const graphql = intel.graphql || [];
                    const openapi = intel.openapi || [];
                    const cors = intel.cors_issues || [];
                    const extracted = intel.extracted_data || [];

                    activeLines.push(`=== SPIDER MODULE ===`);
                    activeLines.push(`Discovered Endpoints: ${endpoints.length}`);
                    activeLines.push(`Extracted Secrets: ${secrets.length}`);
                    activeLines.push(`Robots Disallowed Paths: ${robots.length}`);
                    activeLines.push(`Comment Leaks: ${comments.length}`);
                    activeLines.push(`GraphQL Endpoints: ${graphql.length}`);
                    activeLines.push(`OpenAPI Specs: ${openapi.length}`);
                    activeLines.push(`Source Maps: ${sourcemaps.length}`);
                    activeLines.push(`CORS Flaws: ${cors.length}`);
                    activeLines.push(`Extracted Data Leaks: ${extracted.length}`);
                    activeLines.push(``);

                    if (secrets.length > 0) {
                        activeLines.push(`--- SECRETS IDENTIFIED ---`);
                        secrets.forEach(sec => {
                            let secStr = sec.content || sec.value || sec.match || JSON.stringify(sec);
                            if (sec.type) secStr = `[${sec.type}] ${secStr}`;
                            if (sec.source) secStr += ` (${sec.source})`;
                            activeLines.push(`  ↳ Secret: ${secStr}`);
                        });
                        activeLines.push(``);
                    }

                    if (robots.length > 0) {
                        activeLines.push(`--- ROBOTS.TXT FINDINGS ---`);
                        robots.forEach(r => {
                            let pathVal = typeof r === 'string' ? r : (r.path || r.url || JSON.stringify(r));
                            activeLines.push(`[HIGH] ROBOTS DISALLOWED ENTRY: ${pathVal}`);
                        });
                        activeLines.push(``);
                    }

                    if (comments.length > 0) {
                        activeLines.push(`--- SENSITIVE COMMENT LEAKS ---`);
                        comments.forEach(c => {
                            let cStr = c.content || c.comment || JSON.stringify(c);
                            let src = c.source ? ` in ${c.source}` : '';
                            activeLines.push(`[HIGH] COMMENT LEAK: ${cStr}${src}`);
                        });
                        activeLines.push(``);
                    }

                    if (extracted.length > 0) {
                        activeLines.push(`--- EXTRACTED LEAKS ---`);
                        extracted.forEach(ex => {
                            let label = ex.label || ex.type || 'Data';
                            let val = ex.content || ex.value || JSON.stringify(ex);
                            let src = ex.source ? ` (${ex.source})` : '';
                            activeLines.push(`[HIGH] EXTRACT LEAK: [${label}] ${val}${src}`);
                        });
                        activeLines.push(``);
                    }

                    if (sourcemaps.length > 0) {
                        activeLines.push(`--- SOURCE MAPS EXPOSED ---`);
                        sourcemaps.forEach(sm => {
                            let parent = sm.parent ? ` (parent: ${sm.parent})` : '';
                            activeLines.push(`[HIGH] EXPOSED SOURCE MAP: ${sm.url}${parent}`);
                        });
                        activeLines.push(``);
                    }

                    if (graphql.length > 0) {
                        activeLines.push(`--- GRAPHQL EXPOSED ---`);
                        graphql.forEach(g => {
                            activeLines.push(`[HIGH] GRAPHQL ENDPOINT: ${g.url || g}`);
                        });
                        activeLines.push(``);
                    }

                    if (openapi.length > 0) {
                        activeLines.push(`--- OPENAPI ENDPOINTS ---`);
                        openapi.forEach(o => {
                            activeLines.push(`[INFO] OPENAPI SPEC EXPOSED: ${o.url || o}`);
                        });
                        activeLines.push(``);
                    }

                    if (cors.length > 0) {
                        activeLines.push(`--- CORS ISSUES ---`);
                        cors.forEach(c => {
                            activeLines.push(`[MEDIUM] CORS VULNERABILITY: ${c.url || c.origin || JSON.stringify(c)}`);
                        });
                        activeLines.push(``);
                    }
                } else {
                    let hasFindings = false;
                    for (const vk of ['vulnerabilities', 'findings', 'cors_vulnerabilities', 'cves', 'jwts', 'reconstructed']) {
                        const items = intel[vk] || [];
                        if (Array.isArray(items) && items.length > 0) {
                            if (!hasFindings) {
                                activeLines.push(`=== ${mod.toUpperCase()} FINDINGS ===`);
                                hasFindings = true;
                            }
                            items.forEach(v => {
                                if (typeof v === 'string') {
                                    activeLines.push(`- ${v}`);
                                } else if (v && typeof v === 'object') {
                                    const sev = (v.severity || v.confidence || 'INFO').toUpperCase();
                                    const vtype = v.finding_type || v.type || v.name || 'Vulnerability';
                                    const method = v.method || 'GET';
                                    const url = v.url || 'N/A';
                                    const param = v.parameter || v.param_name || '';
                                    activeLines.push(`[${sev}] ${vtype.replace(/_/g, ' ').toUpperCase()}`);
                                    activeLines.push(`  Method: ${method} | Target: ${url}`);
                                    if (param) activeLines.push(`  Parameter: ${param}`);
                                    if (v.evidence) activeLines.push(`  Evidence: ${v.evidence}`);
                                    if (v.poc_curl) activeLines.push(`  PoC: ${v.poc_curl}`);
                                    activeLines.push(``);
                                }
                            });
                        }
                    }
                }
            }
            if (activeLines.length > 3) {
                lootMap['ACTIVE_SESSION_FINDINGS.txt'] = activeLines;
            }
        } catch (e) {
            console.error("Failed to parse active sync data for loot:", e);
        }
    }

    event.reply('loot-data', lootMap);
});

// 7. Target History
ipcMain.on('save-target', (event, url) => {
    let history = [];
    if (fs.existsSync(HISTORY_FILE)) {
        try { history = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')); } catch (_) {}
    }
    if (!history.includes(url)) {
        history.unshift(url);
        fs.writeFileSync(HISTORY_FILE, JSON.stringify(history.slice(0, 20)));
    }
    event.reply('history-data', history);
    // Sync prey to both engines when target changes
    if (opsEngine) opsEngine.setPrey(url);
    if (intelEngine) intelEngine.setPrey(url);
});

ipcMain.on('get-history', (event) => {
    if (fs.existsSync(HISTORY_FILE)) {
        try { event.reply('history-data', JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'))); } catch (_) {}
    }
});

// 8. Repro — routed to opsEngine
ipcMain.on('run-repro', (event, { cmd }) => {
    opsEngine.enqueue({
        lines: [cmd],
        promptsExpected: 1,
        streaming: true,
        onDone: () => safeSend('repro-done', { code: 0 })
    });
});

// 9. Settings sync — each command queued individually on both engines
ipcMain.on('sync-settings-to-console', (event, settings) => {
    const cmds = [];
    if (settings.proxy)     cmds.push(`proxy ${settings.proxy}`);
    if (settings.oob)       cmds.push(`setg oob ${settings.oob}`);
    if (settings.bugbounty) cmds.push(`setg bugbounty ${settings.bugbounty}`);
    // AI is handled exclusively via ai-handshake channel — do NOT set here
    cmds.forEach(cmd => {
        if (opsEngine)   opsEngine.enqueue({   lines: [cmd], promptsExpected: 1, streaming: false });
        if (intelEngine) intelEngine.enqueue({ lines: [cmd], promptsExpected: 1, streaming: false });
    });
});

ipcMain.on('exec-repro', (event, payload) => {
    let command = '';
    let cwd = process.cwd();
    if (typeof payload === 'string') {
        command = payload;
    } else if (payload && typeof payload === 'object') {
        command = payload.command || '';
        cwd = payload.cwd || cwd;
    }

    if (!command.trim().startsWith('curl')) {
        event.reply('repro-out', 'Error: Repro shell restricted to curl commands only.\n');
        event.reply('repro-done');
        return;
    }

    let cleanCommand = command;
    const parts = command.split(/\s+/);
    const hasSilent = parts.some(p => p === '-s' || p === '--silent' || p === '-sS' || p === '--no-progress-meter');
    if (!hasSilent) {
        cleanCommand = command.replace(/^(\s*curl\b)/, '$1 -sS');
    }

    const { spawn } = require('child_process');
    const child = spawn('bash', ['-c', cleanCommand], { cwd });
    child.stdout.on('data', (data) => {
        event.reply('repro-out', data.toString());
    });
    child.stderr.on('data', (data) => {
        event.reply('repro-out', data.toString());
    });
    child.on('error', (err) => {
        event.reply('repro-out', `\n[ERROR] Command failed to start: ${err.message}\n`);
    });
    child.on('close', (code) => {
        event.reply('repro-done');
    });
});

// ── AI HANDLERS — all via intelEngine (never blocks opsEngine) ─────────────

// ── AI HANDLERS ────────────────────────────────────────────────────────────
// FLOW: setg ai local → activate hellhound → then ask/analyze/howl work
// Each command queued individually (promptsExpected:1 always)

// AI Handshake handles setting the provider and activating the neural core
ipcMain.on('ai-handshake', (event, payload) => {
    let provider = '';
    let key = '';
    if (typeof payload === 'string') {
        key = payload;
        provider = (!key || key === 'local' || key === 'ollama' || key.toUpperCase() === 'LOCAL') ? 'LOCAL' : '';
    } else {
        provider = payload.provider;
        key = payload.key;
    }

    const isLocal = !key || key === 'local' || key === 'ollama' || key.toUpperCase() === 'LOCAL' || provider === 'LOCAL';
    
    // Command selection based on user preference and console.py logic
    const cmds = [];
    if (!isLocal && provider) {
        cmds.push(`setg ai_provider ${provider.toLowerCase()}`);
    }
    cmds.push(isLocal ? 'activate hellhound' : `setg ai ${key}`);
    
    // Sync to both engines
    if (opsEngine) opsEngine.enqueue({ lines: cmds, promptsExpected: cmds.length, streaming: false });
    
    intelEngine.enqueue({
        lines: cmds,
        promptsExpected: cmds.length,
        streaming: false,
        onDone: (out) => {
            // After activation/setting provider, check options for actual status
            intelEngine.enqueue({
                lines: ['options'],
                promptsExpected: 1,
                streaming: false,
                onDone: (out2) => {
                    // Strip ANSI before checking — console output is colored
                    const clean = (out2 || '').replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '');
                    const activated = (out || '').replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '');
                    const isOnline = clean.includes('ONLINE') || clean.includes('CONNECTED') || activated.includes('Hellhound is activated');
                    // Send both: activation output + options output for full context
                    const finalOut = deepCleanOutput((out || '') + '\n' + (out2 || ''));
                    event.reply('ai-response', finalOut);
                }
            });
        }
    });
});

ipcMain.on('ai-ask', (event, question) => {
    const sanitizedQuestion = (question || '').replace(/\r?\n/g, ' ');
    let completed = false;
    
    // Safety timeout: 45 seconds to prevent permanent UI lockup
    const timer = setTimeout(() => {
        if (!completed) {
            completed = true;
            event.reply('ai-response', 'Error: Neural Core request timed out. Please check model connectivity.');
            if (intelEngine) {
                intelEngine.current = null;
                intelEngine.busy = false;
                intelEngine.promptsSeen = 0;
                intelEngine._drain();
            }
        }
    }, 45000);

    intelEngine.enqueue({
        lines: [`ask ${sanitizedQuestion}`],
        promptsExpected: 1,
        streaming: false,
        onDone: (out) => {
            if (completed) return;
            completed = true;
            clearTimeout(timer);
            const cleanOut = deepCleanOutput(out);
            event.reply('ai-response', cleanOut || 'No response from Neural Core.');
        }
    });
});

ipcMain.on('ai-analyze', (event, target) => {
    const sanitizedTarget = (target || '').replace(/\r?\n/g, ' ');
    // Pass targets as argument to skip interactive menu (console.py supports this)
    // e.g. "analyze 1,2,5" or just "analyze" for all
    const isSelection = sanitizedTarget && /^[\d,\s]+$/.test(sanitizedTarget);
    const cmd = isSelection ? `analyze ${sanitizedTarget}` : 'analyze';
    const cmds = [];
    if (sanitizedTarget && sanitizedTarget !== 'LIST' && !isSelection) cmds.push(`prey ${sanitizedTarget}`);
    cmds.push(cmd);

    let acc = '';
    let completed = false;

    // Safety timeout: 60 seconds
    const timer = setTimeout(() => {
        if (!completed) {
            completed = true;
            event.reply('ai-response', 'Error: Neural Core analysis timed out. Please try again.');
            if (intelEngine) {
                intelEngine.current = null;
                intelEngine.busy = false;
                intelEngine.promptsSeen = 0;
                intelEngine._drain();
            }
        }
    }, 60000);

    cmds.forEach((c, i) => {
        const isLast = i === cmds.length - 1;
        intelEngine.enqueue({
            lines: [c],
            promptsExpected: 1,
            streaming: false,
            onDone: (out) => {
                if (completed) return;
                if (out) acc += out + '\n';
                if (isLast) {
                    completed = true;
                    clearTimeout(timer);
                    event.reply('ai-response', acc);
                }
            }
        });
    });
});

ipcMain.on('ai-howl', (event) => {
    intelEngine.enqueue({
        lines: ['howl'],
        promptsExpected: 1,
        streaming: false,
        onDone: (out) => event.reply('howl-data', out || 'Howl complete. No critical patterns detected.')
    });
});

ipcMain.on('get-attack-graph', (event) => {
    intelEngine.enqueue({
        lines: ['howl --graph'],
        promptsExpected: 1,
        streaming: false,
        onDone: (out) => {
            try {
                // The output should be a JSON string from console.py
                const graph = JSON.parse(out);
                event.reply('graph-data', graph);
            } catch (e) {
                console.error("Failed to parse graph JSON:", e);
                event.reply('graph-data', { nodes: [], edges: [] });
            }
        }
    });
});

ipcMain.on('get-arsenal', (event) => {
    opsEngine.enqueue({
        lines: ['arsenal'],
        promptsExpected: 1,
        streaming: false,
        onDone: (out) => event.reply('arsenal-data', out)
    });
});

ipcMain.on('get-status', (event) => {
    opsEngine.enqueue({
        lines: ['status'],
        promptsExpected: 1,
        streaming: false,
        onDone: (out) => event.reply('status-data', out)
    });
});

// Intel selection — send selection number(s) as analyze argument
ipcMain.on('intel-selection-confirmed', (event, selection) => {
    intelEngine.enqueue({
        lines: [`analyze ${selection}`],
        promptsExpected: 1,
        streaming: false,
        onDone: (out) => safeSend('ai-response', out || 'Analysis complete.')
    });
});


ipcMain.on('check-ai-status', (event) => {
    if (!intelEngine || !intelEngine.isReady()) {
        event.reply('ai-status-result', '[!] Intel engine not ready yet.'); return;
    }
    if (intelEngine.busy) {
        event.reply('ai-status-result', '[*] Engine busy (AI activation in progress). Try again shortly.'); return;
    }
    // Use direct 'options' command for actual status
    intelEngine.enqueue({ lines: ['options'], promptsExpected: 1, streaming: false, onDone: (out) => event.reply('ai-status-result', out || '') });
});

// Intel Center — build structured finding cards from synced session data
ipcMain.on('get-intel-targets', (event) => {
    const syncFile = path.join(PROJECT_ROOT, 'storage', 'sync', 'session_sync.json');
    if (!fs.existsSync(syncFile)) {
        event.reply('intel-target-list', []);
        return;
    }

    try {
        const raw = fs.readFileSync(syncFile, 'utf8');
        const results = JSON.parse(raw);
        const targets = [];
        let idCounter = 1;

        for (const [module, data] of Object.entries(results)) {
            // Recurse to find anything that looks like a finding
            const findings = [];
            
            function extract(obj) {
                if (!obj) return;
                if (Array.isArray(obj)) {
                    obj.forEach(item => {
                        if (typeof item === 'object') extract(item);
                        else if (typeof item === 'string') findings.push({ type: 'Info', context: item, severity: 'INFO' });
                    });
                    return;
                }
                if (typeof obj === 'object') {
                    // Check for common keys
                    const keys = ['vulnerabilities', 'findings', 'secrets', 'endpoints', 'urls', 'intel', 'results', 'data'];
                    keys.forEach(k => {
                        if (obj[k]) {
                            if (Array.isArray(obj[k])) {
                                obj[k].forEach(item => {
                                    if (typeof item === 'object') findings.push(item);
                                    else if (typeof item === 'string') findings.push({ type: 'Info', context: item, severity: 'INFO' });
                                });
                            }
                            else extract(obj[k]);
                        }
                    });
                    // If it has a 'url' and 'type', it's likely a finding itself
                    if (obj.url || obj.type || obj.vulnerability) {
                        findings.push(obj);
                    }
                }
            }
            extract(data);
            
            findings.forEach(f => {
                if (typeof f !== 'object') return;
                const severity = (f.severity || "INFO").toUpperCase();
                const type = f.type || f.vulnerability || "Intel";
                const url = f.url || f.context || f.endpoint || "Internal Finding";
                
                targets.push({
                    id: idCounter++,
                    module: module.toUpperCase().substring(0, 12),
                    type: type,
                    severity: severity,
                    url: url,
                    raw: typeof f === 'string' ? f : JSON.stringify(f),
                    data: f
                });
            });
        }
        
        const ord = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
        targets.sort((a, b) => (ord[a.severity] || 4) - (ord[b.severity] || 4));
        event.reply('intel-target-list', targets);
    } catch (e) {
        console.error("Failed to sync intel targets:", e);
        event.reply('intel-target-list', []);
    }
});

// 11. Export session
ipcMain.on('export-session', (event, { filename, content }) => {
    try {
        if (!fs.existsSync(LOOT_DIR)) fs.mkdirSync(LOOT_DIR, { recursive: true });
        const outputPath = path.join(LOOT_DIR, filename);
        fs.writeFileSync(outputPath, content, 'utf8');
        safeSend('export-done', { path: outputPath });
    } catch (e) { console.error('Export failed:', e); }
});

ipcMain.on('open-loot-dir', () => {
    if (fs.existsSync(LOOT_DIR)) {
        require('electron').shell.openPath(LOOT_DIR);
    }
});

ipcMain.on('purge-loot', (event) => {
    if (fs.existsSync(LOOT_DIR)) {
        try {
            fs.rmSync(LOOT_DIR, { recursive: true, force: true });
            fs.mkdirSync(LOOT_DIR, { recursive: true });
            event.reply('loot-data', {});
        } catch (e) { console.error('Purge failed:', e); }
    }
});

// 12. Window Controls
ipcMain.on('window-minimize', () => { if (mainWindow) mainWindow.minimize(); });
ipcMain.on('window-maximize', () => {
    if (!mainWindow) return;
    if (mainWindow.isMaximized()) mainWindow.unmaximize();
    else mainWindow.maximize();
});
ipcMain.on('window-close', () => { if (mainWindow) mainWindow.close(); });