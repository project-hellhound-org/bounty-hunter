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
const PROMPT_RE = /hellhound\s*[\(\[]?[^\)\]]*[\)\]]?\s*>/;

const ANIMATION_PHRASES = [
    'hellhound framework console is',
    'hellhound is using',
    'hellhound is thinking',
    'framework console is starting',
    'hud initializing',
    'recon probing', 'recon well-known', 'recon sitemaps',
    'recon phase', 'recon robots',
    'well-known 0/', 'sitemaps 0/', 'probing base 0/',
    'intelligent probing', 'intelligent prob',
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

// ── TELEMETRY CLASSIFIER ───────────────────────────────────────────────────
const FINDING_PATTERNS = [
    { re: /\[critical\]/i,            severity: 'critical' },
    { re: /\[high\]/i,                severity: 'high'     },
    { re: /\[medium\]/i,              severity: 'medium'   },
    { re: /\[low\]/i,                 severity: 'low'      },
    { re: /\[info\]/i,                severity: 'info'     },
    { re: /\[vuln\]|\bvulnerable\b/i, severity: 'high'     },
    { re: /\[found\]|\bfound\b/i,     severity: 'info'     },
    { re: /\[warn\]|\bwarning\b/i,    severity: 'medium'   },
    { re: /\[error\]|\berror\b/i,     severity: 'low'      },
    { re: /https?:\/\/[^\s]+/,        severity: 'info'     },
    { re: /\[\*\]/,                   severity: 'info'     },
    { re: /\[>\]|\[!\]/,              severity: 'medium'   },
    { re: /\[secret\]/i,              severity: 'high'     },
    { re: /\[leak\]/i,                severity: 'high'     },
];

function classifyLine(line) {
    for (const { re, severity } of FINDING_PATTERNS) {
        if (re.test(line)) return { line: line.trim(), severity };
    }
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
        this.captureBuffer = '';
        this.promptsSeen = 0;
        this.stdoutBuffer = '';
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
        this.stdoutBuffer += data.toString();
        const lines = this.stdoutBuffer.split('\n');
        this.stdoutBuffer = lines.pop(); // hold incomplete tail

        lines.forEach(rawLine => this._processLine(rawLine));

        // Check tail — CLI prompt has no trailing newline
        if (PROMPT_RE.test(this.stdoutBuffer.trimEnd())) {
            this.stdoutBuffer = '';
            this._onPrompt();
        }
    }

    _processLine(rawLine) {
        const isPrompt = PROMPT_RE.test(rawLine);

        if (!this.ready) {
            if (isPrompt) {
                this.ready = true;
                if (this.onReady) this.onReady(this.name);
                this._drain();
            }
            return;
        }

        if (isPrompt) { this._onPrompt(); return; }

        const filtered = filterLine(rawLine);
        if (filtered === null) return;

        if (this.current && !this.current.streaming) {
            // Capture mode — accumulate for AI/options responses
            this.captureBuffer += filtered + '\n';
        } else if (this.current?.streaming && this.onLine) {
            // Streaming mode — send live to ops feed
            this.onLine(filtered);
        }
    }

    _onPrompt() {
        if (!this.busy || !this.current) return;
        this.promptsSeen++;
        if (this.promptsSeen < this.current.promptsExpected) return;

        const wasStreaming = this.current.streaming;
        const hasOnDone = !!this.current.onDone;
        const captured = this.captureBuffer.trim();

        if (this.current.captureReply && this.current.captureChannel) {
            this.current.captureReply(this.current.captureChannel, {
                output: captured,
                success: captured.length > 0
            });
        }
        if (this.current.onDone) this.current.onDone(captured);
        if (wasStreaming && !hasOnDone) {
            // Strike complete
            safeSend('proc-exit', { pid: this.proc?.pid || -1, code: 0 });
        }

        this.current = null;
        this.captureBuffer = '';
        this.promptsSeen = 0;
        this.busy = false;
        this._drain();
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
        this.captureBuffer = '';
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

// 2. Options preflight — configure module and capture options output
ipcMain.on('get-options', (event, { module, args }) => {
    const target = args.target || '';
    const lines = [];
    if (target) lines.push(`prey ${target}`);
    lines.push(`equip ${module}`);
    Object.entries(args).forEach(([key, val]) => {
        if (key === 'target') return;
        if (val === true) lines.push(`set ${key} true`);
        else if (val !== false && val !== '') lines.push(`set ${key} ${val}`);
    });
    lines.push('options');

    opsEngine.enqueue({
        lines,
        promptsExpected: lines.length,
        streaming: false,
        captureReply: event.reply.bind(event),
        captureChannel: 'options-data'
    });
});

// 3. Strike confirmed — module already configured by get-options
ipcMain.on('strike-confirmed', (event) => {
    event.reply('proc-started', { pid: opsEngine.proc?.pid || -1, module: 'confirmed' });
    opsEngine.enqueue({ lines: ['strike'], promptsExpected: 1, streaming: true });
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
    if (!fs.existsSync(LOOT_DIR)) return;
    const lootMap = {};

    function scanDir(dir) {
        try {
            fs.readdirSync(dir).forEach(entry => {
                const fullPath = path.join(dir, entry);
                const stat = fs.statSync(fullPath);
                if (stat.isDirectory()) {
                    scanDir(fullPath); // recurse into target subdirectories
                } else if (entry.endsWith('.json') || entry.endsWith('.txt')) {
                    try {
                        const raw = fs.readFileSync(fullPath, 'utf8').trim();
                        if (!raw) return;
                        // Use relative path as key so session log shows target/module
                        const relKey = path.relative(LOOT_DIR, fullPath);
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

    scanDir(LOOT_DIR);
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

// 9. Settings sync — both engines receive global config
ipcMain.on('sync-settings-to-console', (event, settings) => {
    const cmds = [];
    if (settings.proxy)     cmds.push(`proxy ${settings.proxy}`);
    if (settings.oob)       cmds.push(`setg oob ${settings.oob}`);
    if (settings.bugbounty) cmds.push(`setg bugbounty ${settings.bugbounty}`);
    const isLocal = settings.ai_provider === 'LOCAL' || settings.ai_provider === 'LOCAL_SLM';
    if (isLocal) {
        cmds.push('setg ai local');
    } else if (settings.ai_key) {
        cmds.push(`setg ai ${settings.ai_key}`);
    }
    if (cmds.length === 0) return;
    const entry = { lines: cmds, promptsExpected: cmds.length, streaming: false };
    if (opsEngine) opsEngine.enqueue({ ...entry });
    if (intelEngine) intelEngine.enqueue({ ...entry, lines: [...cmds] });
});

// 10. Repro shell — curl only
ipcMain.on('exec-repro', (event, command) => {
    if (!command.trim().startsWith('curl')) {
        event.reply('repro-out', 'Error: Repro shell restricted to curl commands only.');
        return;
    }
    exec(command, (error, stdout, stderr) => {
        if (stdout) event.reply('repro-out', stdout);
        if (stderr) event.reply('repro-out', `[STDERR] ${stderr}`);
        if (error) event.reply('repro-out', `[ERROR] ${error.message}`);
    });
});

// ── AI HANDLERS — all via intelEngine (never blocks opsEngine) ─────────────

ipcMain.on('ai-ask', (event, question) => {
    intelEngine.enqueue({
        lines: [`ask ${question}`],
        promptsExpected: 1,
        streaming: false,
        onDone: (out) => event.reply('ai-response', out || 'No response. Check AI provider in Settings.')
    });
});

ipcMain.on('ai-analyze', (event, target) => {
    // If target is "LIST", we just run 'analyze' to get the menu
    const lines = [];
    if (target && target !== 'LIST') lines.push(`prey ${target}`);
    lines.push('analyze');

    intelEngine.enqueue({
        lines,
        promptsExpected: lines.length,
        streaming: false,
        onDone: (out) => {
            // Check if output contains a menu [1], [2], etc.
            const menuMatches = out.match(/\[\d+\]/g);
            if (menuMatches && menuMatches.length > 0) {
                // Parse the menu into structured data
                const targets = [];
                const lines = out.split('\n');
                lines.forEach(line => {
                    const match = line.match(/^\s*\[(\d+)\]\s+(.*?)\s+\((.*?)\)\s+on\s+(.*?)\s+\[(.*?)\]/i);
                    if (match) {
                        targets.push({
                            id: match[1],
                            type: match[2].trim(),
                            severity: match[3].trim(),
                            url: match[4].trim(),
                            module: match[5].trim()
                        });
                    }
                });
                if (targets.length > 0) {
                    safeSend('intel-target-list', targets);
                    return;
                }
            }
            event.reply('ai-response', out || `Analysis of ${target} complete.`);
        }
    });
});

ipcMain.on('intel-selection-confirmed', (event, selection) => {
    // selection is a string like "1,2,5" or just "1"
    // Since we are already in the middle of a command (analyze),
    // we just write to stdin and wait for the prompt.
    
    // We can hijack the 'onLine' of intelEngine temporarily if we want,
    // but better to just use a one-off capture.
    intelEngine.captureBuffer = '';
    intelEngine.promptsSeen = 0;
    
    // We need to tell the engine that it's now waiting for a prompt again
    intelEngine.busy = true;
    intelEngine.current = {
        streaming: false,
        promptsExpected: 1,
        onDone: (out) => {
            safeSend('ai-response', out || 'Analysis complete.');
        }
    };
    
    intelEngine.write(selection);
});

ipcMain.on('ai-howl', (event) => {
    intelEngine.enqueue({
        lines: ['howl'],
        promptsExpected: 1,
        streaming: false,
        onDone: (out) => event.reply('ai-response', out || 'Howl complete. No critical patterns detected.')
    });
});

ipcMain.on('ai-handshake', (event, key) => {
    const isLocal = !key || key === 'local' || key === 'ollama' || key === 'LOCAL_SLM';
    const lines = isLocal ? ['setg ai local', 'activate hellhound'] : [`setg ai ${key}`];
    // Send to intelEngine (primary) and sync to opsEngine
    intelEngine.enqueue({
        lines,
        promptsExpected: lines.length,
        streaming: false,
        onDone: (out) => {
            event.reply('ai-response', out || 'AI Handshake initialized.');
            event.reply('ai-status-result', out || '');
        }
    });
    if (opsEngine) opsEngine.enqueue({ lines: [...lines], promptsExpected: lines.length, streaming: false });
});

ipcMain.on('check-ai-status', (event) => {
    intelEngine.enqueue({
        lines: ['show options'],
        promptsExpected: 1,
        streaming: false,
        onDone: (out) => event.reply('ai-status-result', out || '')
    });
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

// 12. Window Controls
ipcMain.on('window-minimize', () => { if (mainWindow) mainWindow.minimize(); });
ipcMain.on('window-maximize', () => {
    if (!mainWindow) return;
    if (mainWindow.isMaximized()) mainWindow.unmaximize();
    else mainWindow.maximize();
});
ipcMain.on('window-close', () => { if (mainWindow) mainWindow.close(); });