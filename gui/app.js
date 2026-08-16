/**
 * HELLHOUND // APEX-KING HUD — Pure PyWebView Client Architecture
 * 
 * Replaces Electron IPC entirely with window.pywebview.api calls.
 * Implements target-isolated chat threads and structurally isolated findings panel.
 */

// Global State
let currentTarget = null;
let targetsList = [];
let isExecuting = false;
let findingsComponent = null;

// Slash Command Registry for Autocomplete
const SLASH_COMMANDS = [
    { cmd: "/recon", desc: "Target reconnaissance pipeline with scope verification", usage: "/recon <target>" },
    { cmd: "/hunt", desc: "Autonomous scope-aware multi-stage hunt and triage", usage: "/hunt [target]" },
    { cmd: "/scan", desc: "Execute a specific discovery/analysis module", usage: "/scan <module> [target]" },
    { cmd: "/howl", desc: "Correlate discoveries or generate attack graph", usage: "/howl [--graph]" },
    { cmd: "/skills", desc: "List loaded methodology and exploitation skills", usage: "/skills" },
    { cmd: "/scope", desc: "Inspect or configure target scope rules", usage: "/scope" },
    { cmd: "/model", desc: "Check or switch active AI model", usage: "/model [name]" },
    { cmd: "/help", desc: "Show unified slash commands documentation", usage: "/help" },
    { cmd: "/clear", desc: "Clear current conversation thread", usage: "/clear" }
];

// Helper: safe pywebview API caller
async function callApi(method, ...args) {
    if (!window.pywebview || !window.pywebview.api) {
        console.warn(`[PyWebView] API not available yet for call: ${method}`);
        return null;
    }
    try {
        const fn = window.pywebview.api[method];
        if (typeof fn !== 'function') {
            console.error(`[PyWebView] Unknown API method: ${method}`);
            return null;
        }
        return await fn(...args);
    } catch (err) {
        console.error(`[PyWebView] Error calling ${method}:`, err);
        throw err;
    }
}

// ── CUSTOM CONFIRMATION MODAL ───────────────────────────────────────
function showConfirmModal({ title = "CONFIRM ACTION", message = "Are you sure you want to proceed?", confirmText = "CONFIRM", danger = true } = {}) {
    return new Promise((resolve) => {
        const modal = document.getElementById('confirmModal');
        const titleEl = document.getElementById('confirmModalTitle');
        const msgEl = document.getElementById('confirmModalMessage');
        const cancelBtn = document.getElementById('cancelConfirmBtn');
        const acceptBtn = document.getElementById('acceptConfirmBtn');

        if (!modal) {
            resolve(confirm(message));
            return;
        }

        if (titleEl) titleEl.innerText = title;
        if (msgEl) msgEl.innerText = message;
        if (acceptBtn) {
            acceptBtn.innerText = confirmText;
            if (danger) {
                acceptBtn.classList.add('btn-danger');
            } else {
                acceptBtn.classList.remove('btn-danger');
            }
        }

        modal.classList.add('open');

        const cleanup = () => {
            modal.classList.remove('open');
            cancelBtn?.removeEventListener('click', onCancel);
            acceptBtn?.removeEventListener('click', onAccept);
        };

        const onCancel = () => {
            cleanup();
            resolve(false);
        };

        const onAccept = () => {
            cleanup();
            resolve(true);
        };

        cancelBtn?.addEventListener('click', onCancel);
        acceptBtn?.addEventListener('click', onAccept);
    });
}

// ══════════════════════════════════════════════════════
// ChatRenderer — single source of truth mapping backend events to UI.
// The backend (emit.py / agent.py / tool modules) only ever sends
// structured data (type + payload) via tool_start/tool_result/status/etc;
// it never builds HTML. This is the only place that decides how a given
// event type is presented.
//
//   STATUS/INFO/WARN/SUCCESS -> inline activity line
//   TOOL_START               -> small running chip
//   TOOL_RESULT (rich)       -> evidence card (subdomain tree, httpx table)
//   TOOL_RESULT (thin)       -> inline completion line
//   ERROR / SCOPE_BLOCKED    -> friendly inline AI message, never a raw
//                                Python traceback
// ══════════════════════════════════════════════════════
const ChatRenderer = {
    render(emit) {
        const type = emit.type || 'info';
        const payload = emit.payload;

        if (type === 'tool_start') return this._toolStart(payload);
        if (type === 'tool_result') return this._toolResult(payload);
        if (type === 'status' || type === 'info' || type === 'warn' || type === 'error' || type === 'success') {
            return this._statusLine(payload);
        }
        return this._inline(String(payload));
    },

    // Strips raw Python tracebacks / exception noise down to one plain
    // sentence — the doc's "never expose Python traceback" rule, applied
    // everywhere an error string might originate from a backend module.
    friendlyError(raw, context) {
        if (!raw) return `I hit an internal issue${context ? ' during ' + context : ''} and skipped that step.`;
        const text = String(raw);
        if (/Traceback \(most recent call last\)|File "[^"]+", line \d+|^\s+at .+:\d+/m.test(text)) {
            return `I couldn't complete ${context || 'that step'} because an internal module error occurred. I've skipped it and continued with the rest of the investigation.`;
        }
        return text.length > 220 ? text.slice(0, 220) + '…' : text;
    },

    _inline(text, opts = {}) {
        const icon = opts.icon ? `<span class="node-status-icon ${opts.iconClass || ''}">${opts.icon}</span>` : (opts.pulse ? '<span class="node-status-dot pulse"></span>' : '');
        return `<div class="inline-activity-line">${icon}<span class="inline-activity-text">${escapeHtml(text)}</span></div>`;
    },

    _toolStart(payload) {
        const tool = payload?.tool || 'Tool';
        const args = payload?.args || {};
        const targetStr = args.domain || args.target || args.url || args.subdomain || args.hosts || '';
        return `
            <div class="inline-activity-line">
                <span class="node-status-dot pulse"></span>
                <span class="inline-activity-text">Running <code class="inline-tool-badge">${escapeHtml(tool)}</code>${targetStr ? ` · ${escapeHtml(String(targetStr))}` : ''}</span>
            </div>
        `;
    },

    _statusLine(payload) {
        let msg;
        if (typeof payload === 'object' && payload !== null) {
            msg = payload.message || payload.text || payload.detail || payload.status || 'Update received';
        } else {
            msg = String(payload);
        }
        return this._inline(this.friendlyError(msg));
    },

    _toolResult(payload) {
        const tool = payload?.tool || 'Tool';
        const result = payload?.result || {};

        if (result.blocked || (typeof result.error === 'string' && (result.error.includes('SCOPE_VIOLATION') || result.error.includes('SCOPE REFUSAL')))) {
            return this._inline(
                `Skipped — ${result.error || result.reason || 'out of the authorized scope'}.`,
                { icon: '⦸', iconClass: 'blocked-icon' }
            );
        }

        if (result.error) {
            return this._inline(this.friendlyError(result.error, `the ${tool} step`), { icon: '!', iconClass: 'error-icon' });
        }

        if (tool === 'dns_bruteforce' || tool === 'subfinder') {
            return this._subdomainCard(tool, result);
        }
        if (tool === 'permute_subdomains' || tool === 'resolve_candidates') {
            return this._permutationCard(tool, result);
        }
        if (tool === 'httpx') {
            return this._httpxCard(result);
        }

        const keys = Object.keys(result).filter(k => k !== 'status');
        const isLightweight = keys.length <= 3 && keys.every(k => typeof result[k] !== 'object' || result[k] === null);
        if (isLightweight) {
            const summary = keys.map(k => `${k}: ${result[k]}`).join(' · ');
            return this._inline(`${tool} completed${summary ? ' — ' + summary : ''}`, { icon: '✓', iconClass: 'success-icon' });
        }

        const keySummary = keys.map(k => {
            const val = result[k];
            const valStr = Array.isArray(val) ? `${val.length} items` : (typeof val === 'object' ? 'object' : String(val));
            return `<div><strong>${escapeHtml(k)}:</strong> ${escapeHtml(valStr)}</div>`;
        }).join('');
        return `
            <div class="node-exec-card success">
                <div class="node-exec-header">
                    <span class="node-status-icon">✓</span>
                    <span class="node-tool-name">${escapeHtml(tool)} Completed</span>
                </div>
                <div class="node-exec-body">${keySummary || 'Completed successfully'}</div>
            </div>
        `;
    },

    _subdomainCard(tool, result) {
        const subs = result.subdomains || [];
        const count = result.total_discovered || result.count || subs.length;
        const rootDomain = result.domain || 'Target';
        const limit = 12;
        const branchesHtml = subs.slice(0, limit).map((sub, idx) => {
            const prefix = (idx === Math.min(subs.length, limit) - 1) ? '└──' : '├──';
            return `<div class="node-branch-item"><span class="tree-line">${prefix}</span><span class="node-sub-dot online"></span><span class="node-sub-name">${escapeHtml(sub)}</span></div>`;
        }).join('');
        const remaining = subs.length > limit ? `<div class="node-branch-more">+ ${subs.length - limit} more subdomains</div>` : '';
        return `
            <div class="node-topology-card">
                <div class="node-topo-header">
                    <span class="node-topo-title">DOMAIN TOPOLOGY MAP (${tool})</span>
                    <span class="node-topo-badge">${count} DISCOVERED</span>
                </div>
                <div class="node-topo-tree">
                    <div class="node-tree-root"><span class="node-icon root">◆</span><span class="node-root-name">${escapeHtml(rootDomain)}</span></div>
                    <div class="node-tree-branches">${branchesHtml}${remaining}</div>
                </div>
            </div>
        `;
    },

    _permutationCard(tool, result) {
        const cands = result.candidates || result.subdomains || [];
        const count = result.resolved_count || result.count || cands.length;
        const limit = 10;
        const itemsHtml = cands.slice(0, limit).map((item, idx) => {
            const prefix = (idx === Math.min(cands.length, limit) - 1) ? '└──' : '├──';
            return `<div class="node-branch-item"><span class="tree-line">${prefix}</span><span class="node-sub-dot resolved"></span><span class="node-sub-name">${escapeHtml(item)}</span></div>`;
        }).join('');
        return `
            <div class="node-topology-card">
                <div class="node-topo-header">
                    <span class="node-topo-title">PERMUTATION & RESOLUTION (${tool})</span>
                    <span class="node-topo-badge">${count} RESOLVED</span>
                </div>
                <div class="node-topo-tree"><div class="node-tree-branches">${itemsHtml}</div></div>
            </div>
        `;
    },

    _httpxCard(result) {
        const liveServices = result.live_hosts || result.services || [];
        const rowsHtml = Array.isArray(liveServices) ? liveServices.slice(0, 10).map(srv => {
            const urlStr = typeof srv === 'string' ? srv : (srv.url || srv.host);
            const status = srv.status_code || 200;
            const title = srv.title ? ` - ${srv.title}` : '';
            const statusClass = status >= 200 && status < 300 ? 'status-200' : (status >= 300 && status < 400 ? 'status-300' : 'status-400');
            return `<div class="httpx-service-row"><span class="http-status-code ${statusClass}">${status}</span><span class="service-url">${escapeHtml(urlStr)}</span><span class="service-title">${escapeHtml(title)}</span></div>`;
        }).join('') : `<div>Probed ${liveServices} live hosts</div>`;
        return `
            <div class="node-topology-card">
                <div class="node-topo-header">
                    <span class="node-topo-title">HTTP SERVICE PROBES (httpx)</span>
                    <span class="node-topo-badge">${Array.isArray(liveServices) ? liveServices.length : 'ACTIVE'} SERVICES</span>
                </div>
                <div class="httpx-services-list">${rowsHtml}</div>
            </div>
        `;
    },
};

// Back-compat wrapper — existing call sites use this name.
function renderToolEmitCard(emit) {
    return ChatRenderer.render(emit);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. INITIALIZATION & LIFECYCLE
// ─────────────────────────────────────────────────────────────────────────────

window.addEventListener('DOMContentLoaded', () => {
    setupDOMEventHandlers();
});

window.addEventListener('pywebviewready', async () => {
    console.log("[HELLHOUND] PyWebView API bridge initialized.");
    await refreshSystemInfo();
    await loadTargetsList();
    await initVoiceState();
});

// Setup agent emit handler called from Python
window.onAgentEmit = (data) => {
    if (!data || data.target !== currentTarget) return;
    handleIncomingEmit(data);
};

// ─────────────────────────────────────────────────────────────────────────────
// 2. TARGET ARCHIVE & SELECTION
// ─────────────────────────────────────────────────────────────────────────────

async function loadTargetsList(selectTargetName = null) {
    try {
        const targets = await callApi('list_targets') || [];
        targetsList = targets;
        renderTargetList(targets);

        if (selectTargetName) {
            await switchTarget(selectTargetName);
        } else if (!currentTarget && targets.length > 0) {
            await switchTarget(targets[0].name);
        }
    } catch (e) {
        console.error("Failed to load targets:", e);
    }
}

function renderTargetList(targets) {
    const listEl = document.getElementById('targetList');
    if (!listEl) return;

    listEl.innerHTML = '';
    const filterQuery = (document.getElementById('targetSearchInput')?.value || '').toLowerCase().trim();

    const filtered = targets.filter(t => t.name.toLowerCase().includes(filterQuery));

    if (filtered.length === 0) {
        listEl.innerHTML = `
            <div style="padding: 24px 12px; text-align: center; color: var(--text-dim); font-size: 12px;">
                No targets found.
            </div>
        `;
        return;
    }

    filtered.forEach(t => {
        const item = document.createElement('div');
        item.className = `target-item ${t.name === currentTarget ? 'active' : ''}`;
        item.onclick = (e) => {
            if (e.target.closest('.target-delete-btn')) return;
            switchTarget(t.name);
        };

        const timeStr = t.last_active ? formatRelativeTime(t.last_active) : 'Ready';

        item.innerHTML = `
            <div class="target-item-top">
                <span class="target-name" title="${escapeHtml(t.name)}">${escapeHtml(t.name)}</span>
                ${t.name !== 'default' ? `<button class="target-delete-btn" title="Delete target" data-name="${escapeHtml(t.name)}">✕</button>` : ''}
            </div>
            <div class="target-item-bottom">
                <span class="target-findings-pill">${t.findings_count} findings</span>
                <span class="target-item-time">${timeStr}</span>
            </div>
        `;

        const delBtn = item.querySelector('.target-delete-btn');
        if (delBtn) {
            delBtn.onclick = async (e) => {
                e.stopPropagation();
                const confirmed = await showConfirmModal({
                    title: "DELETE TARGET",
                    message: `Are you sure you want to delete target "${t.name}" and all associated task data?`,
                    confirmText: "DELETE TARGET"
                });
                if (confirmed) {
                    await deleteTarget(t.name);
                }
            };
        }

        listEl.appendChild(item);
    });
}

/**
 * Switch Target:
 * Structurally destroys old findings component, updates header, and reloads isolated chat.
 */
async function switchTarget(targetName) {
    if (currentTarget === targetName && findingsComponent) {
        return;
    }

    currentTarget = targetName;

    // 1. Destroy and dereference any existing findings component (structural isolation)
    if (findingsComponent) {
        findingsComponent.destroy();
        findingsComponent = null;
    }

    // 2. Update active highlighting in sidebar
    document.querySelectorAll('.target-item').forEach(el => {
        const nameEl = el.querySelector('.target-name');
        if (nameEl && nameEl.innerText === targetName) {
            el.classList.add('active');
        } else {
            el.classList.remove('active');
        }
    });

    // 3. Update Header Info
    const displayEl = document.getElementById('activeTargetNameDisplay');
    if (displayEl) displayEl.innerText = targetName;

    // 4. Fetch target metadata
    try {
        const targetData = await callApi('get_target', targetName);
        if (targetData) {
            const inScopeCount = targetData.scope_rules?.in_scope?.length || 0;
            const scopeCountEl = document.getElementById('scopeRuleCount');
            if (scopeCountEl) {
                scopeCountEl.innerText = `${inScopeCount} in-scope`;
            }
        }
    } catch (err) {
        console.error("Error fetching target details:", err);
    }

    // 5. Instantiate fresh Findings Component for this target
    findingsComponent = new IsolatedFindingsComponent(targetName);
    await findingsComponent.refreshData();

    // 5b. Speak the mission briefing — built from the findings data just fetched above
    speakBriefing(buildBriefingText(targetName, findingsComponent.data));

    // 6. Reload Chat History for this target
    await loadTargetChatHistory(targetName);
}

async function createTarget(name) {
    if (!name || !name.trim()) return;
    try {
        const created = await callApi('create_target', name.trim());
        await loadTargetsList(created.name);
    } catch (e) {
        alert("Failed to create target: " + e);
    }
}

async function deleteTarget(name) {
    try {
        await callApi('delete_target', name);
        if (currentTarget === name) {
            currentTarget = null;
        }
        await loadTargetsList();
    } catch (e) {
        alert("Failed to delete target: " + e);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. STRUCTURALLY ISOLATED FINDINGS COMPONENT
// ─────────────────────────────────────────────────────────────────────────────

class IsolatedFindingsComponent {
    constructor(targetName) {
        this.targetName = targetName;
        this.data = null;
        this.currentCategory = 'all';
        this.drawerEl = document.getElementById('findingsDrawer');
        this.listEl = document.getElementById('findingsList');
        this.searchEl = document.getElementById('findingsSearchInput');
        this.subtitleEl = document.getElementById('findingsTargetSubtitle');
        this.headerBadge = document.getElementById('headerFindingsCount');

        if (this.subtitleEl) {
            this.subtitleEl.innerText = `TARGET: ${this.targetName}`;
        }
    }

    async refreshData() {
        if (!this.targetName) return;
        try {
            // Strictly fetch from the target's own task.json state
            this.data = await callApi('get_findings', this.targetName);
            this.updateBadges();
            this.render();
        } catch (e) {
            console.error(`[Findings] Failed to fetch for ${this.targetName}:`, e);
        }
    }

    updateBadges() {
        if (!this.data) return;
        const total = this.data.total_count || 0;
        if (this.headerBadge) this.headerBadge.innerText = total;

        const badgeAll = document.getElementById('badge-all');
        if (badgeAll) badgeAll.innerText = total;

        const categories = this.data.categories || {};
        for (const [cat, items] of Object.entries(categories)) {
            const b = document.getElementById(`badge-${cat}`);
            if (b) b.innerText = Array.isArray(items) ? items.length : 0;
        }
    }

    open(category = 'all') {
        this.currentCategory = category;
        this.setActiveTab(category);
        this.drawerEl?.classList.add('open');
        this.render();
    }

    close() {
        this.drawerEl?.classList.remove('open');
    }

    setActiveTab(category) {
        document.querySelectorAll('.category-tab').forEach(tab => {
            if (tab.getAttribute('data-category') === category) {
                tab.classList.add('active');
            } else {
                tab.classList.remove('active');
            }
        });
    }

    render() {
        if (!this.listEl) return;
        this.listEl.innerHTML = '';

        if (!this.data || !this.data.categories) {
            this.listEl.innerHTML = `<div class="findings-empty-state"><span>No findings discovered yet.</span></div>`;
            return;
        }

        const searchQuery = (this.searchEl?.value || '').toLowerCase().trim();
        let itemsToRender = [];

        if (this.currentCategory === 'all') {
            for (const [cat, items] of Object.entries(this.data.categories)) {
                if (Array.isArray(items)) {
                    items.forEach(it => itemsToRender.push({ category: cat, value: it }));
                }
            }
        } else {
            const catItems = this.data.categories[this.currentCategory] || [];
            if (Array.isArray(catItems)) {
                catItems.forEach(it => itemsToRender.push({ category: this.currentCategory, value: it }));
            }
        }

        // Apply search filter
        if (searchQuery) {
            itemsToRender = itemsToRender.filter(item => {
                const str = typeof item.value === 'object' ? JSON.stringify(item.value) : String(item.value);
                return str.toLowerCase().includes(searchQuery) || item.category.toLowerCase().includes(searchQuery);
            });
        }

        if (itemsToRender.length === 0) {
            this.listEl.innerHTML = `
                <div class="findings-empty-state">
                    <span>No matching findings in ${this.currentCategory.toUpperCase()}</span>
                </div>
            `;
            return;
        }

        itemsToRender.forEach(item => {
            const card = document.createElement('div');
            card.className = 'finding-card';

            const rawText = typeof item.value === 'object' ? JSON.stringify(item.value, null, 2) : String(item.value);
            const displayText = typeof item.value === 'object' ? (item.value.host || item.value.subdomain || item.value.url || item.value.title || rawText) : String(item.value);

            card.innerHTML = `
                <div class="finding-card-header">
                    <span class="finding-category-tag">${escapeHtml(item.category.replace('_', ' '))}</span>
                </div>
                <div class="finding-value">${escapeHtml(displayText)}</div>
                <div class="finding-card-footer">
                    <button class="btn-finding-copy" title="Copy finding">Copy</button>
                </div>
            `;

            card.querySelector('.btn-finding-copy').onclick = () => {
                copyToClipboard(rawText);
            };

            this.listEl.appendChild(card);
        });
    }

    destroy() {
        // Unbind and clear to ensure zero cross-target data persistence
        if (this.listEl) this.listEl.innerHTML = '';
        this.data = null;
        this.close();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. CHAT CONVERSATION & RENDERING
// ─────────────────────────────────────────────────────────────────────────────

async function loadTargetChatHistory(targetName) {
    const threadEl = document.getElementById('chatThread');
    if (!threadEl) return;

    threadEl.innerHTML = '';

    try {
        const history = await callApi('get_chat_history', targetName) || [];
        if (history.length === 0) {
            showWelcomeHero();
            return;
        }

        history.forEach(msg => {
            appendMessageBubble(msg.role, msg.content, msg.chips || [], msg.emits || [], false);
        });

        scrollToBottom();
    } catch (e) {
        console.error("Error loading chat history:", e);
    }
}

// ══════════════════════════════════════════════════════
// MISSION BRIEFING VOICE
// Backend-driven TTS via Fish Audio (see VoiceService in
// hellhound/core/voice_service.py, exposed through HellhoundAPI in
// gui_app.py) — NOT the browser's speechSynthesis, NOT pyttsx3/edge-tts.
// Each user configures their own Fish Audio API key + reference voice
// in Settings > Voice; nothing is hardcoded and nothing lives in .env.
//
// window.onVoiceEvent(...) is pushed by VoiceService's event callback via
// evaluate_js — real start/end/unavailable/error callbacks, not a timer.
// ══════════════════════════════════════════════════════
let voiceEnabled = true;
let voiceConfigured = false; // set from get_voice_settings() on load
let lastBriefingText = '';

async function initVoiceState() {
    try {
        const settings = await callApi('get_voice_settings');
        voiceEnabled = settings?.enabled !== false;
        voiceConfigured = !!settings?.configured;
        setVoiceUI(!voiceConfigured ? 'unavailable' : (voiceEnabled ? 'idle' : 'off'));
    } catch (err) {
        console.warn('[Voice] could not load voice settings:', err);
    }
}

function setVoiceUI(state, reason) {
    // state: 'idle' | 'speaking' | 'off' | 'unavailable'
    const btn = document.getElementById('voiceToggleBtn');
    const label = document.getElementById('voiceToggleLabel');
    const logo = document.querySelector('.header-logo-img, .brand-logo');
    if (btn && label) {
        btn.classList.toggle('voice-off', state === 'off' || state === 'unavailable');
        btn.classList.toggle('speaking', state === 'speaking');
        label.innerText = state === 'unavailable' ? 'VOICE UNAVAILABLE' : (state === 'off' ? 'MUTE VOICE' : (state === 'speaking' ? 'SPEAKING' : 'SPEAK BRIEFING'));
        btn.title = (state === 'unavailable' && reason) ? reason : 'Click to open Voice Settings';
    }
    // Wolf-eye glow: intensify the existing logo glow while actually speaking
    logo?.classList.toggle('eyes-glowing', state === 'speaking');
}

function pushWaveformTick() {
    const wave = document.getElementById('voiceWaveform');
    if (!wave) return;
    wave.querySelectorAll('.wave-bar').forEach(bar => {
        bar.style.height = `${30 + Math.random() * 70}%`;
    });
}

window.onVoiceEvent = function (evt) {
    if (evt.type === 'start') {
        setVoiceUI('speaking');
    } else if (evt.type === 'word') {
        pushWaveformTick(); // real per-word callback from the engine, not a fake interval
    } else if (evt.type === 'end') {
        setVoiceUI(voiceEnabled ? 'idle' : 'off');
        document.getElementById('voiceWaveform')?.querySelectorAll('.wave-bar').forEach(bar => {
            bar.style.height = '8%';
        });
    } else if (evt.type === 'unavailable') {
        setVoiceUI('unavailable', evt.payload?.reason);
        console.warn('[Voice] unavailable:', evt.payload?.reason);
    } else if (evt.type === 'error') {
        console.error('[Voice] engine error:', evt.payload?.error);
        setVoiceUI('unavailable', evt.payload?.error);
    }
};

// Opens Settings straight to the Voice tab — the "Open Voice Settings"
// escape hatch shown whenever voice is unavailable, per spec.
async function openVoiceSettingsTab() {
    await openSettingsModal();
    document.querySelector('.settings-tab[data-settings-tab="voice"]')?.click();
}

function buildBriefingText(targetName, findingsData) {
    const total = findingsData?.total_count || 0;
    if (total === 0) {
        return `Welcome back, hunter. Target ${targetName} is engaged with no findings on record yet. Ready for your first command.`;
    }
    const cats = findingsData?.categories || {};
    const parts = [];
    const label = (key) => ({
        takeover_candidates: 'takeover candidate',
        subdomains: 'subdomain',
        open_ports: 'open port',
        live_hosts: 'live host',
        endpoints: 'endpoint',
        vulnerabilities: 'vulnerability',
        tls_info: 'T L S finding',
    }[key] || key.replace(/_/g, ' '));
    for (const [cat, items] of Object.entries(cats)) {
        const n = Array.isArray(items) ? items.length : 0;
        if (n > 0) parts.push(`${n} ${label(cat)}${n === 1 ? '' : 's'}`);
    }
    const highPriority = (cats.takeover_candidates?.length || 0) + (cats.vulnerabilities?.length || 0);
    let text = `Welcome back, hunter. Target ${targetName} has ${total} total findings on record: ${parts.join(', ')}.`;
    if (highPriority > 0) {
        text += ` ${highPriority} of those require verification before they're report-ready.`;
    }
    return text;
}

async function speakBriefing(text) {
    if (!voiceEnabled || !text) return;
    if (!voiceConfigured) {
        setVoiceUI('unavailable');
        return;
    }
    lastBriefingText = text;
    try {
        const res = await callApi('speak_briefing', text);
        if (res?.status === 'unavailable' || res?.status === 'error') {
            console.error('[Voice] speak_briefing failed:', res.reason || res);
            setVoiceUI('unavailable', res.reason);
        }
    } catch (err) {
        console.error('[Voice] speak_briefing call failed:', err);
        setVoiceUI('unavailable', err?.message);
    }
}

async function stopSpeaking() {
    try { await callApi('stop_speaking'); } catch (err) { /* engine may already be idle */ }
    setVoiceUI(voiceEnabled ? 'idle' : 'off');
}

async function replayBriefing() {
    // Replays the cached audio from the last generation instead of
    // re-hitting the Fish Audio API.
    if (!voiceConfigured) {
        setVoiceUI('unavailable');
        return;
    }
    try {
        const res = await callApi('replay_voice');
        if (res?.status === 'unavailable') setVoiceUI('unavailable');
    } catch (err) {
        console.error('[Voice] replay_voice call failed:', err);
    }
}

// Single header button, three behaviors depending on state:
//   unavailable      -> jump to Settings > Voice
//   currently speaking -> Mute (stop playback)
//   idle             -> toggle voice on/off for future briefings
function toggleVoice() {
    if (!voiceConfigured) {
        openVoiceSettingsTab();
        return;
    }
    const btn = document.getElementById('voiceToggleBtn');
    if (btn?.classList.contains('speaking')) {
        stopSpeaking();
        return;
    }
    voiceEnabled = !voiceEnabled;
    if (!voiceEnabled) stopSpeaking();
    setVoiceUI(voiceEnabled ? 'idle' : 'off');
}

function showWelcomeHero() {
    const threadEl = document.getElementById('chatThread');
    if (!threadEl) return;

    threadEl.innerHTML = `
        <div id="welcomeHero" class="welcome-hero">
            <h2 class="welcome-title">AUTONOMOUS RECON ARCHIVE</h2>
            <p class="welcome-desc">
                Engaged target: <strong style="color: #ff5577;">${escapeHtml(currentTarget || 'None')}</strong>.
                Execute scope-aware slash commands or chat directly with the AI agent.
            </p>
        </div>
    `;
}

// Pulls subdomain/permutation/httpx data out of a message's tool_result
// emits. Returns null if there's nothing graph-worthy (no subdomains
// discovered), so the chip only appears when it's actually useful.
function extractReconGraphData(emits) {
    if (!emits || emits.length === 0) return null;

    let rootDomain = null;
    let subdomains = [];
    let permutationMatches = [];   // [{host, a, cname, status_code}]
    const httpxByHost = {};        // hostname -> {status_code, title, tech}

    for (const e of emits) {
        if (e.type !== 'tool_result' || !e.payload) continue;
        const { tool, result } = e.payload;
        if (!result || typeof result !== 'object') continue;

        if ((tool === 'dns_bruteforce' || tool === 'subfinder') && Array.isArray(result.subdomains)) {
            rootDomain = rootDomain || result.domain;
            subdomains = Array.from(new Set([...subdomains, ...result.subdomains]));
        } else if (tool === 'resolve_candidates' && Array.isArray(result.resolved)) {
            permutationMatches = result.resolved;
        } else if (tool === 'httpx' && Array.isArray(result.live_hosts)) {
            for (const h of result.live_hosts) {
                try {
                    const hostname = new URL(h.url).hostname;
                    httpxByHost[hostname] = { status_code: h.status_code, title: h.title, tech: h.tech };
                } catch (_) { /* ignore unparseable url */ }
            }
        }
    }

    if (!rootDomain && subdomains.length === 0) return null;
    if (subdomains.length === 0 && permutationMatches.length === 0) return null;

    return { rootDomain: rootDomain || 'target', subdomains, permutationMatches, httpxByHost };
}

function truncateMiddle(s, max) {
    if (!s) return '';
    if (s.length <= max) return s;
    const keep = Math.floor((max - 3) / 2);
    return s.slice(0, keep) + '...' + s.slice(s.length - keep);
}

function renderReconGraphSVG(data) {
    const { rootDomain, subdomains, permutationMatches, httpxByHost } = data;

    const COL_W = 240;
    const ROW_H = 44;
    const NODE_W = 210;
    const NODE_H = 30;
    const PAD = 20;

    // Build a flat node list with (col, row) grid positions.
    const nodes = [];
    const edges = [];

    nodes.push({ id: 'root', label: rootDomain, col: 0, row: 0, kind: 'root' });

    subdomains.forEach((s, i) => {
        const id = `sub:${s}`;
        nodes.push({ id, label: s, col: 1, row: i, kind: 'subdomain', httpx: httpxByHost[s] });
        edges.push(['root', id]);
    });

    if (permutationMatches.length > 0) {
        const bucketId = 'bucket:permutation';
        nodes.push({ id: bucketId, label: 'Permutation matches', col: 1, row: subdomains.length, kind: 'bucket' });
        edges.push(['root', bucketId]);

        permutationMatches.forEach((m, i) => {
            const id = `perm:${m.host}`;
            nodes.push({ id, label: m.host, col: 2, row: subdomains.length + i, kind: 'permutation', httpx: httpxByHost[m.host] });
            edges.push([bucketId, id]);
        });
    }

    const maxRow = Math.max(...nodes.map(n => n.row), 0);
    const maxCol = Math.max(...nodes.map(n => n.col), 0);
    const width = PAD * 2 + (maxCol + 1) * COL_W;
    const height = PAD * 2 + (maxRow + 1) * ROW_H;

    const pos = {};
    nodes.forEach(n => {
        pos[n.id] = {
            x: PAD + n.col * COL_W,
            y: PAD + n.row * ROW_H + NODE_H / 2
        };
    });

    const edgePaths = edges.map(([fromId, toId]) => {
        const a = pos[fromId], b = pos[toId];
        const x1 = a.x + NODE_W, y1 = a.y;
        const x2 = b.x, y2 = b.y;
        const midX = (x1 + x2) / 2;
        return `<path d="M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}" class="graph-edge" />`;
    }).join('');

    const nodeEls = nodes.map(n => {
        const p = pos[n.id];
        let statusClass = 'unknown';
        let statusLabel = '';
        if (n.httpx) {
            const code = n.httpx.status_code;
            statusClass = code && code < 400 ? 'live' : 'dead';
            statusLabel = code ? String(code) : '';
        }
        return `
            <g class="graph-node graph-node-${n.kind} status-${statusClass}" transform="translate(${p.x}, ${p.y - NODE_H / 2})">
                <rect width="${NODE_W}" height="${NODE_H}" rx="6"></rect>
                <circle cx="14" cy="${NODE_H / 2}" r="4" class="graph-status-dot"></circle>
                <text x="26" y="${NODE_H / 2 + 4}" class="graph-node-label">${escapeHtml(truncateMiddle(n.label, 26))}</text>
                ${statusLabel ? `<text x="${NODE_W - 10}" y="${NODE_H / 2 + 4}" text-anchor="end" class="graph-status-label">${statusLabel}</text>` : ''}
                <title>${escapeHtml(n.label)}${n.httpx?.title ? ' \u2014 ' + escapeHtml(n.httpx.title) : ''}</title>
            </g>
        `;
    }).join('');

    return `
        <div class="graph-scroll">
            <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
                ${edgePaths}
                ${nodeEls}
            </svg>
        </div>
    `;
}

function appendMessageBubble(role, content, chips = [], emits = [], scroll = true, metrics = null) {
    const threadEl = document.getElementById('chatThread');
    if (!threadEl) return;

    // Remove welcome hero if present
    const hero = document.getElementById('welcomeHero');
    if (hero) hero.remove();

    // Remove any streaming caret placeholder message
    const activeStream = threadEl.querySelector('.streaming-assistant-msg');
    if (activeStream) activeStream.remove();

    const msgEl = document.createElement('div');
    msgEl.className = `chat-msg ${role}`;

    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const formattedHtml = formatMarkdown(content);

    if (role === 'user') {
        msgEl.innerHTML = `
            <div class="user-bubble">
                <div class="user-header" style="text-align: right; margin-bottom: 4px;">
                    <button class="btn-msg-copy" title="Copy text" style="background:none; border:none; color:#888; cursor:pointer; font-size:12px;">Copy</button>
                </div>
                <div class="user-body">${formattedHtml}</div>
            </div>
        `;
        msgEl.querySelector('.btn-msg-copy')?.addEventListener('click', () => {
            copyToClipboard(content);
        });
    } else {
        let chipsHtml = '';
        if (chips && chips.length > 0) {
            chipsHtml = `<div class="finding-chips-container">` + chips.map(c => `
                <button class="finding-chip" data-category="${escapeHtml(c.category)}">
                    <span>${escapeHtml(c.label)}</span>
                    <span class="chip-count">${c.count}</span>
                </button>
            `).join('') + `</div>`;
        }

        let emitsHtml = '';
        if (emits && emits.length > 0) {
            emitsHtml = `<div class="tool-emits-container">` + emits.map(e => renderToolEmitCard(e)).join('') + `</div>`;
        }

        const graphData = extractReconGraphData(emits);
        let graphChipHtml = '';
        if (graphData) {
            graphChipHtml = `
                <button class="findings-map-toggle">
                    <span class="findings-map-icon">&#x2318;</span>
                    <span>Findings Map</span>
                    <span class="findings-map-count">${graphData.subdomains.length + graphData.permutationMatches.length} host(s)</span>
                </button>
                <div class="findings-map-panel" style="display: none;"></div>
            `;
        }

        msgEl.innerHTML = `
            <div class="assistant-bubble">
                <div class="assistant-header">
                    <div class="assistant-tag">
                        <img src="../Images/logo.png" alt="" class="assistant-avatar-icon" onerror="this.style.display='none'">
                        <span>HELLHOUND AI</span>
                        <span class="assistant-timestamp">${timeStr}</span>
                    </div>
                    <div class="assistant-actions" style="display: flex; align-items: center; gap: 10px;">
                        ${metrics ? `<span style="font-size: 10px; color: #888; font-family: monospace;">${metrics.tokens} tokens | ${metrics.time_sec}s</span>` : ''}
                        <button class="btn-msg-copy" title="Copy response">Copy</button>
                    </div>
                </div>
                ${emitsHtml}
                <div class="assistant-body">${formattedHtml}</div>
                ${chipsHtml}
                ${graphChipHtml}
            </div>
        `;

        let fullOutputToCopy = content;
        if (emits && emits.length > 0) {
            fullOutputToCopy = emits.map(e => `[${e.type.toUpperCase()}] ${typeof e.payload === 'object' ? JSON.stringify(e.payload) : String(e.payload)}`).join('\n') + '\n\n' + content;
        }

        msgEl.querySelector('.btn-msg-copy')?.addEventListener('click', () => {
            copyToClipboard(fullOutputToCopy);
        });

        wireCodeBlockCopyButtons(msgEl.querySelector('.assistant-body'));

        // Add interactive event listeners on finding chips
        msgEl.querySelectorAll('.finding-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                const category = chip.getAttribute('data-category');
                if (findingsComponent) {
                    findingsComponent.open(category);
                }
            });
        });

        // Wire Findings Map toggle
        const mapToggle = msgEl.querySelector('.findings-map-toggle');
        const mapPanel = msgEl.querySelector('.findings-map-panel');
        if (mapToggle && mapPanel && graphData) {
            mapToggle.onclick = () => {
                const open = mapPanel.style.display !== 'none';
                mapPanel.style.display = open ? 'none' : 'block';
                mapToggle.classList.toggle('open', !open);
                if (!open && !mapPanel.dataset.rendered) {
                    mapPanel.innerHTML = renderReconGraphSVG(graphData);
                    mapPanel.dataset.rendered = '1';
                }
            };
        }
    }

    threadEl.appendChild(msgEl);

    if (scroll) {
        scrollToBottom();
    }
}

// Per-turn state for the live status widget. Reset in handleSendMessage
// right before each request starts.
let _turnHasToolRun = false;
let _turnHasStreamedToken = false;

function handleIncomingEmit(data) {
    console.log("[AGENT EMIT]", data);

    // Hard guard: once a turn is no longer executing (response returned,
    // stopped, or errored), drop anything that still arrives. Without this,
    // a straggling backend tick (the thinking-indicator thread ticks every
    // ~80ms and isn't guaranteed to stop instantly) can land *after* we've
    // already cleaned up the DOM and recreate a status node that then never
    // gets removed — that's the "stale HELLHOUND... (Ns · esc to interrupt)"
    // bug. Ignoring all post-completion emits fixes it at the source.
    if (!isExecuting) return;

    const thread = document.getElementById('chatThread');
    if (!thread) return;

    if (data.type === 'token') {
        _turnHasStreamedToken = true;
        // Actual text is now flowing — that IS the live feedback, so drop
        // any pre-content "Thinking" spinner immediately (Fix 3: no
        // execution status once real output has started, unless a tool
        // is genuinely running).
        if (!_turnHasToolRun) {
            thread.querySelector('.in-flight-emit-msg')?.remove();
        }

        let streamingMsg = thread.querySelector('.streaming-assistant-msg');
        if (!streamingMsg) {
            streamingMsg = document.createElement('div');
            streamingMsg.className = 'chat-msg assistant streaming-assistant-msg';
            streamingMsg.innerHTML = `
                <div class="assistant-bubble">
                    <div class="assistant-header">
                        <div class="assistant-tag">
                            <img src="../Images/logo.png" alt="" class="assistant-avatar-icon" onerror="this.style.display='none'">
                            <span>HELLHOUND AI</span>
                            <span class="assistant-timestamp">${formatRelativeTime(new Date().toISOString())}</span>
                        </div>
                    </div>
                    <div class="assistant-body"></div>
                </div>
            `;
            thread.appendChild(streamingMsg);
        }
        const bodyEl = streamingMsg.querySelector('.assistant-body');
        if (bodyEl) {
            streamingMsg.dataset.accumulated = (streamingMsg.dataset.accumulated || '') + (data.payload || '');
            bodyEl.innerHTML = formatMarkdown(streamingMsg.dataset.accumulated) + '<span class="stream-caret"></span>';
            wireCodeBlockCopyButtons(bodyEl);
        }
        scrollToBottom();
        return;
    }

    // Everything below this line concerns the live execution-status widget.
    // Rule (Fix 3): a generic "status"/"info" tick with no tool involved and
    // no content yet is the pre-first-token "thinking" phase and IS shown;
    // once a tool has actually started, or once tokens are flowing, generic
    // ticks just update the existing widget rather than resurrecting it.
    const wrapperExists = !!thread.querySelector('.in-flight-emit-msg');
    // tool_start/tool_result are always meaningful (Fix 3's "tool execution
    // shows live status"). warn/error/success are discrete, actionable
    // events (e.g. a scope violation) and are always shown too — only the
    // routine "status"/"info" chatter is gated to the pre-content phase.
    const isAlwaysShow = data.type === 'tool_start' || data.type === 'tool_result'
        || data.type === 'warn' || data.type === 'error' || data.type === 'success';
    const isPreContentThinkingTick = (data.type === 'status' || data.type === 'info') && !_turnHasToolRun && !_turnHasStreamedToken;

    if (!isAlwaysShow && !isPreContentThinkingTick && !wrapperExists) {
        // Pure conversation, no tool ever ran, content already streaming —
        // nothing to show. Drop it.
        return;
    }

    // Single in-flight wrapper for the whole turn: a spinner-based live
    // status line ("⟳ Thinking · 1s" / "⟳ Running subfinder · 4s") + a row
    // of small chips for tools currently executing + a results area for
    // evidence cards/lines once a tool actually returns something. No
    // bordered terminal strip.
    let liveWrapper = thread.querySelector('.in-flight-emit-msg');
    if (!liveWrapper) {
        liveWrapper = document.createElement('div');
        liveWrapper.className = 'chat-msg assistant in-flight-emit-msg';
        liveWrapper.innerHTML = `
            <div class="assistant-bubble" style="padding: 4px 4px 4px 0;">
                <div class="live-status-line">
                    <span class="live-status-spinner"></span>
                    <span class="live-status-text">Thinking</span>
                    <span class="live-status-timer">0s</span>
                </div>
                <div class="tool-chip-row"></div>
                <div class="tool-emits-container active-in-flight-emits"></div>
            </div>
        `;
        thread.appendChild(liveWrapper);
        scrollToBottom();
    }

    const statusTextEl = liveWrapper.querySelector('.live-status-text');
    const chipRow = liveWrapper.querySelector('.tool-chip-row');
    const resultsContainer = liveWrapper.querySelector('.active-in-flight-emits');

    if (data.type === 'tool_start') {
        _turnHasToolRun = true;
        const tool = data.payload?.tool || 'tool';
        if (statusTextEl) statusTextEl.textContent = `Running ${tool}`;
        if (chipRow) {
            const existing = chipRow.querySelector(`[data-chip-tool="${cssEscape(tool)}"]`);
            if (!existing) {
                const chip = document.createElement('span');
                chip.className = 'tool-chip';
                chip.setAttribute('data-chip-tool', tool);
                chip.innerHTML = `<span class="tool-chip-dot"></span><span>${escapeHtml(tool)}</span>`;
                chipRow.appendChild(chip);
            }
        }
        scrollToBottom();
        return;
    }

    if (data.type === 'status' || data.type === 'info') {
        const msg = typeof data.payload === 'object' ? (data.payload?.message || data.payload?.text || '') : String(data.payload || '');
        if (statusTextEl && msg) statusTextEl.textContent = ChatRenderer.friendlyError(msg);
        scrollToBottom();
        return;
    }

    if (data.type === 'tool_result') {
        const tool = data.payload?.tool;
        if (chipRow && tool) {
            const chip = chipRow.querySelector(`[data-chip-tool="${cssEscape(tool)}"]`);
            if (chip) chip.remove();
        }
        if (resultsContainer) {
            const cardHtml = renderToolEmitCard(data);
            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = cardHtml;
            resultsContainer.appendChild(tempDiv.firstElementChild || tempDiv);
        }
        scrollToBottom();
        // Live findings drawer sync: a tool_result almost always means new
        // state was written to the target's task.json, so refresh the
        // drawer as it happens rather than waiting for the whole turn.
        scheduleLiveFindingsRefresh();
        return;
    }

    // Fallback for any other emit type (warn/error/success/etc.)
    if (resultsContainer) {
        const cardHtml = renderToolEmitCard(data);
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = cardHtml;
        resultsContainer.appendChild(tempDiv.firstElementChild || tempDiv);
        scrollToBottom();
    }
}

// data-chip-tool values are tool names (alnum/underscore in practice) but
// escape defensively since they come from the backend.
function cssEscape(s) {
    return String(s).replace(/["\\]/g, '\\$&');
}

let _liveFindingsRefreshTimer = null;
function scheduleLiveFindingsRefresh() {
    if (!findingsComponent) return;
    if (_liveFindingsRefreshTimer) return; // already queued, coalesce bursts
    _liveFindingsRefreshTimer = setTimeout(() => {
        _liveFindingsRefreshTimer = null;
        findingsComponent.refreshData();
    }, 400);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. MESSAGE SENDING & EXECUTION CONTROL
// ─────────────────────────────────────────────────────────────────────────────

async function handleSendMessage() {
    const input = document.getElementById('chatInput');
    if (!input || isExecuting) return;

    const text = input.value.trim();
    if (!text) return;

    if (!currentTarget) {
        alert("Please create or select a target first.");
        return;
    }

    // Clear input & reset height
    input.value = '';
    input.style.height = 'auto';
    hideSlashPalette();

    // Render User Message immediately
    appendMessageBubble('user', text);

    // Reset per-turn live-status state and sweep any stale in-flight nodes
    // from a previous turn before starting fresh.
    _turnHasToolRun = false;
    _turnHasStreamedToken = false;
    document.querySelectorAll('.in-flight-emit-msg, .streaming-assistant-msg').forEach(el => el.remove());

    // Update execution UI state
    setExecutionState(true);

    try {
        const res = await callApi('send_message', currentTarget, text);
        
        // Remove in-flight emit bubble and any leftover streaming
        // placeholder — the finished bubble below is the sole source of
        // truth for this turn's content.
        document.querySelectorAll('.in-flight-emit-msg, .streaming-assistant-msg').forEach(el => el.remove());

        if (res) {
            appendMessageBubble('assistant', res.response, res.chips || [], res.emits || [], true, res.metrics);
            // Refresh isolated findings drawer data and sidebar counts
            if (findingsComponent) {
                await findingsComponent.refreshData();
            }
            await loadTargetsList();
        }
    } catch (err) {
        console.error("Error executing query:", err);
        document.querySelectorAll('.in-flight-emit-msg, .streaming-assistant-msg').forEach(el => el.remove());
        appendMessageBubble('assistant', `Error: ${err.message || err}`);
    } finally {
        setExecutionState(false);
    }
}

async function handleStopRequest() {
    if (!currentTarget) return;
    try {
        await callApi('stop_request', currentTarget);
        setExecutionState(false);
        document.querySelectorAll('.in-flight-emit-msg, .streaming-assistant-msg').forEach(el => el.remove());
        appendMessageBubble('assistant', '*[Execution stopped by user]*');
    } catch (e) {
        console.error("Error stopping request:", e);
    }
}

let _executionTimerInterval = null;
let _executionStartedAt = 0;

function setExecutionState(executing) {
    isExecuting = executing;
    const sendBtn = document.getElementById('sendBtn');
    const chatInput = document.getElementById('chatInput');

    if (sendBtn) {
        if (executing) {
            sendBtn.innerHTML = '<span>■</span>';
            sendBtn.title = 'Stop active task';
            sendBtn.classList.add('btn-stop-mode');
        } else {
            sendBtn.innerHTML = '<span>➤</span>';
            sendBtn.title = 'Send message (Enter)';
            sendBtn.classList.remove('btn-stop-mode');
        }
    }
    if (chatInput) {
        chatInput.placeholder = executing ? 'Executing toolchain and reasoning...' : 'Type a message or /command...';
    }

    if (executing) {
        _executionStartedAt = Date.now();
        if (_executionTimerInterval) clearInterval(_executionTimerInterval);
        _executionTimerInterval = setInterval(() => {
            const timerEl = document.querySelector('.in-flight-emit-msg .live-status-timer');
            if (timerEl) {
                const secs = Math.max(0, Math.round((Date.now() - _executionStartedAt) / 1000));
                timerEl.textContent = `${secs}s`;
            }
        }, 1000);
    } else if (_executionTimerInterval) {
        clearInterval(_executionTimerInterval);
        _executionTimerInterval = null;
    }
}

// Nested subcommand suggestions, keyed by base command.
// Structure: { <cmd>: { <parent-token-path>: [ {value, desc}, ... ] } }
// "" (empty string key) = suggestions shown right after the base command itself.
const SLASH_SUBCOMMANDS = {
    "/recon": {
        "": [
            { value: "subdomains", desc: "Asset discovery only (subfinder/dns_bruteforce)" },
            { value: "endpoints", desc: "Content and endpoint discovery only (spider)" },
            { value: "tech", desc: "Live-host and technology fingerprinting only (httpx)" },
        ],
        "subdomains": [
            { value: "active", desc: "DNS brute-force enumeration (CTF/lab targets, isolated zones)" },
            { value: "passive", desc: "CT-log/passive sources via subfinder (default for public targets)" },
            { value: "permute", desc: "Generate + resolve mutated candidate subdomains from found hosts" },
        ],
    },
};
// /surface and /spider are aliases of /recon — reuse the same tree.
SLASH_SUBCOMMANDS["/surface"] = SLASH_SUBCOMMANDS["/recon"];
SLASH_SUBCOMMANDS["/spider"] = SLASH_SUBCOMMANDS["/recon"];

// ─────────────────────────────────────────────────────────────────────────────
// 6. SLASH COMMAND PALETTE & AUTOCOMPLETE
// ─────────────────────────────────────────────────────────────────────────────

let selectedSlashIndex = 0;
let currentSlashMatches = [];   // [{ value, desc, usage }]
let currentReplaceStart = 0;    // index in input.value where the match gets spliced in

function setupSlashPalette() {
    const input = document.getElementById('chatInput');
    const palette = document.getElementById('slashPalette');
    if (!input || !palette) return;

    input.addEventListener('input', () => {
        const val = input.value;
        if (val.startsWith('/')) {
            renderSlashPalette(val);
        } else {
            hideSlashPalette();
        }
    });

    input.addEventListener('keydown', (e) => {
        if (palette.style.display === 'flex') {
            const items = palette.querySelectorAll('.slash-item');
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                selectedSlashIndex = (selectedSlashIndex + 1) % items.length;
                updateSlashSelection(items);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                selectedSlashIndex = (selectedSlashIndex - 1 + items.length) % items.length;
                updateSlashSelection(items);
            } else if (e.key === 'Enter' || e.key === 'Tab') {
                if (items.length > 0 && selectedSlashIndex < items.length) {
                    e.preventDefault();
                    applySlashMatch(selectedSlashIndex);
                }
            } else if (e.key === 'Escape') {
                hideSlashPalette();
            }
        } else if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSendMessage();
        }
    });
}

// Computes { matches, replaceStart } for the current input value.
// replaceStart is the character index in `value` where the currently-typed
// word begins — the part that gets replaced when a suggestion is chosen.
function getSlashMatches(value) {
    const trailingSpace = /\s$/.test(value);
    const tokens = value.split(/\s+/).filter(Boolean);
    if (tokens.length === 0) return { matches: [], replaceStart: 0 };

    const currentWord = trailingSpace ? '' : tokens[tokens.length - 1];
    const replaceStart = value.length - currentWord.length;

    // Still typing/filtering the base command itself
    if (tokens.length === 1 && !trailingSpace) {
        const filter = currentWord.slice(1).toLowerCase();
        const matches = SLASH_COMMANDS
            .filter(c => c.cmd.slice(1).startsWith(filter))
            .map(c => ({ value: c.cmd, desc: c.desc, usage: c.usage }));
        return { matches, replaceStart: 0 }; // base command always replaces the whole input
    }

    // Subcommand level(s)
    const cmdName = tokens[0].toLowerCase();
    const tree = SLASH_SUBCOMMANDS[cmdName];
    if (!tree) return { matches: [], replaceStart };

    const completedArgTokens = (trailingSpace ? tokens.slice(1) : tokens.slice(1, -1))
        .map(t => t.toLowerCase());

    // Path key: "" for right after the base command, else the first arg token
    const pathKey = completedArgTokens.length === 0 ? "" : completedArgTokens[0];
    const candidates = tree[pathKey] || [];

    // Don't re-suggest a value that's already been typed for this command
    const already = new Set(completedArgTokens.slice(pathKey === "" ? 0 : 1));
    const filtered = candidates.filter(c => !already.has(c.value.toLowerCase()));

    const matches = filtered
        .filter(c => c.value.toLowerCase().startsWith(currentWord.toLowerCase()))
        .map(c => ({ value: c.value, desc: c.desc, usage: '' }));

    return { matches, replaceStart };
}

function renderSlashPalette(query) {
    const palette = document.getElementById('slashPalette');
    if (!palette) return;

    const { matches, replaceStart } = getSlashMatches(query);
    currentSlashMatches = matches;
    currentReplaceStart = replaceStart;

    if (matches.length === 0) {
        hideSlashPalette();
        return;
    }

    palette.innerHTML = '';
    selectedSlashIndex = 0;

    // Breadcrumb: show completed tokens once we're past the base command
    const trailingSpace = /\s$/.test(query);
    const tokens = query.split(/\s+/).filter(Boolean);
    const completed = trailingSpace ? tokens : tokens.slice(0, -1);
    if (completed.length > 1) {
        const crumb = document.createElement('div');
        crumb.className = 'slash-breadcrumb';
        crumb.textContent = completed.join(' \u203a ');  // "› " separator
        palette.appendChild(crumb);
    }

    matches.forEach((c, idx) => {
        const item = document.createElement('div');
        item.className = `slash-item ${idx === 0 ? 'selected' : ''}`;
        item.setAttribute('data-cmd', c.value);

        item.innerHTML = `
            <div class="slash-item-left">
                <span class="slash-item-cmd">${c.value}</span>
                <span class="slash-item-desc">${c.desc}</span>
            </div>
            <span class="slash-item-usage">${c.usage || ''}</span>
        `;

        item.onclick = () => applySlashMatch(idx);

        palette.appendChild(item);
    });

    palette.style.display = 'flex';
}

// Splices the chosen suggestion into the input at currentReplaceStart,
// replacing only the word currently being typed — preserves everything
// typed before it (target, prior subcommand tokens, etc).
function applySlashMatch(idx) {
    const input = document.getElementById('chatInput');
    const match = currentSlashMatches[idx];
    if (!input || !match) return;

    const before = input.value.slice(0, currentReplaceStart);
    input.value = before + match.value + ' ';
    input.focus();

    const { matches } = getSlashMatches(input.value);
    if (matches.length === 0) {
        hideSlashPalette();
    } else {
        renderSlashPalette(input.value);
    }
}

function updateSlashSelection(items) {
    items.forEach((it, i) => {
        if (i === selectedSlashIndex) {
            it.classList.add('selected');
            it.scrollIntoView({ block: 'nearest' });
        } else {
            it.classList.remove('selected');
        }
    });
}

function hideSlashPalette() {
    const palette = document.getElementById('slashPalette');
    if (palette) palette.style.display = 'none';
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. SYSTEM INFO & SCOPE MODAL
// ─────────────────────────────────────────────────────────────────────────────

async function refreshSystemInfo() {
    try {
        const info = await callApi('get_system_info');
        if (info) {
            const modelLabel = document.getElementById('modelLabel');
            if (modelLabel) {
                modelLabel.innerText = `${info.ai_provider}:${info.ai_model}`;
            }
            const verLabel = document.getElementById('versionLabel');
            if (verLabel && info.version) {
                verLabel.innerText = `v${info.version}`;
            }
        }
    } catch (e) {
        console.error("Failed to load system info:", e);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. DOM EVENT HANDLERS & MODALS
// ─────────────────────────────────────────────────────────────────────────────

function setupDOMEventHandlers() {
    // Send / Stop Button Toggle
    document.getElementById('sendBtn')?.addEventListener('click', () => {
        if (isExecuting) {
            handleStopRequest();
        } else {
            handleSendMessage();
        }
    });

    // Clean UI Toggle
    document.getElementById('bgToggleBtn')?.addEventListener('click', () => {
        document.body.classList.toggle('clean-interface');
    });

    // Voice Toggle
    document.getElementById('voiceToggleBtn')?.addEventListener('click', toggleVoice);

    // Slash Palette
    setupSlashPalette();

    // Auto-expand textarea
    const chatInput = document.getElementById('chatInput');
    chatInput?.addEventListener('input', () => {
        chatInput.style.height = 'auto';
        chatInput.style.height = (chatInput.scrollHeight) + 'px';
    });

    // New Target Modal
    const newTargetBtn = document.getElementById('newTargetBtn');
    const newTargetModal = document.getElementById('newTargetModal');
    const newTargetInput = document.getElementById('newTargetInput');
    const confirmNewTargetBtn = document.getElementById('confirmNewTargetBtn');
    const cancelNewTargetBtn = document.getElementById('cancelNewTargetBtn');

    newTargetBtn?.addEventListener('click', () => {
        if (newTargetModal) {
            newTargetModal.classList.add('open');
            newTargetInput.value = '';
            newTargetInput.focus();
        }
    });

    cancelNewTargetBtn?.addEventListener('click', () => {
        newTargetModal?.classList.remove('open');
    });

    confirmNewTargetBtn?.addEventListener('click', async () => {
        const name = newTargetInput?.value;
        if (name && name.trim()) {
            newTargetModal?.classList.remove('open');
            await createTarget(name.trim());
        }
    });

    newTargetInput?.addEventListener('keydown', async (e) => {
        if (e.key === 'Enter') {
            const name = newTargetInput?.value;
            if (name && name.trim()) {
                newTargetModal?.classList.remove('open');
                await createTarget(name.trim());
            }
        } else if (e.key === 'Escape') {
            newTargetModal?.classList.remove('open');
        }
    });

    // Scope Modal
    const scopeModal = document.getElementById('scopeModal');
    const scopeInlineBtn = document.getElementById('scopeInlineBtn');
    const scopeTextInput = document.getElementById('scopeTextInput');
    const saveScopeBtn = document.getElementById('saveScopeBtn');
    const cancelScopeBtn = document.getElementById('cancelScopeBtn');

    const openScopeModal = async () => {
        if (!currentTarget) return;
        try {
            const targetData = await callApi('get_target', currentTarget);
            if (scopeTextInput && targetData) {
                const inScope = (targetData.scope_rules?.in_scope || []).join('\n');
                scopeTextInput.value = inScope;
            }
            scopeModal?.classList.add('open');
        } catch (e) {
            console.error(e);
        }
    };

    scopeInlineBtn?.addEventListener('click', openScopeModal);

    cancelScopeBtn?.addEventListener('click', () => {
        scopeModal?.classList.remove('open');
    });

    saveScopeBtn?.addEventListener('click', async () => {
        if (!currentTarget) return;
        const text = scopeTextInput?.value || '';
        try {
            await callApi('set_scope', currentTarget, text);
            scopeModal?.classList.remove('open');
            await switchTarget(currentTarget);
        } catch (e) {
            alert("Failed to save scope: " + e);
        }
    });

    // Clear Chat Button
    document.getElementById('clearChatBtn')?.addEventListener('click', async () => {
        if (!currentTarget) return;
        const confirmed = await showConfirmModal({
            title: "CLEAR CONVERSATION",
            message: `Clear all message history for target "${currentTarget}"?`,
            confirmText: "CLEAR CHAT"
        });
        if (confirmed) {
            await callApi('clear_chat_history', currentTarget);
            await loadTargetChatHistory(currentTarget);
        }
    });

    // Findings Drawer Toggle & Close
    document.getElementById('findingsToggleBtn')?.addEventListener('click', () => {
        if (findingsComponent) {
            findingsComponent.open('all');
        }
    });

    document.getElementById('closeFindingsBtn')?.addEventListener('click', () => {
        if (findingsComponent) {
            findingsComponent.close();
        }
    });

    // Category Tabs in Findings Panel
    document.querySelectorAll('.category-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const cat = tab.getAttribute('data-category');
            if (findingsComponent) {
                findingsComponent.setActiveTab(cat);
                findingsComponent.currentCategory = cat;
                findingsComponent.render();
            }
        });
    });

    // Search in Findings
    document.getElementById('findingsSearchInput')?.addEventListener('input', () => {
        if (findingsComponent) {
            findingsComponent.render();
        }
    });

    // Target Search
    document.getElementById('targetSearchInput')?.addEventListener('input', () => {
        renderTargetList(targetsList);
    });

    // Sliding Sidebar (hover the rail itself, from the logo down — no
    // separate header logo trigger anymore, just the one rail).
    const sidebar = document.getElementById('sidebar');

    let sidebarHoverTimer = null;

    const openSlidingSidebar = () => {
        if (sidebarHoverTimer) {
            clearTimeout(sidebarHoverTimer);
            sidebarHoverTimer = null;
        }
        sidebar?.classList.add('open');
    };

    const closeSlidingSidebar = () => {
        if (sidebarHoverTimer) clearTimeout(sidebarHoverTimer);
        sidebarHoverTimer = setTimeout(() => {
            sidebar?.classList.remove('open');
        }, 280);
    };

    if (sidebar) {
        sidebar.addEventListener('mouseenter', openSlidingSidebar);
        sidebar.addEventListener('mouseleave', closeSlidingSidebar);
    }

    // Ctrl+B — pin/unpin the nav rail open, independent of hover
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
            e.preventDefault();
            if (sidebarHoverTimer) {
                clearTimeout(sidebarHoverTimer);
                sidebarHoverTimer = null;
            }
            sidebar?.classList.toggle('open');
        }
    });

    // ── Floating Settings Button & Modal Setup ──
    const settingsBtn = document.getElementById('settingsBtn');
    const closeSettingsModalBtn = document.getElementById('closeSettingsModalBtn');
    const cancelSettingsBtn = document.getElementById('cancelSettingsBtn');
    const saveSettingsBtn = document.getElementById('saveSettingsBtn');
    const installMissingToolsBtn = document.getElementById('installMissingToolsBtn');

    settingsBtn?.addEventListener('click', openSettingsModal);
    closeSettingsModalBtn?.addEventListener('click', closeSettingsModal);
    cancelSettingsBtn?.addEventListener('click', closeSettingsModal);
    saveSettingsBtn?.addEventListener('click', saveSettings);

    // Settings Navigation Tabs
    document.querySelectorAll('.settings-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const targetPaneId = 'settings-tab-' + tab.getAttribute('data-settings-tab');
            document.querySelectorAll('.settings-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.settings-tab-pane').forEach(p => p.classList.remove('active'));

            tab.classList.add('active');
            document.getElementById(targetPaneId)?.classList.add('active');
        });
    });

    // Install Missing Tools Action
    installMissingToolsBtn?.addEventListener('click', async () => {
        installMissingToolsBtn.disabled = true;
        const originalText = installMissingToolsBtn.textContent;
        installMissingToolsBtn.textContent = 'INSTALLING TOOLS...';
        try {
            const res = await callApi('install_missing_tools');
            if (res && res.tools) {
                renderToolsGrid(res.tools);
            }
        } catch (e) {
            console.error('Failed to install tools:', e);
        } finally {
            installMissingToolsBtn.disabled = false;
            installMissingToolsBtn.textContent = originalText;
        }
    });

    // Voice: Test / Replay Last Test
    const testVoiceBtn = document.getElementById('testVoiceBtn');
    const replayTestVoiceBtn = document.getElementById('replayTestVoiceBtn');

    testVoiceBtn?.addEventListener('click', async () => {
        testVoiceBtn.disabled = true;
        const original = testVoiceBtn.textContent;
        testVoiceBtn.textContent = 'TESTING...';
        updateVoiceStatusIndicator(null, 'Testing...');
        try {
            await callApi('save_voice_settings', {
                enabled: document.getElementById('cfgVoiceEnabled')?.checked ?? true,
                api_key: document.getElementById('cfgVoiceApiKey')?.value || '',
                reference_id: document.getElementById('cfgVoiceReferenceId')?.value || '',
                model: document.getElementById('cfgVoiceModel')?.value || 's2.1-pro-free',
                speed: parseFloat(document.getElementById('cfgVoiceSpeed')?.value) || 1.08,
            });
            const res = await callApi('test_voice');
            if (res?.status === 'ok') {
                updateVoiceStatusIndicator(true, '✓ Connected');
            } else {
                console.warn('[Voice] test failed:', res);
                updateVoiceStatusIndicator(false, res?.reason || 'Voice unavailable.');
            }
        } catch (e) {
            console.error('[Voice] test_voice failed:', e);
            updateVoiceStatusIndicator(false, 'Call failed: ' + (e?.message || e));
        } finally {
            testVoiceBtn.disabled = false;
            testVoiceBtn.textContent = original;
        }
    });

    replayTestVoiceBtn?.addEventListener('click', async () => {
        try { await callApi('replay_voice'); } catch (e) { console.error('[Voice] replay failed:', e); }
    });

    document.getElementById('installFishAudioBtn')?.addEventListener('click', async (e) => {
        const btn = e.target;
        btn.disabled = true;
        btn.textContent = 'INSTALLING...';
        try {
            const res = await callApi('install_fish_audio_sdk');
            await refreshVoiceDiagnostics();
            if (res?.status !== 'ok') {
                updateVoiceStatusIndicator(false, 'Install failed — see diagnostics below.');
            }
        } catch (err) {
            updateVoiceStatusIndicator(false, 'Install call failed: ' + (err?.message || err));
        } finally {
            btn.disabled = false;
            btn.textContent = 'INSTALL AUTOMATICALLY';
        }
    });

    // API Key Eye Toggle (Show/Hide)
    document.querySelectorAll('.btn-toggle-key').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;
            if (input.type === 'password') {
                input.type = 'text';
                btn.textContent = 'HIDE';
                btn.title = 'Hide key';
            } else {
                input.type = 'password';
                btn.textContent = 'SHOW';
                btn.title = 'Show key';
            }
        });
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 8.5. SETTINGS MODAL CONTROLLER
// ─────────────────────────────────────────────────────────────────────────────

async function openSettingsModal() {
    const modal = document.getElementById('settingsModal');
    const statusSpan = document.getElementById('settingsSaveStatus');
    if (statusSpan) statusSpan.textContent = '';

    try {
        const settings = await callApi('get_settings');
        if (settings) {
            // Models
            const orchProv = document.getElementById('cfgOrchestratorProvider');
            const orchModel = document.getElementById('cfgOrchestratorModel');
            const synthProv = document.getElementById('cfgSynthesizerProvider');
            const synthModel = document.getElementById('cfgSynthesizerModel');

            if (orchProv) orchProv.value = settings.orchestrator_provider || 'ollama';
            if (orchModel) orchModel.value = settings.orchestrator_model || 'qwen2.5:3b-instruct';
            if (synthProv) synthProv.value = settings.synthesizer_provider || 'nvidia';
            if (synthModel) synthModel.value = settings.synthesizer_model || 'nvidia/nemotron-3-super-120b-a12b';

            // API Keys
            const keys = settings.api_keys || {};
            const keyNv = document.getElementById('cfgKeyNvidia');
            const keyAnt = document.getElementById('cfgKeyAnthropic');
            const keyOai = document.getElementById('cfgKeyOpenai');
            const keyOr = document.getElementById('cfgKeyOpenrouter');
            const keyGroq = document.getElementById('cfgKeyGroq');
            const keyGemini = document.getElementById('cfgKeyGemini');

            if (keyNv) keyNv.value = keys.nvidia || '';
            if (keyAnt) keyAnt.value = keys.anthropic || '';
            if (keyOai) keyOai.value = keys.openai || '';
            if (keyOr) keyOr.value = keys.openrouter || '';
            if (keyGroq) keyGroq.value = keys.groq || '';
            if (keyGemini) keyGemini.value = keys.gemini || '';

            // Tools & Auto-Install
            const autoInstall = document.getElementById('cfgAutoInstallTools');
            if (autoInstall) autoInstall.checked = Boolean(settings.auto_install_missing_tools);

            renderToolsGrid(settings.tools);

            // Bug Bounty
            const handle = document.getElementById('cfgResearcherHandle');
            if (handle) handle.value = settings.researcher_handle || '';

            const globalHdrs = document.getElementById('cfgGlobalHeaders');
            if (globalHdrs && settings.global_headers) {
                if (typeof settings.global_headers === 'object') {
                    const lines = Object.entries(settings.global_headers).map(([k, v]) => `${k}: ${v}`);
                    globalHdrs.value = lines.join('\n');
                } else {
                    globalHdrs.value = String(settings.global_headers);
                }
            }
        }
    } catch (e) {
        console.warn('Could not load settings from backend:', e);
    }

    try {
        const voice = await callApi('get_voice_settings');
        if (voice) {
            const enabled = document.getElementById('cfgVoiceEnabled');
            const apiKey = document.getElementById('cfgVoiceApiKey');
            const refId = document.getElementById('cfgVoiceReferenceId');
            const model = document.getElementById('cfgVoiceModel');
            const speed = document.getElementById('cfgVoiceSpeed');
            if (enabled) enabled.checked = voice.enabled !== false;
            // Never populate the real key back into the field — only show a
            // masked placeholder so the user knows one is already saved.
            if (apiKey) {
                apiKey.value = '';
                apiKey.placeholder = voice.api_key_set ? voice.api_key_masked : 'Paste your Fish Audio API key';
            }
            if (refId) refId.value = voice.reference_id || '';
            if (model) model.value = voice.model || 's2.1-pro-free';
            if (speed) speed.value = voice.speed || 1.08;
            updateVoiceStatusIndicator(voice.configured);
            await refreshVoiceDiagnostics();
        }
    } catch (e) {
        console.warn('Could not load voice settings from backend:', e);
    }

    modal?.classList.add('open');
}

function updateVoiceStatusIndicator(connected, message) {
    const dot = document.getElementById('voiceStatusDot');
    const text = document.getElementById('voiceStatusText');
    if (dot) {
        dot.classList.toggle('connected', connected === true);
        dot.classList.toggle('testing', connected === null);
    }
    if (text) {
        text.textContent = message || (connected ? '✓ Connected' : 'Not configured');
        text.style.color = connected === false ? '#f87171' : '';
    }
}

async function refreshVoiceDiagnostics() {
    // Always reads sys.executable live from the running process — never a
    // cached or hardcoded interpreter path.
    const block = document.getElementById('voiceDiagBlock');
    const installBtn = document.getElementById('installFishAudioBtn');
    if (!block) return;
    try {
        const d = await callApi('get_voice_diagnostics');
        block.textContent =
            `Python           ${d.python_executable}\n` +
            `Fish Audio       ${d.fishaudio_importable ? '✓ Installed' : '✗ Not installed for this interpreter'}\n` +
            `Voice (ffplay)   ${d.ffplay_path ? '✓ Ready — ' + d.ffplay_path : '✗ Not found on PATH'}`;
        if (installBtn) installBtn.style.display = d.fishaudio_importable ? 'none' : 'inline-block';
    } catch (e) {
        block.textContent = 'Could not read diagnostics: ' + (e?.message || e);
    }
}

function closeSettingsModal() {
    const modal = document.getElementById('settingsModal');
    modal?.classList.remove('open');
}

function renderToolsGrid(toolsData) {
    const grid = document.getElementById('toolsStatusGrid');
    if (!grid) return;
    grid.innerHTML = '';

    if (!toolsData || !toolsData.tools) {
        grid.innerHTML = '<div style="color:var(--text-muted); font-size:11px; padding:10px;">Tool status unavailable</div>';
        return;
    }

    const tools = toolsData.tools;
    Object.keys(tools).sort().forEach(name => {
        const item = tools[name];
        const card = document.createElement('div');
        card.className = 'tool-card';
        const isAvail = Boolean(item.available);
        card.innerHTML = `
            <div class="tool-name">${escapeHtml(name)}</div>
            <span class="tool-status-tag ${isAvail ? 'installed' : 'missing'}">${isAvail ? 'INSTALLED' : 'MISSING'}</span>
        `;
        grid.appendChild(card);
    });
}

async function saveSettings() {
    const statusSpan = document.getElementById('settingsSaveStatus');
    const saveBtn = document.getElementById('saveSettingsBtn');
    if (statusSpan) statusSpan.textContent = 'Saving...';
    if (saveBtn) saveBtn.disabled = true;

    // Parse custom headers
    const rawHeaders = document.getElementById('cfgGlobalHeaders')?.value || '';
    const globalHeaders = {};
    rawHeaders.split('\n').forEach(line => {
        const parts = line.split(':');
        if (parts.length >= 2) {
            const k = parts[0].trim();
            const v = parts.slice(1).join(':').trim();
            if (k) globalHeaders[k] = v;
        }
    });

    // Assemble payload
    const payload = {
        orchestrator_provider: document.getElementById('cfgOrchestratorProvider')?.value || 'ollama',
        orchestrator_model: document.getElementById('cfgOrchestratorModel')?.value || 'qwen2.5:3b-instruct',
        synthesizer_provider: document.getElementById('cfgSynthesizerProvider')?.value || 'nvidia',
        synthesizer_model: document.getElementById('cfgSynthesizerModel')?.value || 'nvidia/nemotron-3-super-120b-a12b',
        api_keys: {
            nvidia: document.getElementById('cfgKeyNvidia')?.value || '',
            anthropic: document.getElementById('cfgKeyAnthropic')?.value || '',
            gemini: document.getElementById('cfgKeyGemini')?.value || '',
            openai: document.getElementById('cfgKeyOpenai')?.value || '',
            openrouter: document.getElementById('cfgKeyOpenrouter')?.value || '',
            groq: document.getElementById('cfgKeyGroq')?.value || '',
        },
        researcher_handle: document.getElementById('cfgResearcherHandle')?.value || '',
        global_headers: globalHeaders,
        auto_install_missing_tools: document.getElementById('cfgAutoInstallTools')?.checked || false,
    };

    const voicePayload = {
        enabled: document.getElementById('cfgVoiceEnabled')?.checked ?? true,
        api_key: document.getElementById('cfgVoiceApiKey')?.value || '',
        reference_id: document.getElementById('cfgVoiceReferenceId')?.value || '',
        model: document.getElementById('cfgVoiceModel')?.value || 's2.1-pro-free',
        speed: parseFloat(document.getElementById('cfgVoiceSpeed')?.value) || 1.08,
    };

    try {
        const res = await callApi('save_settings', payload);
        const voiceRes = await callApi('save_voice_settings', voicePayload);
        voiceEnabled = voiceRes?.settings?.enabled !== false;
        voiceConfigured = !!voiceRes?.settings?.configured;
        updateVoiceStatusIndicator(voiceConfigured);
        setVoiceUI(!voiceConfigured ? 'unavailable' : (voiceEnabled ? 'idle' : 'off'));
        if (statusSpan) {
            statusSpan.textContent = '✓ Configuration saved successfully';
            statusSpan.style.color = '#4ade80';
        }
        setTimeout(() => {
            closeSettingsModal();
            if (statusSpan) statusSpan.textContent = '';
        }, 800);
    } catch (e) {
        if (statusSpan) {
            statusSpan.textContent = 'Error: ' + e;
            statusSpan.style.color = '#f87171';
        }
    } finally {
        if (saveBtn) saveBtn.disabled = false;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. UTILITY HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function scrollToBottom(force = false) {
    const thread = document.getElementById('chatThread');
    if (!thread) return;
    const isAtBottom = (thread.scrollHeight - thread.scrollTop - thread.clientHeight) < 150;
    if (force || isAtBottom) {
        thread.scrollTop = thread.scrollHeight;
    }
}

function wireCodeBlockCopyButtons(containerEl) {
    if (!containerEl) return;
    containerEl.querySelectorAll('.code-block-copy-btn').forEach(btn => {
        if (btn.dataset.wired) return; // avoid double-binding on re-renders (streaming re-sets innerHTML)
        btn.dataset.wired = '1';
        btn.addEventListener('click', () => {
            const codeEl = btn.closest('.code-block')?.querySelector('pre code');
            if (!codeEl) return;
            copyToClipboard(codeEl.textContent);
            btn.textContent = 'Copied';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.textContent = 'Copy';
                btn.classList.remove('copied');
            }, 1500);
        });
    });
}

function copyToClipboard(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.opacity = 0;
    document.body.appendChild(textArea);
    textArea.select();
    try {
        document.execCommand("copy");
        console.log("Copied via execCommand");
    } catch (err) {
        console.error("execCommand copy failed:", err);
    }
    document.body.removeChild(textArea);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatRelativeTime(isoString) {
    try {
        const date = new Date(isoString);
        const now = new Date();
        const diffSecs = Math.floor((now - date) / 1000);
        if (diffSecs < 60) return 'Just now';
        const diffMins = Math.floor(diffSecs / 60);
        if (diffMins < 60) return `${diffMins}m ago`;
        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours}h ago`;
        const diffDays = Math.floor(diffHours / 24);
        return `${diffDays}d ago`;
    } catch {
        return 'Recent';
    }
}

/**
 * Robust Markdown Parser for chat responses supporting tables, headers, lists, code blocks, hr, and inline styling
 */
function formatMarkdown(text) {
    if (!text) return '';

    let html = text;

    // Helper for inline markdown replacements
    const inlineMarkdown = (str) => {
        if (!str) return '';
        return str
            .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
            .replace(/\*([^*]+)\*/g, '<em>$1</em>')
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    };

    // 1. Code blocks (fenced ```...```)
    const codeBlocks = [];
    html = html.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (match, lang, code) => {
        const id = `___CODE_BLOCK_${codeBlocks.length}___`;
        const label = (lang || 'text').toLowerCase();
        const codeText = code.trim();
        codeBlocks.push(
            `<div class="code-block">` +
                `<div class="code-block-header">` +
                    `<span class="code-block-lang">${escapeHtml(label)}</span>` +
                    `<button type="button" class="code-block-copy-btn" title="Copy code">Copy</button>` +
                `</div>` +
                `<pre><code class="language-${escapeHtml(label)}">${escapeHtml(codeText)}</code></pre>` +
            `</div>`
        );
        return id;
    });

    // 2. Markdown Tables
    const tableRegex = /((?:^[ \t]*\|[^\n]+\|[ \t]*\n)+)/gm;
    html = html.replace(tableRegex, (match) => {
        const lines = match.trim().split('\n').map(l => l.trim());
        if (lines.length < 2) return match;

        const headerRow = lines[0];
        const delimiterRow = lines[1];

        if (!/^[ \t]*\|[ \t]*:?-+:?[ \t]*(\|[ \t]*:?-+:?[ \t]*)+\|[ \t]*$/.test(delimiterRow)) {
            return match;
        }

        const parseRow = (rowStr) => rowStr.replace(/^\||\|$/g, '').split('|').map(cell => cell.trim());

        const headers = parseRow(headerRow);
        const bodyLines = lines.slice(2);

        let tableHtml = '<div class="table-container"><table class="markdown-table"><thead><tr>';
        headers.forEach(h => {
            tableHtml += `<th>${inlineMarkdown(escapeHtml(h))}</th>`;
        });
        tableHtml += '</tr></thead><tbody>';

        bodyLines.forEach(bLine => {
            if (!bLine.startsWith('|')) return;
            const cells = parseRow(bLine);
            tableHtml += '<tr>';
            cells.forEach(c => {
                tableHtml += `<td>${inlineMarkdown(escapeHtml(c))}</td>`;
            });
            tableHtml += '</tr>';
        });

        tableHtml += '</tbody></table></div>';
        return tableHtml;
    });

    // 3. Headers
    html = html.replace(/^#### (.*$)/gim, '<h4>$1</h4>');
    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

    // 4. Horizontal Rules
    html = html.replace(/^[ \t]*[-*_]{3,}[ \t]*$/gim, '<hr>');

    // 5. Bold & Italics & Inline Code
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // 6. Bullet lists & Numbered lists
    html = html.replace(/^\s*[-*]\s+(.*$)/gim, '<li>$1</li>');
    html = html.replace(/((?:<li>.*<\/li>\s*)+)/gims, '<ul>$1</ul>');

    // 7. Paragraphs
    const blocks = html.split(/\n\n+/);
    html = blocks.map(b => {
        b = b.trim();
        if (!b) return '';
        if (b.startsWith('<h') || b.startsWith('<pre') || b.startsWith('<ul') || b.startsWith('<div') || b.startsWith('<hr') || b.startsWith('<table') || b.startsWith('___CODE_BLOCK_')) {
            return b;
        }
        return `<p>${b.replace(/\n/g, '<br>')}</p>`;
    }).join('');

    // Restore Code Blocks
    codeBlocks.forEach((cb, idx) => {
        html = html.replace(`___CODE_BLOCK_${idx}___`, cb);
    });

    return html;
}