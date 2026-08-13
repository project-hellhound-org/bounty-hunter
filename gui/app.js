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
                if (confirm(`Delete target "${t.name}" and all associated task data?`)) {
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

function appendMessageBubble(role, content, chips = [], emits = [], scroll = true, metrics = null) {
    const threadEl = document.getElementById('chatThread');
    if (!threadEl) return;

    // Remove welcome hero if present
    const hero = document.getElementById('welcomeHero');
    if (hero) hero.remove();

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
            emitsHtml = `<div class="tool-emits-container">` + emits.map(e => `
                <div class="tool-emit-card ${e.type}">${escapeHtml(typeof e.payload === 'object' ? JSON.stringify(e.payload) : String(e.payload))}</div>
            `).join('') + `</div>`;
        }

        msgEl.innerHTML = `
            <div class="assistant-bubble">
                <div class="assistant-header">
                    <div class="assistant-tag">
                        <span>HELLHOUND AGENT</span>
                    </div>
                    <div class="assistant-actions" style="display: flex; align-items: center; gap: 10px;">
                        ${metrics ? `<span style="font-size: 10px; color: #888; font-family: monospace;">${metrics.tokens} tokens | ${metrics.time_sec}s</span>` : ''}
                        <button class="btn-msg-copy" title="Copy response">Copy</button>
                    </div>
                </div>
                <div class="assistant-body">${formattedHtml}</div>
                ${emitsHtml}
                ${chipsHtml}
            </div>
        `;

        let fullOutputToCopy = content;
        if (emits && emits.length > 0) {
            fullOutputToCopy = emits.map(e => `[${e.type.toUpperCase()}] ${typeof e.payload === 'object' ? JSON.stringify(e.payload) : String(e.payload)}`).join('\n') + '\n\n' + content;
        }

        msgEl.querySelector('.btn-msg-copy')?.addEventListener('click', () => {
            copyToClipboard(fullOutputToCopy);
        });

        // Add interactive event listeners on finding chips
        msgEl.querySelectorAll('.finding-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                const category = chip.getAttribute('data-category');
                if (findingsComponent) {
                    findingsComponent.open(category);
                }
            });
        });
    }

    threadEl.appendChild(msgEl);

    if (scroll) {
        scrollToBottom();
    }
}

function handleIncomingEmit(data) {
    console.log("[AGENT EMIT]", data);
    // Dynamic in-flight emit cards can update the last active assistant message
    const thread = document.getElementById('chatThread');
    if (!thread) return;

    let activeEmitsContainer = thread.querySelector('.active-in-flight-emits');
    if (!activeEmitsContainer) {
        const emitWrapper = document.createElement('div');
        emitWrapper.className = 'chat-msg assistant in-flight-emit-msg';
        emitWrapper.innerHTML = `
            <div class="assistant-bubble" style="padding: 12px 16px;">
                <div class="assistant-header" style="margin-bottom: 6px;">
                    <div class="assistant-tag" style="color: #38bdf8;">
                        <span class="status-dot-pulse"></span>
                        <span>EXECUTING PIPELINE...</span>
                    </div>
                </div>
                <div class="tool-emits-container active-in-flight-emits"></div>
            </div>
        `;
        thread.appendChild(emitWrapper);
        activeEmitsContainer = emitWrapper.querySelector('.active-in-flight-emits');
        scrollToBottom();
    }

    if (activeEmitsContainer) {
        if (data.type === 'status') {
            let statusCard = activeEmitsContainer.querySelector('.tool-emit-card.status');
            if (statusCard) {
                statusCard.innerText = typeof data.payload === 'object' ? JSON.stringify(data.payload) : String(data.payload);
                scrollToBottom();
                return;
            }
        }
        const item = document.createElement('div');
        item.className = `tool-emit-card ${data.type}`;
        item.innerText = typeof data.payload === 'object' ? JSON.stringify(data.payload) : String(data.payload);
        activeEmitsContainer.appendChild(item);
        scrollToBottom();
    }
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

    // Update execution UI state
    setExecutionState(true);

    try {
        const res = await callApi('send_message', currentTarget, text);
        
        // Remove in-flight emit bubble if present
        document.querySelectorAll('.in-flight-emit-msg').forEach(el => el.remove());

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
        appendMessageBubble('assistant', `Error: ${err.message || err}`);
    } finally {
        setExecutionState(false);
    }
}

async function handleStopRequest() {
    if (!currentTarget) return;
    try {
        await callApi('stop_request', currentTarget);
    } catch (e) {
        console.error("Error stopping request:", e);
    }
}

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
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. SLASH COMMAND PALETTE & AUTOCOMPLETE
// ─────────────────────────────────────────────────────────────────────────────

let selectedSlashIndex = 0;

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
                    const chosenCmd = items[selectedSlashIndex].getAttribute('data-cmd');
                    if (chosenCmd) {
                        input.value = chosenCmd + ' ';
                        hideSlashPalette();
                    }
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

function renderSlashPalette(query) {
    const palette = document.getElementById('slashPalette');
    if (!palette) return;

    const filter = query.toLowerCase().slice(1);
    const matches = SLASH_COMMANDS.filter(c => c.cmd.slice(1).startsWith(filter));

    if (matches.length === 0) {
        hideSlashPalette();
        return;
    }

    palette.innerHTML = '';
    selectedSlashIndex = 0;

    matches.forEach((c, idx) => {
        const item = document.createElement('div');
        item.className = `slash-item ${idx === 0 ? 'selected' : ''}`;
        item.setAttribute('data-cmd', c.cmd);

        item.innerHTML = `
            <div class="slash-item-left">
                <span class="slash-item-cmd">${c.cmd}</span>
                <span class="slash-item-desc">${c.desc}</span>
            </div>
            <span class="slash-item-usage">${c.usage}</span>
        `;

        item.onclick = () => {
            const input = document.getElementById('chatInput');
            if (input) {
                input.value = c.cmd + ' ';
                input.focus();
            }
            hideSlashPalette();
        };

        palette.appendChild(item);
    });

    palette.style.display = 'flex';
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
    const scopeModalBtn = document.getElementById('scopeModalBtn');
    const scopeBadge = document.getElementById('scopeSummaryBadge');
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

    scopeModalBtn?.addEventListener('click', openScopeModal);
    scopeBadge?.addEventListener('click', openScopeModal);

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
        if (confirm(`Clear conversation history for "${currentTarget}"?`)) {
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

    // Sliding Sidebar (Slide out when hovering top-left logo / brand)
    const logoTrigger = document.getElementById('logoTrigger');
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

    if (logoTrigger && sidebar) {
        logoTrigger.addEventListener('mouseenter', openSlidingSidebar);
        logoTrigger.addEventListener('mouseleave', closeSlidingSidebar);
        sidebar.addEventListener('mouseenter', openSlidingSidebar);
        sidebar.addEventListener('mouseleave', closeSlidingSidebar);
        
        logoTrigger.addEventListener('click', (e) => {
            e.stopPropagation();
            sidebar.classList.toggle('open');
        });
    }

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

            if (keyNv) keyNv.value = keys.nvidia || '';
            if (keyAnt) keyAnt.value = keys.anthropic || '';
            if (keyOai) keyOai.value = keys.openai || '';
            if (keyOr) keyOr.value = keys.openrouter || '';
            if (keyGroq) keyGroq.value = keys.groq || '';

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

    modal?.classList.add('open');
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
            openai: document.getElementById('cfgKeyOpenai')?.value || '',
            openrouter: document.getElementById('cfgKeyOpenrouter')?.value || '',
            groq: document.getElementById('cfgKeyGroq')?.value || '',
        },
        researcher_handle: document.getElementById('cfgResearcherHandle')?.value || '',
        global_headers: globalHeaders,
        auto_install_missing_tools: document.getElementById('cfgAutoInstallTools')?.checked || false,
    };

    try {
        const res = await callApi('save_settings', payload);
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

function scrollToBottom() {
    const thread = document.getElementById('chatThread');
    if (thread) {
        thread.scrollTop = thread.scrollHeight;
    }
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
 * Lightweight Markdown Parser for chat responses
 */
function formatMarkdown(text) {
    if (!text) return '';

    // Code blocks
    let html = text.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (match, lang, code) => {
        return `<pre><code class="language-${escapeHtml(lang)}">${escapeHtml(code.trim())}</code></pre>`;
    });

    // Inline code
    html = html.replace(/`([^`]+)`/g, (match, code) => {
        return `<code>${escapeHtml(code)}</code>`;
    });

    // Headers
    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

    // Bold & Italics
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');

    // Bullet lists
    html = html.replace(/^\s*[-*]\s+(.*$)/gim, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>)/gims, '<ul>$1</ul>');

    // Paragraphs
    const blocks = html.split(/\n\n+/);
    html = blocks.map(b => {
        b = b.trim();
        if (b.startsWith('<h') || b.startsWith('<pre') || b.startsWith('<ul') || b.startsWith('<div')) {
            return b;
        }
        return `<p>${b.replace(/\n/g, '<br>')}</p>`;
    }).join('');

    return html;
}