"""
tests/test_gui_api.py

Automated test suite for the PyWebView HellhoundAPI backend,
validating target lifecycle, chat threads, structural findings isolation,
and complete eradication of legacy IPC mechanisms.
"""

import os
from pathlib import Path
import pytest

from hellhound.gui_app import HellhoundAPI, GuiEmit
from hellhound.core.tasks import create_or_load_target, save_target, list_targets


@pytest.fixture
def api(tmp_path, monkeypatch):
    """Fixture providing an isolated HellhoundAPI instance with temp target storage."""
    targets_dir = tmp_path / "targets"
    targets_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("hellhound.core.tasks._get_targets_dir", lambda: str(targets_dir))
    monkeypatch.setattr("hellhound.gui_app._get_targets_dir", lambda: str(targets_dir))
    return HellhoundAPI()


def test_target_lifecycle(api):
    """Test creating, listing, fetching, updating scope, and deleting targets."""
    # 1. Create Target
    res = api.create_target("alpha.corp")
    assert res["name"] == "alpha.corp"

    # 2. List Targets
    targets = api.list_targets()
    names = [t["name"] for t in targets]
    assert "alpha.corp" in names

    # 3. Update Scope
    updated = api.set_scope("alpha.corp", "*.alpha.corp\napi.alpha.corp")
    assert "alpha.corp" in updated["scope_rules"]["in_scope"]
    assert "api.alpha.corp" in updated["scope_rules"]["in_scope"]

    # 4. Get Target
    target_data = api.get_target("alpha.corp")
    assert target_data["name"] == "alpha.corp"
    assert "alpha.corp" in target_data["scope_rules"]["in_scope"]

    # 5. Delete Target
    del_res = api.delete_target("alpha.corp")
    assert del_res["status"] == "ok"
    targets_after = api.list_targets()
    assert "alpha.corp" not in [t["name"] for t in targets_after]


def test_findings_structural_isolation(api):
    """
    Critical Test: Ensure complete structural isolation of findings between targets.
    Data in target-alpha MUST NEVER bleed into target-beta.
    """
    # 1. Setup target Alpha with specific findings
    t_alpha = create_or_load_target("target-alpha.com")
    t_alpha.state["takeover_candidates"] = [
        {"host": "sub1.target-alpha.com", "service": "s3", "cname": "s3.amazonaws.com"},
        {"host": "sub2.target-alpha.com", "service": "github", "cname": "user.github.io"}
    ]
    t_alpha.state["subdomains"] = ["sub1.target-alpha.com", "sub2.target-alpha.com", "api.target-alpha.com"]
    t_alpha.state["open_ports"] = ["sub1.target-alpha.com:443", "api.target-alpha.com:8443"]
    t_alpha.findings = [{"title": "Subdomain Takeover on sub1", "severity": "CRITICAL"}]
    save_target(t_alpha)

    # 2. Setup target Beta with different findings
    t_beta = create_or_load_target("target-beta.com")
    t_beta.state["takeover_candidates"] = []
    t_beta.state["subdomains"] = ["portal.target-beta.com", "vpn.target-beta.com"]
    t_beta.state["open_ports"] = ["vpn.target-beta.com:1194"]
    t_beta.findings = []
    save_target(t_beta)

    # 3. Query findings for Alpha
    alpha_findings = api.get_findings("target-alpha.com")
    assert alpha_findings["target"] == "target-alpha.com"
    assert len(alpha_findings["categories"]["takeover_candidates"]) == 2
    assert len(alpha_findings["categories"]["subdomains"]) == 3
    assert len(alpha_findings["findings"]) == 1
    assert "portal.target-beta.com" not in str(alpha_findings)

    # 4. Query findings for Beta — must be 100% free of Alpha's data
    beta_findings = api.get_findings("target-beta.com")
    assert beta_findings["target"] == "target-beta.com"
    assert len(beta_findings["categories"]["takeover_candidates"]) == 0
    assert len(beta_findings["categories"]["subdomains"]) == 2
    assert len(beta_findings["findings"]) == 0
    assert "sub1.target-alpha.com" not in str(beta_findings)
    assert "s3.amazonaws.com" not in str(beta_findings)


def test_chat_history_isolation(api):
    """Ensure conversation threads are strictly isolated per target."""
    api.create_target("chat-target-1.org")
    api.create_target("chat-target-2.org")

    # Manually populate chat history in target 1
    t1 = create_or_load_target("chat-target-1.org")
    t1.state["chat_history"] = [
        {"role": "user", "content": "hello target 1"},
        {"role": "assistant", "content": "response 1"}
    ]
    save_target(t1)

    # Verify target 2 chat history is empty
    t2_history = api.get_chat_history("chat-target-2.org")
    assert len(t2_history) == 0

    t1_history = api.get_chat_history("chat-target-1.org")
    assert len(t1_history) == 2
    assert t1_history[0]["content"] == "hello target 1"

    # Test clear_chat_history
    api.clear_chat_history("chat-target-1.org")
    assert len(api.get_chat_history("chat-target-1.org")) == 0


def test_stop_request_signaling(api):
    """Test stop signal mechanism for active requests."""
    api.create_target("stop-target.com")
    res = api.stop_request("stop-target.com")
    assert res["status"] == "ok"
    assert api._cancel_flags.get("stop-target.com") is True


def test_legacy_ipc_eradication():
    """Verify that all obsolete Electron and IPC files and handlers are completely deleted."""
    gui_dir = Path(__file__).resolve().parent.parent / "gui"
    
    # Assert legacy files are gone
    assert not (gui_dir / "main.js").exists()
    assert not (gui_dir / "list_modules.py").exists()
    assert not (gui_dir / "package.json").exists()
    assert not (gui_dir / "package-lock.json").exists()
    assert not (gui_dir / "node_modules").exists()

    # Read frontend files and verify 0 occurrences of ipcRenderer or dead handlers
    for filename in ["app.html", "app.js", "app.css"]:
        content = (gui_dir / filename).read_text()
        assert "ipcRenderer" not in content
        assert "ipcMain" not in content
        for dead_kw in ["get-modules", "ai-howl", "strike-confirmed", "abort-strike", "get-loot", "run-repro", "exec-repro"]:
            assert dead_kw not in content
