"""
hellhound/core/voice_service.py

Fish Audio TTS voice service for the Hellhound desktop GUI ONLY.

This module is never imported by hellhound/cli.py or anything under
hellhound/core/chat_ui.py. The CLI stays silent and unchanged.

Design goals (per Hellhound v2 voice spec):
  * Single engine: Fish Audio SDK. No pyttsx3, no edge-tts, no browser
    speechSynthesis, no pygame.
  * Per-user credentials: API key + reference_id live in the user's own
    ~/.hellhound/config.json (via hellhound.core.ai_utils.load_config /
    save_config), never in a committed .env.
  * Simple surface for the frontend bridge (HellhoundAPI in gui_app.py):
        voice_service.speak(text)
        voice_service.stop()
        voice_service.replay()
  * Playback via ffplay against cached temp mp3 files.
  * Never raises into the caller for expected failure modes (missing key,
    bad reference id, network down) -- callers get a structured result
    dict and the service reports "unavailable" through its event callback.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("hellhound.gui.voice")

DEFAULT_MODEL = "s2.1-pro-free"
DEFAULT_SPEED = 1.08
CACHE_DIR = Path(tempfile.gettempdir()) / "hellhound_voice_cache"
MAX_CACHED_FILES = 20


class VoiceUnavailable(Exception):
    """Raised internally when voice cannot run; always caught at the boundary."""


class VoiceService:
    """
    Owns exactly one Fish Audio-backed playback session at a time.

    Thread-safety: speak()/stop()/replay() are safe to call from the
    pywebview JS-bridge thread. Generation + playback run on a worker
    thread so the GUI event loop never blocks.
    """

    def __init__(self, event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        """
        event_callback(event_type, payload) is invoked for UI sync, mirroring
        the existing window.onVoiceEvent contract:
            event_type in {"start", "end", "unavailable", "error"}
        """
        self._event_cb = event_callback
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None
        self._worker: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._last_audio_path: Optional[Path] = None
        self._last_text: Optional[str] = None
        self._speaking = False

        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Public API used by HellhoundAPI
    # ------------------------------------------------------------------ #

    def is_speaking(self) -> bool:
        return self._speaking

    def speak(self, text: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate + play `text` using the given voice config:
            {"api_key": ..., "reference_id": ..., "model": ..., "speed": ...}

        Returns immediately with {"status": "speaking"} once playback has
        started, or {"status": "unavailable"/"error", "reason": ...} if it
        could not start. Playback itself happens off-thread.
        """
        text = (text or "").strip()
        if not text:
            return {"status": "error", "reason": "empty_text"}

        api_key = (config or {}).get("api_key", "").strip()
        reference_id = (config or {}).get("reference_id", "").strip()
        model = (config or {}).get("model") or DEFAULT_MODEL
        speed = float((config or {}).get("speed") or DEFAULT_SPEED)

        if not api_key or not reference_id:
            self._emit("unavailable", {"reason": "not_configured"})
            return {"status": "unavailable", "reason": "not_configured"}

        # Stop whatever is currently playing before starting new speech.
        self.stop()
        self._stop_flag.clear()

        started = threading.Event()
        result_box: Dict[str, Any] = {}

        def _run():
            try:
                audio_path = self._generate(text, api_key, reference_id, model, speed)
                self._last_audio_path = audio_path
                self._last_text = text
                self._prune_cache()
                if self._stop_flag.is_set():
                    return
                result_box["status"] = "speaking"
                started.set()
                self._play(audio_path)
            except VoiceUnavailable as e:
                result_box["status"] = "unavailable"
                result_box["reason"] = str(e)
                started.set()
                self._emit("unavailable", {"reason": str(e)})
            except Exception as e:  # noqa: BLE001 - never crash the GUI
                logger.exception("Voice generation/playback failed")
                reason = _describe_exception(e)
                result_box["status"] = "error"
                result_box["reason"] = reason
                started.set()
                self._emit("error", {"error": reason})
            finally:
                self._speaking = False
                if not self._stop_flag.is_set():
                    self._emit("end", {})

        self._worker = threading.Thread(target=_run, name="hellhound-voice", daemon=True)
        self._speaking = True
        self._emit("start", {"text": text})
        self._worker.start()

        # Give the worker a brief window to report immediate failures
        # (bad key / bad reference id) without blocking the UI thread
        # on the full network + audio round trip.
        started.wait(timeout=0.05)
        return result_box or {"status": "speaking"}

    def stop(self) -> Dict[str, Any]:
        """Stop any in-flight generation or playback."""
        self._stop_flag.set()
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:  # noqa: BLE001
                try:
                    proc.kill()
                except Exception:  # noqa: BLE001
                    pass
        was_speaking = self._speaking
        self._speaking = False
        if was_speaking:
            self._emit("end", {})
        return {"status": "stopped"}

    def replay(self) -> Dict[str, Any]:
        """Replay the last generated audio without hitting the API again."""
        if not self._last_audio_path or not self._last_audio_path.exists():
            self._emit("unavailable", {"reason": "nothing_to_replay"})
            return {"status": "unavailable", "reason": "nothing_to_replay"}

        self.stop()
        self._stop_flag.clear()
        self._speaking = True
        self._emit("start", {"text": self._last_text or ""})

        def _run():
            try:
                self._play(self._last_audio_path)
            finally:
                self._speaking = False
                if not self._stop_flag.is_set():
                    self._emit("end", {})

        self._worker = threading.Thread(target=_run, name="hellhound-voice-replay", daemon=True)
        self._worker.start()
        return {"status": "speaking"}

    def test_voice(self, config: Dict[str, Any], sample_text: Optional[str] = None) -> Dict[str, Any]:
        """
        Synchronous connectivity check used by the "Test Voice" button in
        Settings. Generates a short clip and plays it, blocking until
        generation completes so the Settings panel can show a real
        success/failure status.
        """
        sample_text = sample_text or "Hellhound voice link confirmed."
        api_key = (config or {}).get("api_key", "").strip()
        reference_id = (config or {}).get("reference_id", "").strip()
        model = (config or {}).get("model") or DEFAULT_MODEL
        speed = float((config or {}).get("speed") or DEFAULT_SPEED)

        if not api_key or not reference_id:
            return {"status": "unavailable", "reason": "not_configured"}

        try:
            audio_path = self._generate(sample_text, api_key, reference_id, model, speed)
            self._last_audio_path = audio_path
            self._last_text = sample_text
            if not shutil_which("ffplay"):
                return {"status": "error", "reason": "ffplay not found on PATH — install ffmpeg (audio generated fine, playback can't start)."}
            self._play(audio_path, block=True)
            return {"status": "ok"}
        except VoiceUnavailable as e:
            return {"status": "unavailable", "reason": str(e)}
        except Exception as e:  # noqa: BLE001
            logger.exception("Voice test failed")
            return {"status": "error", "reason": _describe_exception(e)}

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _generate(self, text: str, api_key: str, reference_id: str, model: str, speed: float) -> Path:
        try:
            from fishaudio import FishAudio
        except ImportError as e:
            import sys
            raise VoiceUnavailable(
                f"fish-audio-sdk not importable under {sys.executable}. "
                f"Install it into THIS interpreter: {sys.executable} -m pip install fish-audio-sdk"
            ) from e

        try:
            client = FishAudio(api_key=api_key)
            audio_bytes = client.tts.convert(
                text=text,
                reference_id=reference_id,
                model=model,
                speed=max(0.5, min(2.0, speed)),
                format="mp3",
            )
        except VoiceUnavailable:
            raise
        except Exception as e:  # noqa: BLE001
            # Surface the REAL error (auth failure, bad reference_id, network
            # down, etc.) instead of a generic message -- this is what shows
            # up in the Voice Status line so it's actually debuggable.
            logger.exception("Fish Audio generation failed")
            detail = _describe_exception(e)
            raise VoiceUnavailable(f"Voice unavailable: {detail}") from e

        if not audio_bytes:
            raise VoiceUnavailable("Voice unavailable: Fish Audio returned no audio data")

        out_path = CACHE_DIR / f"briefing_{int(time.time() * 1000)}.mp3"
        with open(out_path, "wb") as f:
            f.write(audio_bytes)
        return out_path

    def _play(self, path: Path, block: bool = False) -> None:
        if not shutil_which("ffplay"):
            raise VoiceUnavailable("ffplay not found (install ffmpeg)")

        cmd = ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", str(path)]
        proc = subprocess.Popen(cmd)
        with self._lock:
            self._proc = proc

        if block:
            proc.wait()
            with self._lock:
                if self._proc is proc:
                    self._proc = None
            return

        proc.wait()
        with self._lock:
            if self._proc is proc:
                self._proc = None

    def _prune_cache(self) -> None:
        try:
            files = sorted(CACHE_DIR.glob("briefing_*.mp3"), key=lambda p: p.stat().st_mtime)
            excess = len(files) - MAX_CACHED_FILES
            for f in files[:max(0, excess)]:
                f.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass

    def _emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        if self._event_cb:
            try:
                self._event_cb(event_type, payload)
            except Exception:  # noqa: BLE001
                logger.exception("voice event callback failed")


def shutil_which(cmd: str) -> Optional[str]:
    import shutil
    return shutil.which(cmd)


def _describe_exception(e: Exception) -> str:
    """
    Turns SDK/httpx exceptions into a short, actually-useful message instead
    of a bare repr. Fish Audio's SDK is built on httpx, so most failures are
    httpx.HTTPStatusError (auth/bad reference id) or httpx.RequestError
    (DNS/network/timeout).
    """
    resp = getattr(e, "response", None)
    if resp is not None:
        status = getattr(resp, "status_code", None)
        body = ""
        try:
            body = resp.text[:200]
        except Exception:  # noqa: BLE001
            pass
        if status == 401 or status == 403:
            return f"HTTP {status} — API key rejected. Double-check the key in Settings."
        if status == 404:
            return f"HTTP {status} — voice reference ID not found."
        if status:
            return f"HTTP {status}{': ' + body if body else ''}"
    msg = str(e).strip()
    if not msg:
        msg = type(e).__name__
    return msg[:200]


def diagnostics() -> Dict[str, Any]:
    """
    Environment diagnostic for the Voice tab. Answers the single most common
    support question: "pip says it's installed, why doesn't the app see it?"
    -- almost always the GUI process is a different interpreter/venv than
    whatever shell `pip install` was run in.
    """
    import sys

    fishaudio_ok = False
    fishaudio_path = None
    try:
        import fishaudio
        fishaudio_ok = True
        fishaudio_path = getattr(fishaudio, "__file__", None)
    except ImportError:
        pass

    return {
        "python_executable": sys.executable,
        "fishaudio_importable": fishaudio_ok,
        "fishaudio_path": fishaudio_path,
        "ffplay_path": shutil_which("ffplay"),
    }


# Module-level singleton — one voice session for the whole desktop app.
_instance: Optional[VoiceService] = None


def get_voice_service(event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> VoiceService:
    global _instance
    if _instance is None:
        _instance = VoiceService(event_callback=event_callback)
    elif event_callback is not None:
        _instance._event_cb = event_callback
    return _instance
