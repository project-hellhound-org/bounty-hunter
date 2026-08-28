# hellhound-fixed-files.zip — what's in here

Unzip this over your existing `bounty-hunter/` checkout (see command below).
It **overwrites** these files and **adds** one new one:

- `hellhound/gui_app.py`        — voice (Fish Audio) API surface fully removed
- `hellhound/core/commands.py`  — adds `/uninstall`, natural-language uninstall
                                   intent detection, `/setup max-iterations <n>`
- `hellhound/core/agent.py`     — tool-iteration cap now configurable (was a
                                   hardcoded 15, default is now 60)
- `hellhound/core/ai_utils.py`  — new `max_agent_iterations` config key
- `gui/app.js`, `gui/app.html`, `gui/app.css` — voice UI fully removed
- `requirements.txt`            — `fish-audio-sdk` dependency removed
- `uninstall.sh`                — new top-level cleanup script (new file)

## One manual step this zip cannot do

Zip extraction can only add/overwrite files, not delete them. Delete the now-unused
voice backend module yourself:

```
rm bounty-hunter/hellhound/core/voice_service.py
```

Everything that imported it (`gui_app.py`) has already been edited to not
reference it, so this is safe.
