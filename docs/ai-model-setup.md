# AI Model Setup

Bounty Hunter runs every turn through two roles — **orchestrator** (picks
and calls tools) and **synthesizer** (writes the researcher-facing
analysis/report at the end of a turn). They can point at the same model or
two different ones. If you just want one model doing both jobs, skip ahead
to [Setting both tiers at once](#setting-both-tiers-at-once).

## Option A — Free Cloud AI via NVIDIA NIM (recommended for most people)

NVIDIA NIM gives free API credits and frontier-class 120B+ model inference
with zero local GPU requirement.

1. Sign up at [build.nvidia.com](https://build.nvidia.com/) and grab your
   free API key (starts with `nvapi-`).
2. Inside bounty-hunter, save the key once:
   ```
   /model set-key nvidia nvapi-your-key-here
   ```
3. Point both tiers at a model:
   ```
   /model both nvidia nvidia/nemotron-3-ultra-550b-a55b
   ```

NVIDIA periodically retires older model IDs — if a model you had working
suddenly 410s, check [build.nvidia.com](https://build.nvidia.com/) for the
current model catalog and switch with the same command.

## Option B — Commercial Cloud Providers (Claude, Gemini, OpenAI)

```
/model set-key anthropic sk-ant-...
/model set-key gemini AIza...
/model set-key openai sk-...
```

Then assign a role (or both) — use whatever model ID your provider is
currently serving (there's no fixed whitelist, any valid model string for
that provider works):
```
/model synthesizer anthropic claude-3-5-sonnet
/model orchestrator gemini gemini-2.0-flash
```

## Option C — Fully Offline Local AI (Ollama)

For air-gapped environments. A 32B+ model is recommended for reliable tool
chaining — smaller models tend to hallucinate tool arguments.

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull a model
ollama pull qwen2.5:32b-instruct-q4_0
```
```
# 3. Inside bounty-hunter
/model both ollama qwen2.5:32b-instruct-q4_0
```

## Setting Both Tiers at Once

If you want the same model doing tool-selection AND write-up, you don't
need to run `/model` twice:

```
/model both <provider> <model-id>
```

This is identical to leaving the role off entirely — `/model <provider>
<model-id>` without `orchestrator`/`synthesizer`/`both` already updates
both tiers — `both` just exists so you can say what you mean.

To split them instead (e.g. a cheap/fast model for tool-calling, a
stronger one for the final write-up):
```
/model orchestrator ollama qwen2.5:7b-instruct
/model synthesizer nvidia nvidia/nemotron-3-ultra-550b-a55b
```

## Checking What's Active

```
/model
```
Prints both tiers' current provider/model, every available model it can
see (local Ollama pulls + any cloud provider you've saved a key for), and
a `[orchestrator]`/`[synthesizer]` tag on whichever ones are currently
assigned.

## Session-Only Changes

Add `--session-only` to try a model without overwriting your saved config:
```
/model synthesizer anthropic claude-3-opus --session-only
```