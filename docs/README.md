# Bounty Hunter — Setup Guides

Step-by-step instructions for everything beyond the one-line installer. The
main [README](../README.md) covers the quick-start; these go deeper on each
piece.

| Guide | What it covers |
| :--- | :--- |
| [AI Model Setup](ai-model-setup.md) | Choosing and configuring your orchestrator/synthesizer AI backend (NVIDIA NIM, Claude, Gemini, OpenAI, or fully offline Ollama) |
| [Burp Suite MCP Setup](mcp-burp-setup.md) | Connecting Burp Suite's MCP server so bounty-hunter can drive Burp directly |
| [Caido Setup](mcp-caido-setup.md) | Connecting Caido — recommended via the caido-mcp-server OAuth integration (66 tools), with the built-in GraphQL integration as a no-install fallback |

If something here doesn't match what you're seeing, run `/mcp` or `/model`
inside bounty-hunter first — both print their current state and the exact
command to fix it, which is usually faster than re-reading a doc.