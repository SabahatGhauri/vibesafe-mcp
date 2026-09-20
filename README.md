# VibeSafe MCP Server

[![CI](https://github.com/SabahatGhauri/vibesafe-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/SabahatGhauri/vibesafe-mcp/actions/workflows/ci.yml)

Run the [VibeSafe](https://vibesafe.info) security scanner directly inside any MCP client — Claude Desktop, Cursor, Windsurf, and others. Ask your AI to *"scan this file with VibeSafe"* and get a plain-English security report with fixes, without leaving your chat.

Built for founders and vibe coders shipping AI-generated apps. **Your code is never stored.**

## Tools

| Tool | What it does |
|------|--------------|
| `vibesafe_scan_code` | Scan code for exposed secrets, injection flaws, and risky patterns → security score + per-issue fixes |
| `vibesafe_scan_url` | Scan a deployed site for missing security headers, HTTPS issues, exposed paths, CORS problems |
| `vibesafe_launch_check` | Open your deployed app in a real browser like a user, capture errors, return a launch-readiness score |
| `vibesafe_supabase_rls_fix` | Write the Row-Level Security policies for a Supabase table (read, insert, update, delete), with steps to apply and verify. Runs locally — no keys leave your machine |

## Setup

### 1. Get a free API key
Sign in at [vibesafe.info](https://vibesafe.info) → **API keys** → **Generate new key**. It starts with `vibesafe_sk_`. Check the website for current plans and scan allowances.

### 2. Add it to your MCP client

**Claude Desktop** — edit `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "vibesafe": {
      "command": "npx",
      "args": ["-y", "vibesafe-mcp"],
      "env": {
        "VIBESAFE_API_KEY": "vibesafe_sk_your_key_here"
      }
    }
  }
}
```

**Cursor** — Settings → MCP → Add new server, or add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "vibesafe": {
      "command": "npx",
      "args": ["-y", "vibesafe-mcp"],
      "env": { "VIBESAFE_API_KEY": "vibesafe_sk_your_key_here" }
    }
  }
}
```

Restart the client. You should see the four VibeSafe tools available.

### 3. Use it
> "Scan this file for security issues with VibeSafe"
> "Run a VibeSafe launch check on https://myapp.vercel.app"
> "Is my Supabase code safe? Scan it."

## Privacy
Code is scanned in memory by the VibeSafe API and never stored. The scanner only receives the code or URL you ask it to check. Learn more at [vibesafe.info](https://vibesafe.info).

## Links
- Website & dashboard: https://vibesafe.info
- VS Code / Cursor extension: search "VibeSafe" in the Extensions marketplace
- Support: contact@vibesafe.info

MIT licensed.

## Development and failure handling

Use Node.js 20 or newer (Node 22 or 24 recommended). The locked dependency tree
requires Node 20 or newer:

```sh
npm ci --ignore-scripts
npm test
```

The tests connect an MCP client to the actual stdio server and intercept outgoing
HTTP requests. They do not contact the scanner or require API credentials. CI
checks Node 20, 22, and 24 using the committed dependency lockfile.

Code and URL requests time out after 60 seconds; Launch Check requests time out
after 120 seconds. Failed or malformed responses return tool errors. Truncated
code/URL results are explicitly marked incomplete and returned with `isError: true`.
The local RLS helper works without an API key.

Report vulnerabilities through [SECURITY.md](SECURITY.md).
