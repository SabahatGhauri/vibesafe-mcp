# VibeSafe MCP Server

Run the [VibeSafe](https://vibesafe.info) security scanner directly inside any MCP client — Claude Desktop, Cursor, Windsurf, and others. Ask your AI to *"scan this file with VibeSafe"* and get a plain-English security report with fixes, without leaving your chat.

Built for founders and vibe coders shipping AI-generated apps. **Your code is never stored.**

## Tools

| Tool | What it does |
|------|--------------|
| `vibesafe_scan_code` | Scan code for exposed secrets, injection flaws, and risky patterns → security score + per-issue fixes |
| `vibesafe_scan_url` | Scan a deployed site for missing security headers, HTTPS issues, exposed paths, CORS problems |
| `vibesafe_launch_check` | Open your deployed app in a real browser like a user, capture errors, return a launch-readiness score |

## Setup

### 1. Get a free API key
Sign in at [vibesafe.info](https://vibesafe.info) → **API keys** → **Generate new key**. It starts with `vibesafe_sk_`. The free plan includes 3 scans per month; Pro is unlimited.

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

Restart the client. You should see the three VibeSafe tools available.

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
