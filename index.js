#!/usr/bin/env node
// VibeSafe MCP server — exposes the VibeSafe security scanner as MCP tools so
// any MCP client (Claude Desktop, Cursor, etc.) can scan code, live URLs, and
// run a Launch Check. Talks to the hosted VibeSafe API; never stores code.
//
// Auth: set VIBESAFE_API_KEY (a vibesafe_sk_... key from vibesafe.info -> API keys).

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const API_BASE = process.env.VIBESAFE_API_BASE || 'https://vibesafe-api.vercel.app';
const API_KEY = process.env.VIBESAFE_API_KEY || '';

function authHeaders() {
  return { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` };
}

function requireKey() {
  if (!API_KEY || !API_KEY.startsWith('vibesafe_sk_')) {
    return 'No VibeSafe API key configured. Get one free at https://vibesafe.info → API keys, then set the VIBESAFE_API_KEY environment variable in your MCP client config (it starts with "vibesafe_sk_").';
  }
  return null;
}

function textResult(text, isError = false) {
  return { content: [{ type: 'text', text }], isError };
}

// Render a scan result (code or live URL) as compact, readable text.
function formatScan(r, header) {
  const issues = r.issues || [];
  const passed = r.passed || [];
  const lines = [];
  lines.push(`${header}`);
  lines.push(`Security score: ${r.score ?? '—'}/100${r.summary ? ' — ' + r.summary : ''}`);
  lines.push('');
  if (issues.length === 0) {
    lines.push('✅ No issues found.');
  } else {
    const order = { critical: 0, warning: 1, info: 2 };
    issues.sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3));
    lines.push(`${issues.length} issue(s) found:`);
    for (const i of issues) {
      lines.push(`\n[${(i.severity || 'issue').toUpperCase()}] ${i.title}${i.line ? ' — ' + i.line : ''}`);
      if (i.description) lines.push(`  ${i.description}`);
      if (i.before) lines.push(`  Replace: ${i.before}`);
      if (i.after) lines.push(`  With:    ${i.after}`);
      if (i.fix || i.fix_explanation) lines.push(`  Fix: ${i.fix || i.fix_explanation}`);
    }
  }
  if (passed.length) lines.push('\nPassed checks: ' + passed.join(', '));
  return lines.join('\n');
}

const server = new McpServer({ name: 'vibesafe', version: '1.0.0' });

// ── TOOL: scan_code ──
server.registerTool(
  'vibesafe_scan_code',
  {
    title: 'Scan code for security issues',
    description: 'Scan a snippet or file of code for security vulnerabilities, exposed secrets, injection flaws, and risky patterns. Returns a security score and per-issue fixes. Use this before shipping AI-generated code. Your code is never stored.',
    inputSchema: {
      code: z.string().min(1).describe('The source code to scan.'),
      language: z.string().optional().describe('Language, e.g. "JavaScript", "Python", "TypeScript". Auto-detected if omitted.'),
    },
  },
  async ({ code, language }) => {
    const err = requireKey();
    if (err) return textResult(err, true);
    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ code, language, source: 'mcp' }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return textResult(`VibeSafe: ${data.error || 'scan failed (' + res.status + ')'}`, true);
      return textResult(formatScan(data, 'VibeSafe code scan'));
    } catch (e) {
      return textResult(`VibeSafe: could not reach the scanner (${e.message}).`, true);
    }
  }
);

// ── TOOL: scan_url ──
server.registerTool(
  'vibesafe_scan_url',
  {
    title: 'Scan a live website for security issues',
    description: 'Scan a deployed, publicly reachable web app for missing security headers, HTTPS issues, exposed paths (like /.env), CORS misconfiguration, and cookie flags — without accessing the code. Returns a security score and fixes.',
    inputSchema: {
      url: z.string().url().describe('The public URL of the deployed app, e.g. https://myapp.vercel.app'),
    },
  },
  async ({ url }) => {
    const err = requireKey();
    if (err) return textResult(err, true);
    try {
      const res = await fetch(`${API_BASE}/api/scan-url`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ url }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return textResult(`VibeSafe: ${data.error || 'scan failed (' + res.status + ')'}`, true);
      return textResult(formatScan(data, `VibeSafe live-website scan — ${url}`));
    } catch (e) {
      return textResult(`VibeSafe: could not reach the scanner (${e.message}).`, true);
    }
  }
);

// ── TOOL: launch_check ──
server.registerTool(
  'vibesafe_launch_check',
  {
    title: 'Run a Launch Check on your deployed app',
    description: 'Act like a real user: open the deployed app in a real browser, click through pages, capture errors, and return a launch-readiness score with what worked, what failed, and what to fix first. Best used right before sharing an app with users. Takes ~30 seconds.',
    inputSchema: {
      url: z.string().url().describe('The public URL of the deployed app to test.'),
      goal: z.string().optional().describe('What should work, e.g. "landing page and pricing" (optional).'),
    },
  },
  async ({ url, goal }) => {
    const err = requireKey();
    if (err) return textResult(err, true);
    try {
      const res = await fetch(`${API_BASE}/api/launch-check`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ url, goal }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return textResult(`VibeSafe: ${data.error || 'Launch Check failed (' + res.status + ')'}`, true);
      const r = data.report || {};
      const lines = [`VibeSafe Launch Check — ${url}`, `Score: ${r.score ?? '—'}/100 — ${r.verdict || ''}`, r.summary || '', ''];
      (data.evidence?.pages || []).forEach(p => {
        lines.push(`${p.ok ? '✅' : '❌'} ${p.label}: ${p.title || p.error || ''}${p.loadMs ? ` (${(p.loadMs / 1000).toFixed(1)}s)` : ''}`);
      });
      if ((r.failed || []).length) {
        lines.push('\nWhat needs fixing:');
        r.failed.forEach(f => lines.push(`- [${f.severity}] ${f.title} — ${f.why || ''} Fix: ${f.fix || ''}`));
      }
      if ((r.next_steps || []).length) {
        lines.push('\nFix these first:');
        r.next_steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
      }
      return textResult(lines.filter(Boolean).join('\n'));
    } catch (e) {
      return textResult(`VibeSafe: could not reach the scanner (${e.message}).`, true);
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
// stdio server: no stdout logging (it would corrupt the protocol). Errors go to stderr.
console.error('VibeSafe MCP server running (stdio).');
