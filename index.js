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
  if (!r || !Number.isFinite(r.score) || r.score < 0 || r.score > 100 || !Array.isArray(r.issues)
    || r.issues.some(i => !i || !['critical', 'warning', 'info'].includes(i.severity))) {
    throw new Error('invalid scan response');
  }
  const issues = r.issues || [];
  const passed = r.passed || [];
  const lines = [];
  lines.push(`${header}`);
  lines.push(`Security score: ${r.score ?? '—'}/100${r.summary ? ' — ' + r.summary : ''}`);
  lines.push('');
  if (r.coverage?.truncated) lines.push('⚠️ Scan incomplete: only part of the input was scanned.');
  if (issues.length === 0) {
    lines.push(r.coverage?.truncated ? 'No issues found in the scanned portion.' : '✅ No issues found.');
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
      if (i.why_it_happened) lines.push(`  Why this happened: ${i.why_it_happened}`);
      if (Array.isArray(i.fix_steps) && i.fix_steps.length) {
        lines.push('  How to fix it:');
        i.fix_steps.forEach((st, n) => lines.push(`    ${n + 1}. ${st}`));
      }
      if (i.evidence && i.evidence.installed_version) {
        lines.push(`  Evidence: installed ${i.evidence.installed_version} (from ${i.evidence.version_source})`
          + (i.evidence.fixed_version ? `, fixed in ${i.evidence.fixed_version}` : '')
          + (i.evidence.advisory ? ` — ${i.evidence.advisory}` : ''));
      }
    }
  }
  if (r.coverage && Array.isArray(r.coverage.notes) && r.coverage.notes.length) {
    lines.push('\nWhat this scan did NOT cover:');
    r.coverage.notes.forEach(n => lines.push(`  - ${n}`));
  }
  if (Array.isArray(r.not_checked) && r.not_checked.length) {
    lines.push('\nCould not be verified from outside: ' + r.not_checked.join('; '));
  }
  if (passed.length) lines.push('\nPassed checks: ' + passed.join(', '));
  return lines.join('\n');
}

const server = new McpServer({ name: 'vibesafe', version: '1.1.0' });

// Generates Row-Level Security policies locally — no network, no keys, nothing
// sent anywhere. Deterministic SQL beats asking a model to remember the syntax.
function rlsPolicySql({ table, ownerColumn, access, teamTable, teamColumn }) {
  const t = table.replace(/[^A-Za-z0-9_]/g, '');
  const col = (ownerColumn || 'user_id').replace(/[^A-Za-z0-9_]/g, '');
  const lines = [`alter table ${t} enable row level security;`, ''];
  if (access === 'public_read') {
    lines.push(`-- Anyone may read; only the owner may change their own rows.`);
    lines.push(`create policy "${t}_public_read"   on ${t} for select using (true);`);
    lines.push(`create policy "${t}_owner_insert"  on ${t} for insert with check (auth.uid() = ${col});`);
    lines.push(`create policy "${t}_owner_update"  on ${t} for update using (auth.uid() = ${col}) with check (auth.uid() = ${col});`);
    lines.push(`create policy "${t}_owner_delete"  on ${t} for delete using (auth.uid() = ${col});`);
  } else if (access === 'team') {
    const mt = (teamTable || 'memberships').replace(/[^A-Za-z0-9_]/g, '');
    const mc = (teamColumn || 'org_id').replace(/[^A-Za-z0-9_]/g, '');
    const member = `${mc} in (select ${mc} from ${mt} where user_id = auth.uid())`;
    lines.push(`-- Members of the same ${mc} share rows; everyone else is denied.`);
    lines.push(`create policy "${t}_team_read"   on ${t} for select using (${member});`);
    lines.push(`create policy "${t}_team_insert" on ${t} for insert with check (${member});`);
    lines.push(`create policy "${t}_team_update" on ${t} for update using (${member}) with check (${member});`);
    lines.push(`create policy "${t}_team_delete" on ${t} for delete using (${member});`);
  } else if (access === 'private') {
    lines.push(`-- Not reachable from the browser at all; server-side code only.`);
    lines.push(`revoke all on ${t} from anon, authenticated;`);
  } else {
    lines.push(`-- Each user reaches only their own rows, for every operation.`);
    lines.push(`create policy "${t}_owner_read"   on ${t} for select using (auth.uid() = ${col});`);
    lines.push(`create policy "${t}_owner_insert" on ${t} for insert with check (auth.uid() = ${col});`);
    lines.push(`create policy "${t}_owner_update" on ${t} for update using (auth.uid() = ${col}) with check (auth.uid() = ${col});`);
    lines.push(`create policy "${t}_owner_delete" on ${t} for delete using (auth.uid() = ${col});`);
  }
  return lines.join('\n');
}

// ── TOOL: supabase_rls_fix ──
server.registerTool(
  'vibesafe_supabase_rls_fix',
  {
    title: 'Write Supabase Row-Level Security policies for a table',
    description: 'Generate the exact Row-Level Security SQL for one Supabase table, covering reads, inserts, updates and deletes, plus the steps to apply it and how to check it worked. Use when a scan reports a table without RLS, a policy that allows everyone, or reads protected while updates and deletes are open. Runs locally: no keys and no data leave the machine.',
    inputSchema: {
      table: z.string().min(1).describe('Table name, e.g. "notes".'),
      access: z.enum(['owner', 'team', 'public_read', 'private']).default('owner')
        .describe('owner = each user sees only their own rows; team = members of the same organisation share rows; public_read = anyone reads, owner writes; private = not reachable from the browser at all.'),
      ownerColumn: z.string().optional().describe('Column holding the owning user id. Defaults to user_id.'),
      teamTable: z.string().optional().describe('For access="team": the membership table. Defaults to memberships.'),
      teamColumn: z.string().optional().describe('For access="team": the shared column, e.g. org_id. Defaults to org_id.'),
    },
  },
  async (args) => {
    const sql = rlsPolicySql(args);
    const t = args.table;
    const out = [
      `Row-Level Security for "${t}" (${args.access || 'owner'} access)`,
      '',
      'WHY THIS HAPPENS: AI builders create the table and wire the browser straight to Supabase, but the rules that decide who may read and change each row are a separate step they usually skip or only write for reading. Until they exist, anyone holding the public anon key — which ships in your site — can reach the table directly.',
      '',
      'SQL to apply:',
      '',
      sql,
      '',
      'HOW TO APPLY IT:',
      '1. Open your Supabase dashboard → SQL Editor → New query.',
      '2. Paste the SQL above and click Run. Do this on a staging project first if you have one.',
      `3. Open your app and confirm a signed-in user still sees their own ${t} rows. Turning RLS on denies everything until policies exist, so this step catches a policy that is too strict.`,
      '4. Sign out (or use a second account) and confirm those rows are no longer visible.',
      '5. Re-scan with VibeSafe to record that it is fixed.',
      '',
      'DO NOT: use the service_role key in browser code to work around a policy — it bypasses every rule here.',
    ].join('\n');
    return textResult(out);
  }
);

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
        signal: AbortSignal.timeout(60000),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return textResult(`VibeSafe: ${data.error || 'scan failed (' + res.status + ')'}`, true);
      return textResult(formatScan(data, 'VibeSafe code scan'), Boolean(data.coverage?.truncated));
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
        signal: AbortSignal.timeout(60000),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return textResult(`VibeSafe: ${data.error || 'scan failed (' + res.status + ')'}`, true);
      return textResult(formatScan(data, `VibeSafe live-website scan — ${url}`), Boolean(data.coverage?.truncated));
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
        signal: AbortSignal.timeout(120000),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return textResult(`VibeSafe: ${data.error || 'Launch Check failed (' + res.status + ')'}`, true);
      const r = data.report || {};
      if (!Number.isFinite(r.score) || r.score < 0 || r.score > 100) return textResult('VibeSafe: invalid Launch Check response.', true);
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
