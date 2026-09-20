import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
const root = fileURLToPath(new URL('../', import.meta.url));
async function connect(t, scenario = {}, key = 'vibesafe_sk_test_only') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vibesafe-mcp-test-'));
  const file = path.join(dir, 'scenario.json'); fs.writeFileSync(file, JSON.stringify(scenario));
  const client = new Client({ name: 'vibesafe-test', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath,
    args: ['--import', pathToFileURL(path.join(root, 'test/mock-fetch.mjs')).href, path.join(root, 'index.js')],
    env: { ...process.env, NODE_OPTIONS: '', VIBESAFE_API_BASE: '', VIBESAFE_API_KEY: key, VIBESAFE_TEST_SCENARIO: file }, stderr: 'pipe' });
  if (transport.stderr) transport.stderr.resume();
  t.after(async () => { await client.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  await client.connect(transport); return client;
}
test('stdio handshake exposes all four tools', async t => {
  const client = await connect(t); const { tools } = await client.listTools();
  assert.deepEqual(tools.map(x => x.name).sort(), ['vibesafe_launch_check', 'vibesafe_scan_code', 'vibesafe_scan_url', 'vibesafe_supabase_rls_fix']);
});
test('local RLS tool works without credentials or network', async t => {
  const client = await connect(t, { networkError: 'Network forbidden' }, '');
  const r = await client.callTool({ name: 'vibesafe_supabase_rls_fix', arguments: { table: 'notes', access: 'owner' } });
  assert.equal(r.isError, false); assert.ok(r.content[0].text.includes('with check (auth.uid() = user_id)'));
});
for (const name of ['vibesafe_scan_code', 'vibesafe_scan_url', 'vibesafe_launch_check']) {
  const args = name === 'vibesafe_scan_code' ? { code: 'const value = 1;' } : { url: 'https://example.com' };
  test(name + ' requires a key', async t => {
    const client = await connect(t, {}, ''); const r = await client.callTool({ name, arguments: args });
    assert.equal(r.isError, true); assert.match(r.content[0].text, /No VibeSafe API key/);
  });
  for (const [label, scenario] of Object.entries({ unauthorized: { status: 401, body: { error: 'invalid key' } },
    malformed: { raw: '<html>error</html>' }, missingFields: { body: {} }, timeout: { networkError: 'TimeoutError' } })) {
    test(name + ' reports ' + label + ' as tool error', async t => {
      const client = await connect(t, scenario); const r = await client.callTool({ name, arguments: args });
      assert.equal(r.isError, true); assert.doesNotMatch(r.content[0].text, /No issues found/);
    });
  }
  test(name + ' accepts a valid response', async t => {
    const client = await connect(t, name === 'vibesafe_launch_check' ? { body: { report: { score: 100, verdict: 'Ready' } } } : {});
    const r = await client.callTool({ name, arguments: args }); assert.equal(r.isError, false); assert.ok(r.content[0].text.includes('100/100'));
  });
}
test('partial code coverage is visible and flagged as an error', async t => {
  const client = await connect(t, { body: { score: 100, issues: [], coverage: { truncated: true } } });
  const r = await client.callTool({ name: 'vibesafe_scan_code', arguments: { code: 'const value = 1;' } });
  assert.equal(r.isError, true); assert.match(r.content[0].text, /Scan incomplete/);
});
